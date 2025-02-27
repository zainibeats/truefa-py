"""
Vault implementation using Rust-based cryptography with envelope encryption.
The vault secures a master key with a vault password, and the master key in turn
secures individual TOTP secrets.
"""

import os
import json
import base64
from pathlib import Path
from .secure_string import SecureString

# Import our Rust crypto module
try:
    import truefa_crypto
except ImportError:
    raise ImportError("truefa_crypto Rust module not found. Please build it first.")

class SecureVault:
    """
    Secure vault implementation with envelope encryption.
    
    This implements a two-layer security model:
    1. Vault password - unlocks the vault and decrypts the master key
    2. Master key - encrypts/decrypts individual TOTP secrets
    
    The master key is never stored directly, only in encrypted form.
    """
    
    def __init__(self, storage_path=None):
        """Initialize the vault with the specified storage path."""
        self.storage_path = storage_path or os.path.expanduser('~/.truefa')
        self.vault_file = os.path.join(self.storage_path, '.vault')
        
        # Ensure storage directory exists with proper permissions
        os.makedirs(self.storage_path, mode=0o700, exist_ok=True)
        
        # Try to set permissions, but don't fail if we can't
        try:
            os.chmod(self.storage_path, 0o700)
        except Exception:
            pass
        
        # Vault state
        self._vault_config = None
        self._master_key = None
        self._is_initialized = False
        
        # Load vault configuration if it exists
        self._load_vault_config()

    def _load_vault_config(self):
        """Load vault configuration from disk if it exists."""
        if os.path.exists(self.vault_file):
            try:
                with open(self.vault_file, 'r') as f:
                    self._vault_config = json.load(f)
                    self._is_initialized = True
            except Exception as e:
                print(f"Error loading vault configuration: {e}")
                self._vault_config = None
                self._is_initialized = False
        else:
            self._vault_config = None
            self._is_initialized = False

    def is_initialized(self):
        """Check if the vault has been initialized."""
        return self._is_initialized

    def is_unlocked(self):
        """Check if the vault is currently unlocked."""
        return truefa_crypto.is_vault_unlocked()

    def create_vault(self, vault_password, master_password):
        """
        Create a new secure vault with the given passwords.
        
        This sets up the two-layer encryption:
        1. Generates a vault key from the vault password
        2. Generates a master key from the master password
        3. Encrypts the master key with the vault key
        4. Stores the encrypted master key and vault salt
        """
        # Create the vault (generates and caches vault key)
        vault_salt = truefa_crypto.create_vault(vault_password)
        
        # Generate a salt for the master key
        master_salt = truefa_crypto.generate_salt()
        
        # Derive the master key
        master_key = truefa_crypto.derive_master_key(master_password, master_salt)
        
        # Encrypt the master key with the vault key
        encrypted_master_key = truefa_crypto.encrypt_master_key(master_key)
        
        # Store the vault configuration
        self._vault_config = {
            'vault_salt': vault_salt,
            'master_salt': master_salt,
            'encrypted_master_key': encrypted_master_key
        }
        
        # Save to disk
        with open(self.vault_file, 'w') as f:
            json.dump(self._vault_config, f)
        
        self._is_initialized = True
        return True

    def unlock_vault(self, vault_password):
        """
        Unlock the vault with the vault password.
        
        This allows access to the master key which can then be used
        to encrypt/decrypt individual TOTP secrets.
        """
        if not self._is_initialized or not self._vault_config:
            return False
        
        vault_salt = self._vault_config.get('vault_salt')
        if not vault_salt:
            return False
        
        # Unlock the vault (derives and caches vault key)
        try:
            truefa_crypto.unlock_vault(vault_password, vault_salt)
            return True
        except Exception:
            return False

    def get_master_key(self):
        """
        Get the decrypted master key for use with secret encryption/decryption.
        
        The vault must be unlocked first using unlock_vault().
        """
        if not self.is_unlocked() or not self._vault_config:
            return None
        
        encrypted_master_key = self._vault_config.get('encrypted_master_key')
        if not encrypted_master_key:
            return None
        
        try:
            decrypted_master_key = truefa_crypto.decrypt_master_key(encrypted_master_key)
            return SecureString(decrypted_master_key)
        except Exception as e:
            print(f"Error getting master key: {e}")
            return None

    def lock_vault(self):
        """Lock the vault, clearing all sensitive data from memory."""
        truefa_crypto.lock_vault()
        return True

    def change_vault_password(self, current_password, new_password):
        """Change the vault password."""
        if not self.unlock_vault(current_password):
            return False
        
        # Get the current master key
        master_key = self.get_master_key()
        if not master_key:
            return False
        
        # Extract the master key as a string
        master_key_str = master_key.get()
        master_key.clear()
        
        # Generate a new vault key and encrypt the master key with it
        vault_salt = truefa_crypto.create_vault(new_password)
        encrypted_master_key = truefa_crypto.encrypt_master_key(master_key_str)
        
        # Update and save configuration
        self._vault_config['vault_salt'] = vault_salt
        self._vault_config['encrypted_master_key'] = encrypted_master_key
        
        with open(self.vault_file, 'w') as f:
            json.dump(self._vault_config, f)
        
        return True

    def change_master_password(self, vault_password, current_master_password, new_master_password):
        """
        Change the master password used for encrypting individual secrets.
        
        This requires:
        1. Unlocking the vault with the vault password
        2. Verifying the current master password
        3. Generating a new master key from the new password
        4. Encrypting it with the vault key
        
        Note: This doesn't re-encrypt existing secrets, which would need to be
        handled separately in the application.
        """
        if not self.unlock_vault(vault_password):
            return False, "Incorrect vault password"
        
        # Verify current master password
        master_salt = self._vault_config.get('master_salt')
        if not master_salt:
            return False, "Vault configuration corrupted"
        
        try:
            # Generate the current master key to verify it
            current_key = truefa_crypto.derive_master_key(current_master_password, master_salt)
            
            # Generate a new salt for the new master password
            new_master_salt = truefa_crypto.generate_salt()
            
            # Derive the new master key
            new_master_key = truefa_crypto.derive_master_key(new_master_password, new_master_salt)
            
            # Encrypt the new master key with the vault key
            encrypted_master_key = truefa_crypto.encrypt_master_key(new_master_key)
            
            # Update and save configuration
            self._vault_config['master_salt'] = new_master_salt
            self._vault_config['encrypted_master_key'] = encrypted_master_key
            
            with open(self.vault_file, 'w') as f:
                json.dump(self._vault_config, f)
            
            return True, "Master password changed successfully"
        except Exception as e:
            return False, f"Error changing master password: {e}"
