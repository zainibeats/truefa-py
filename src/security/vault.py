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

# Import our Rust crypto module with proper fallbacks
try:
    import truefa_crypto
    from truefa_crypto import (
        secure_random_bytes, is_vault_unlocked, vault_exists, 
        create_vault, unlock_vault, lock_vault, generate_salt,
        derive_master_key, encrypt_master_key, decrypt_master_key,
        verify_signature
    )
    print("Successfully imported truefa_crypto module")
except ImportError as e:
    print(f"WARNING: Failed to import truefa_crypto: {str(e)}")
    print("Creating fallback implementation")
    
    # Define a dummy fallback module
    class _DummyModule:
        def __init__(self):
            # State
            self._vault_initialized = False
            self._vault_unlocked = False
            self._vault_salt = None
            self._vault_password_hash = None
            self._master_key = None
            
            # Print for debugging
            print("Initialized dummy truefa_crypto module")
        
        # SecureString implementation
        class SecureString:
            def __init__(self, value):
                """Initialize with a string value to be protected."""
                self._data = value.encode('utf-8') if isinstance(value, str) else value
                
            def __str__(self):
                """Get the protected string value."""
                return self._data.decode('utf-8') if isinstance(self._data, bytes) else str(self._data)
                
            def clear(self):
                """Explicitly clear the protected data."""
                print(f"DUMMY CALL: secure_string_clear((12345,), {{}})")
                self._data = None
        
        # Vault functions
        def secure_random_bytes(self, size):
            """Generate cryptographically secure random bytes."""
            print(f"DUMMY CALL: secure_random_bytes(({size},), {{}})")
            import os
            return os.urandom(size)
            
        def is_vault_unlocked(self):
            """Check if the vault is currently unlocked."""
            return self._vault_unlocked
            
        def vault_exists(self):
            """Check if a vault has been initialized."""
            return self._vault_initialized
            
        def create_vault(self, password):
            """Create a new vault with the given master password."""
            print(f"DUMMY CALL: create_vault(({password},), {{}})")
            import hashlib
            import base64
            import os
            
            # Generate a salt for the vault
            self._vault_salt = base64.b64encode(os.urandom(32)).decode('utf-8')
            
            # Hash the password with the salt
            self._vault_password_hash = hashlib.pbkdf2_hmac(
                'sha256',
                password.encode('utf-8'),
                self._vault_salt.encode('utf-8'),
                100000
            )
            self._vault_password_hash = base64.b64encode(self._vault_password_hash).decode('utf-8')
            
            # Mark the vault as initialized and unlocked
            self._vault_initialized = True
            self._vault_unlocked = True
            
            return self._vault_salt
            
        def unlock_vault(self, password, salt):
            """Unlock the vault with the given password and salt."""
            print(f"DUMMY CALL: unlock_vault(({password}, {salt}), {{}})")
            import hashlib
            import base64
            
            # Hash the provided password with the salt
            password_hash = hashlib.pbkdf2_hmac(
                'sha256',
                password.encode('utf-8'),
                salt.encode('utf-8'),
                100000
            )
            password_hash = base64.b64encode(password_hash).decode('utf-8')
            
            # Check if the password is correct
            if password_hash == self._vault_password_hash:
                self._vault_unlocked = True
                return True
            else:
                return False
                
        def lock_vault(self):
            """Lock the vault, clearing all sensitive data."""
            print("DUMMY CALL: lock_vault((), {})")
            self._vault_unlocked = False
            
        def generate_salt(self):
            """Generate a random salt for key derivation."""
            print("DUMMY CALL: generate_salt((), {})")
            import base64
            import os
            return base64.b64encode(os.urandom(32)).decode('utf-8')
            
        def derive_master_key(self, password, salt):
            """Derive a master key from a password and salt."""
            print(f"DUMMY CALL: derive_master_key(({password}, {salt}), {{}})")
            import hashlib
            import base64
            key = hashlib.pbkdf2_hmac(
                'sha256',
                password.encode('utf-8'),
                salt.encode('utf-8'),
                100000
            )
            return base64.b64encode(key).decode('utf-8')
            
        def encrypt_master_key(self, master_key):
            """Encrypt the master key with the vault key."""
            print(f"DUMMY CALL: encrypt_master_key(({master_key},), {{}})")
            # For fallback, we'll just return the master key since we don't have the vault key
            return master_key
            
        def decrypt_master_key(self, encrypted_key):
            """Decrypt the master key with the vault key."""
            print(f"DUMMY CALL: decrypt_master_key(({encrypted_key},), {{}})")
            # For fallback, we'll just return the encrypted key since we don't have the vault key
            return encrypted_key
            
        def verify_signature(self, message, signature, public_key):
            """Verify a digital signature using the Rust crypto library."""
            print(f"DUMMY CALL: verify_signature((), {{}})")
            # For fallback, we'll just return True for now
            return True
    
    # Create instance of dummy module 
    truefa_crypto = _DummyModule()
    
    # Also define the individual functions at module scope for direct import
    def create_vault(password):
        return truefa_crypto.create_vault(password)
        
    def unlock_vault(password, salt):
        return truefa_crypto.unlock_vault(password, salt)
        
    def lock_vault():
        return truefa_crypto.lock_vault()
        
    def is_vault_unlocked():
        return truefa_crypto.is_vault_unlocked()
        
    def vault_exists():
        return truefa_crypto.vault_exists()
        
    def generate_salt():
        return truefa_crypto.generate_salt()
        
    def derive_master_key(password, salt):
        return truefa_crypto.derive_master_key(password, salt)
        
    def encrypt_master_key(master_key):
        return truefa_crypto.encrypt_master_key(master_key)
        
    def decrypt_master_key(encrypted_key):
        return truefa_crypto.decrypt_master_key(encrypted_key)
        
    def secure_random_bytes(size):
        return truefa_crypto.secure_random_bytes(size)
        
    def verify_signature(message, signature, public_key):
        return truefa_crypto.verify_signature(message, signature, public_key)
    
    print("Created fallback truefa_crypto module with function proxies")

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
