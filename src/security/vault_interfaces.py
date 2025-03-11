"""
Vault Interfaces Module

This module provides the main public interfaces to the secure vault system,
including creating, unlocking, and managing vaults.
"""

import os
import json
import base64
import logging
from datetime import datetime

from .secure_string import SecureString
from . import vault_auth
from . import vault_crypto
from . import vault_directory
from . import vault_master_key
from . import vault_state
from ..utils.debug import debug_print  # Import debug utility
from ..utils.logger import debug, warning, error, info  # Import full logger utilities

# Configure logging
logger = logging.getLogger(__name__)

class SecureVault:
    """
    Secure Vault Implementation for TOTP Secret Management
    
    Implements a two-layer envelope encryption model for maximum security:
    1. Vault password: Authenticates the user and decrypts the master key
    2. Master key: Used to encrypt/decrypt individual TOTP secrets
    
    This design provides several security benefits:
    - The master key is never stored directly, only in encrypted form
    - User can change vault password without re-encrypting all secrets
    - Compartmentalized security with different keys for different purposes
    - Memory-safe handling of sensitive cryptographic material
    """
    
    def __init__(self, storage_path=None):
        """
        Initialize the secure vault with the given storage path.
        
        Args:
            storage_path (str, optional): Path where vault files will be stored.
                If None, the default location will be used.
        """
        # Set up the vault directory
        if storage_path is None:
            # Use default locations
            from .vault_directory import get_secure_vault_dir
            self.vault_dir = get_secure_vault_dir()
            debug_print(f"Using default vault directory: {self.vault_dir}")
        else:
            # Use the specified location
            self.vault_dir = storage_path
            debug_print(f"Using specified vault directory: {self.vault_dir}")
        
        # Ensure the vault directory exists and has proper permissions
        from .vault_directory import create_secure_directory
        self.vault_dir = create_secure_directory(self.vault_dir)
        debug_print(f"Final vault directory after security checks: {self.vault_dir}")
        
        # Initialize the various components
        from . import vault_auth
        self.auth = vault_auth.VaultAuth(self.vault_dir)
        
        # Initialize the state manager
        from . import vault_state
        self.state_manager = vault_state.VaultStateManager(self.vault_dir)
        
        # Initialize the master key manager
        from . import vault_master_key
        self.master_key_manager = vault_master_key.MasterKeyManager(self.vault_dir)
        
        # Initialize state variables
        self._unlocked = False
        self._master_key = None
        
        # Check if vault exists
        debug_print(f"Checking if vault exists at: {os.path.join(self.vault_dir, 'vault.json')}")
        debug_print(f"Vault exists: {os.path.exists(os.path.join(self.vault_dir, 'vault.json'))}")
        debug_print(f"Vault initialized property: {self.is_initialized}")
        
    @property
    def is_initialized(self):
        """Check if the vault has been initialized."""
        try:
            # Check if the vault directory and required files exist
            vault_json_path = os.path.join(self.vault_dir, "vault.json")
            exists = os.path.exists(vault_json_path)
            
            debug_print(f"Checking vault initialization at: {vault_json_path}")
            debug_print(f"File exists: {exists}")
            
            if exists:
                # Also check that the vault file has the required fields
                try:
                    with open(vault_json_path, 'r') as f:
                        metadata = json.load(f)
                    
                    debug_print(f"Vault metadata keys: {list(metadata.keys())}")
                    
                    # Check for required fields
                    required_fields = ["version", "password_hash", "vault_salt"]
                    missing_fields = [field for field in required_fields if field not in metadata]
                    
                    if missing_fields:
                        debug_print(f"Vault file exists but is missing required fields: {missing_fields}")
                        return False
                        
                    debug_print(f"Vault is properly initialized with all required fields")
                    return True
                except Exception as e:
                    debug_print(f"Error reading vault metadata: {e}")
                    return False
            
            return exists
        except Exception as e:
            debug_print(f"Error checking vault initialization: {e}")
            return False
        
    # Add a __str__ method to properly convert to string
    def __str__(self):
        """Return a string representation of the vault."""
        status = "initialized" if self.is_initialized else "not initialized"
        return f"SecureVault({status})"
        
    @property
    def is_unlocked(self):
        """Check if the vault is currently unlocked."""
        debug(f"Checking is_unlocked property, value: {self._unlocked}, master_key: {self._master_key is not None}")
        return self._unlocked and self._master_key is not None
        
    def create_vault(self, vault_password, master_password=None):
        """
        Create a new vault with the given password
        
        Args:
            vault_password: Password to encrypt/decrypt the vault
            master_password: Optional separate password for the master key
            
        Returns:
            bool: True if vault was created successfully, False otherwise
        """
        try:
            from . import vault_crypto
            debug(f"Creating vault with password length {len(vault_password) if vault_password else 'None'}")
            
            # Build the path to the vault file
            vault_file = os.path.join(self.vault_dir, "vault.json")
            debug_print(f"DEBUG [vault_interfaces.py]: Using vault file path: {vault_file}")
            
            # Create the vault directory if it doesn't exist
            os.makedirs(os.path.dirname(vault_file), exist_ok=True)
            
            # Use our updated vault_crypto implementation
            vault_metadata = vault_crypto.create_vault(vault_password, vault_file)
            
            if not vault_metadata:
                debug_print("DEBUG [vault_interfaces.py]: Failed to create vault metadata")
                return False
                
            debug_print(f"DEBUG [vault_interfaces.py]: Vault created successfully with metadata keys: {list(vault_metadata.keys())}")
            
            # Read the metadata into the vault state
            self.metadata = vault_metadata
            
            # Mark the vault as unlocked and set the master key
            self._unlocked = True
            
            # Set the master key from the metadata (for testing only)
            if 'master_key' in vault_metadata:
                debug_print(f"DEBUG [vault_interfaces.py]: Setting master key from metadata")
                self._master_key = vault_metadata['master_key']
            
            return True
        except Exception as e:
            debug_print(f"ERROR [vault_interfaces.py]: Exception in create_vault: {e}")
            import traceback
            traceback.print_exc()
            
    def unlock(self, password):
        """
        Unlock the vault with the provided password
        
        Args:
            password: Password to unlock the vault
            
        Returns:
            bool: True if unlocked successfully, False otherwise
        """
        try:
            from . import vault_crypto
            import traceback
            
            debug(f"Attempting to unlock vault with password of length {len(password) if password else 'None'}")
            
            # Build the path to the vault file
            vault_file = os.path.join(self.vault_dir, "vault.json")
            debug_print(f"DEBUG [vault_interfaces.py]: Vault file path: {vault_file}")
            
            # Check if the vault file exists
            if not os.path.exists(vault_file):
                debug(f"Vault file does not exist at {vault_file}")
                return False
            
            # Load the vault metadata
            try:
                with open(vault_file, 'r') as f:
                    metadata = json.load(f)
                debug(f"Loaded vault metadata with keys: {list(metadata.keys())}")
            except Exception as e:
                error(f"Failed to decode vault JSON: {e}")
                return False
            
            # Get the vault salt
            vault_salt = metadata.get('vault_salt') or metadata.get('salt')
            if not vault_salt:
                error("No vault salt found in metadata")
                return False
            
            debug(f"Using vault salt: {vault_salt[:10]}...")
            
            # Verify the password using the vault_crypto module
            try:
                # Convert password to bytes if it's a string
                password_bytes = password.encode('utf-8') if isinstance(password, str) else password
                
                # Get the stored password hash
                stored_hash = metadata.get('password_hash')
                if not stored_hash:
                    error("No password hash found in metadata")
                    return False
                    
                debug("Verifying password against stored hash...")
                
                # Get the encryption method used
                key_derivation = metadata.get('key_derivation', 'pbkdf2')
                
                # Verify the password
                if key_derivation == 'truefa_crypto':
                    try:
                        from .. import truefa_crypto
                        derived_key = truefa_crypto.derive_key(password, vault_salt)
                        debug(f"Derived key with truefa_crypto: {len(derived_key) if derived_key else 'None'}")
                    except Exception as e:
                        warning(f"Error deriving key with truefa_crypto: {e}")
                        key_derivation = 'pbkdf2'
                        
                # Fall back to PBKDF2 if needed
                if key_derivation == 'pbkdf2':
                    import hashlib
                    salt_bytes = base64.b64decode(vault_salt)
                    derived_key = hashlib.pbkdf2_hmac('sha256', password_bytes, salt_bytes, 100000, 32)
                    derived_key = base64.b64encode(derived_key).decode('utf-8')
                    debug_print(f"DEBUG [vault_interfaces.py]: Derived key with PBKDF2: {len(derived_key) if derived_key else 'None'}")
                    
                # Check if the derived key matches the stored hash
                if derived_key != stored_hash:
                    debug("Password verification failed")
                    self._unlocked = False
                    self._master_key = None
                    return False
                    
                debug("Password verified successfully")
                
                # Decrypt the master key if present
                encrypted_master_key = metadata.get('encrypted_master_key')
                if encrypted_master_key:
                    debug("Decrypting master key...")
                    
                    # For testing, we can use the plaintext master key if available
                    if 'master_key' in metadata:
                        debug_print(f"DEBUG [vault_interfaces.py]: Using plaintext master key from metadata (for testing only)")
                        master_key = metadata['master_key']
                        self._master_key = master_key
                    else:
                        try:
                            from .. import truefa_crypto
                            master_key = truefa_crypto.decrypt_with_key(encrypted_master_key, derived_key)
                            debug_print(f"DEBUG [vault_interfaces.py]: Successfully decrypted master key with truefa_crypto")
                            self._master_key = master_key
                        except Exception as e:
                            debug_print(f"DEBUG [vault_interfaces.py]: Error decrypting with truefa_crypto: {e}")
                            # Fall back to simple decryption
                            try:
                                from Crypto.Cipher import AES
                                from Crypto.Util.Padding import unpad
                                
                                # Decode the encrypted data
                                encrypted_data = base64.b64decode(encrypted_master_key)
                                iv = encrypted_data[:16]
                                ciphertext = encrypted_data[16:]
                                
                                # Create the cipher
                                key = base64.b64decode(derived_key) if isinstance(derived_key, str) else derived_key
                                cipher = AES.new(key, AES.MODE_CBC, iv)
                                
                                # Decrypt the data
                                plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
                                # Store the binary data directly without trying to decode it
                                master_key = base64.b64encode(plaintext).decode('utf-8')
                                debug_print(f"DEBUG [vault_interfaces.py]: Successfully decrypted master key with AES")
                                self._master_key = master_key
                            except Exception as e:
                                debug_print(f"DEBUG [vault_interfaces.py]: Error decrypting with AES: {e}")
                                traceback.print_exc()
                                self._unlocked = False
                                self._master_key = None
                                return False
                    
                    # Store the master key
                    self._master_key = master_key
                    
                # Set unlocked state
                self._unlocked = True
                
                debug("Vault unlocked successfully")
                return True
                
            except Exception as e:
                error(f"Error verifying password: {e}")
                traceback.print_exc()
                self._unlocked = False
                self._master_key = None
                return False
            
        except Exception as e:
            error(f"Exception in unlock: {e}")
            traceback.print_exc()
            self._unlocked = False
            self._master_key = None
            return False
            
    def lock(self):
        """
        Lock the vault, clearing sensitive data from memory.
        
        Returns:
            bool: True if successful
        """
        try:
            # Clear the master key
            if self._master_key:
                self.master_key_manager.clear_master_key()
                self._master_key = None
                
            # Deauthenticate
            self.auth.deauthenticate()
                
            # Set vault state to locked
            self._unlocked = False
            
            return True
            
        except Exception as e:
            logger.error(f"Error locking vault: {e}")
            return False
            
    def get_master_key(self):
        """
        Get the master key for encrypting/decrypting secrets.
        
        Returns:
            SecureString: The master key, or None if vault is locked
        """
        debug(f"get_master_key called, is_unlocked: {self.is_unlocked}")
        if not self.is_unlocked:
            debug("Vault is locked. Cannot access master key.")
            return None
            
        return self._master_key
            
    def change_vault_password(self, current_password, new_password):
        """
        Change the vault password.
        
        This changes the password that protects the master key, without
        changing the master key itself. This means that all encrypted
        secrets remain valid.
        
        Args:
            current_password: The current vault password
            new_password: The new vault password
            
        Returns:
            bool: True if successful
        """
        try:
            # Authenticate with the current password
            if not self.unlock(current_password):
                logger.error("Failed to authenticate with current password")
                return False
                
            # Load the current master key
            if not self._master_key:
                logger.error("Failed to load master key")
                return False
                
            # Generate a new salt for the new password
            vault_salt = vault_crypto.generate_salt()
            
            # Create a new password hash
            password_hash, _ = self.auth.create_password_hash(new_password, vault_salt)
            password_hash_b64 = base64.b64encode(password_hash).decode('utf-8')
            
            # Re-encrypt the master key with the new password
            encrypted_master_key = self.master_key_manager.encrypt_master_key(new_password)
            
            if not encrypted_master_key:
                logger.error("Failed to encrypt master key with new password")
                return False
                
            # Update the vault metadata
            config = self.state_manager.load_config()
            if not config:
                logger.error("Failed to load vault metadata")
                return False
                
            config["salt"] = vault_salt
            config["password_hash"] = password_hash_b64
            config["encrypted_master_key"] = encrypted_master_key
            config["updated"] = datetime.now().isoformat()
            
            # Save the updated vault metadata
            if not self.state_manager.save_config(config):
                logger.error("Failed to save updated vault metadata")
                return False
                
            return True
            
        except Exception as e:
            logger.error(f"Error changing vault password: {e}")
            return False
            
    def change_master_password(self, vault_password, current_master_password, new_master_password):
        """
        Change the master password.
        
        This is a more complex operation that involves re-encrypting all secrets,
        since the master key itself is changing.
        
        Args:
            vault_password: The vault password
            current_master_password: The current master password
            new_master_password: The new master password
            
        Returns:
            bool: True if successful
        """
        logger.error("Master password changing not implemented yet")
        return False 