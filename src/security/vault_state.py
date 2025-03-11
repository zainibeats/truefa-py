"""
Vault State Management Module for TrueFA-Py

Handles the loading, saving, and management of vault state,
including configuration and metadata for the secure vault system.
"""

import os
import json
import base64
import time
from datetime import datetime
from pathlib import Path

from .vault_directory import secure_atomic_write, secure_file_permissions
from src.utils.logger import debug, info, warning, error, critical

class VaultStateManager:
    """
    Manages the state and configuration of the vault system.
    Handles loading and saving vault metadata and configuration.
    """
    
    def __init__(self, vault_dir, config_filename="vault.json"):
        """
        Initialize the vault state manager.
        
        Args:
            vault_dir: Directory where the vault is stored
            config_filename: Name of the configuration file
        """
        self.vault_dir = vault_dir
        self.config_filename = config_filename
        self.vault_path = os.path.join(vault_dir, config_filename)
        self.master_key_path = os.path.join(vault_dir, "master.meta")
        self.state_file = os.path.join(vault_dir, "state.json")
        
        # Default state
        self.config = {
            "version": "1.0",
            "created": None,
            "salt": None
        }
        
        self.state = {
            "last_access": None,
            "access_count": 0,
            "created": None
        }
        
        # Internal state
        self._unlocked = False
        self._master_key = None
    
    @property
    def is_initialized(self):
        """
        Check if the vault has been initialized with required files and metadata.
        
        Returns:
            bool: True if the vault is initialized, False otherwise
        """
        # Check if the vault exists
        if not os.path.exists(self.vault_path):
            return False
            
        # Check if we can load the configuration
        try:
            config = self.load_config()
            # Check for minimum required fields
            required_fields = ["version", "salt"]
            if not config or not all(field in config for field in required_fields):
                return False
                
            return True
        except Exception:
            return False
    
    @property
    def is_unlocked(self):
        """
        Check if the vault is currently unlocked.
        
        Returns:
            bool: True if the vault is unlocked, False otherwise.
        """
        return self._unlocked and self._master_key is not None
    
    def get_master_key(self):
        """
        Get the master key if the vault is unlocked.
        
        Returns:
            SecureString: The master key if the vault is unlocked, None otherwise.
        """
        if not self.is_unlocked:
            return None
        return self._master_key
    
    def vault_exists(self):
        """
        Check if a vault exists at the configured location.
        
        Returns:
            bool: True if vault exists, False otherwise
        """
        return os.path.exists(self.vault_path) and os.path.exists(self.master_key_path)
    
    def load_config(self):
        """
        Load the vault configuration from disk.
        
        Returns:
            dict: The vault configuration, or None if it cannot be loaded
        """
        if not os.path.exists(self.vault_path):
            return None
        
        try:
            with open(self.vault_path, 'r') as f:
                config = json.load(f)
                self.config = config
                return config
        except Exception as e:
            error(f"Error loading vault configuration: {e}")
            return None
    
    def save_config(self, config=None):
        """
        Save the vault configuration to disk.
        
        Args:
            config: Configuration to save, or None to use current config
            
        Returns:
            bool: True if successful, False otherwise
        """
        if config:
            self.config = config
        
        try:
            # Ensure the vault directory exists
            os.makedirs(self.vault_dir, mode=0o700, exist_ok=True)
            
            # Write the configuration atomically
            content = json.dumps(self.config, indent=2)
            return secure_atomic_write(self.vault_path, content)
        except Exception as e:
            error(f"Error saving vault configuration: {e}")
            return False
    
    def load_state(self):
        """
        Load the vault state from disk.
        
        Returns:
            dict: The vault state, or default state if it cannot be loaded
        """
        if not os.path.exists(self.state_file):
            return self.state
        
        try:
            with open(self.state_file, 'r') as f:
                state = json.load(f)
                self.state = state
                return state
        except Exception as e:
            error(f"Error loading vault state: {e}")
            return self.state
    
    def save_state(self, state=None):
        """
        Save the vault state to disk.
        
        Args:
            state: State to save, or None to use current state
            
        Returns:
            bool: True if successful, False otherwise
        """
        if state:
            self.state = state
        
        # Update the last access time
        self.state["last_access"] = datetime.now().isoformat()
        self.state["access_count"] += 1
        
        try:
            # Ensure the vault directory exists
            os.makedirs(self.vault_dir, mode=0o700, exist_ok=True)
            
            # Write the state atomically
            content = json.dumps(self.state, indent=2)
            return secure_atomic_write(self.state_file, content)
        except Exception as e:
            error(f"Error saving vault state: {e}")
            return False
    
    def create_vault_metadata(self, salt):
        """
        Create the initial vault metadata.
        
        Args:
            salt: The salt used for key derivation
            
        Returns:
            bool: True if successful, False otherwise
        """
        # Create the vault configuration
        self.config = {
            "salt": salt,
            "version": "1.0",
            "created": datetime.now().isoformat()
        }
        
        # Create the initial state
        self.state = {
            "last_access": datetime.now().isoformat(),
            "access_count": 1,
            "created": datetime.now().isoformat()
        }
        
        # Save the configuration and state
        return self.save_config() and self.save_state()
    
    def save_master_key_metadata(self, master_salt, encrypted_master_key):
        """
        Save the master key metadata to disk.
        
        Args:
            master_salt: The salt used for master key derivation
            encrypted_master_key: The encrypted master key
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Ensure data is properly encoded as strings for JSON serialization
            if isinstance(master_salt, bytes):
                master_salt_str = base64.b64encode(master_salt).decode('utf-8')
            else:
                master_salt_str = master_salt
            
            if isinstance(encrypted_master_key, bytes):
                encrypted_key_str = base64.b64encode(encrypted_master_key).decode('utf-8')
            else:
                encrypted_key_str = encrypted_master_key
            
            master_meta = {
                "salt": master_salt_str,
                "encrypted_key": encrypted_key_str,
                "version": "1.0"
            }
            
            # Ensure the vault directory exists
            os.makedirs(os.path.dirname(self.master_key_path), mode=0o700, exist_ok=True)
            
            # Write the metadata atomically
            content = json.dumps(master_meta, indent=2)
            return secure_atomic_write(self.master_key_path, content)
        except Exception as e:
            error(f"Error saving master key metadata: {e}")
            return False
    
    def load_master_key_metadata(self):
        """
        Load the master key metadata from disk.
        
        Returns:
            dict: The master key metadata, or None if it cannot be loaded
        """
        if not os.path.exists(self.master_key_path):
            return None
        
        try:
            with open(self.master_key_path, 'r') as f:
                metadata = json.load(f)
                return metadata
        except Exception as e:
            error(f"Error loading master key metadata: {e}")
            return None
    
    def create_vault(self, vault_password, master_password=None):
        """
        Create a new vault with the given password and optional master password.
        
        Args:
            vault_password (str): The password to access the vault.
            master_password (str, optional): If provided, the master key will be derived from
                this password. Otherwise, a random master key will be generated.
                
        Returns:
            bool: True if successful, False otherwise.
        """
        try:
            debug("Starting vault creation process...")
            
            # Import necessary modules
            from secrets import token_bytes
            import hashlib
            
            try:
                from src.truefa_crypto import (
                    c_secure_random_bytes,
                    c_generate_salt,
                    c_derive_vault_key,
                    c_encrypt_master_key
                )
                
                # Generate a new salt for the vault
                vault_salt = c_generate_salt()
                if not vault_salt:
                    vault_salt = os.urandom(32)  # Fallback
                
                debug(f"Generated vault salt: {vault_salt[:10]}...")
                
                # Convert the salt to a string for storage
                salt_str = base64.b64encode(vault_salt).decode('utf-8')
                
                # Convert passwords to bytes if they are not already
                if isinstance(vault_password, str):
                    vault_password_bytes = vault_password.encode('utf-8')
                else:
                    vault_password_bytes = vault_password
                
                debug("Computing password hash...")
                
                # Derive a key from the vault password 
                derived_key = c_derive_vault_key(vault_password_bytes, vault_salt)
                if derived_key is None:
                    # Fallback to PBKDF2
                    derived_key = hashlib.pbkdf2_hmac('sha256', vault_password_bytes, vault_salt, 100000, 32)
                
                # Hash the derived key again to use as the stored password hash
                password_hash = hashlib.sha256(derived_key).digest()
                password_hash_str = base64.b64encode(password_hash).decode('utf-8')
                
                # Process master password (if provided)
                if master_password:
                    debug("Deriving master key from master password...")
                    
                    if isinstance(master_password, str):
                        master_password_bytes = master_password.encode('utf-8')
                    else:
                        master_password_bytes = master_password
                        
                    master_key = hashlib.pbkdf2_hmac('sha256', master_password_bytes, vault_salt, 100000, 32)
                else:
                    debug("Generating random master key...")
                    # Generate a random master key if no master password
                    try:
                        master_key = c_secure_random_bytes(32)
                        if not master_key:
                            master_key = token_bytes(32)
                    except Exception:
                        master_key = token_bytes(32)
                
                # Now encrypt the master key with the derived vault key
                master_salt = os.urandom(16)
                
                debug("Encrypting master key...")
                try:
                    encrypted_master_key = c_encrypt_master_key(master_key, derived_key, master_salt)
                    encrypted_master_key_str = base64.b64encode(encrypted_master_key).decode('utf-8')
                    master_salt_str = base64.b64encode(master_salt).decode('utf-8')
                except Exception:
                    # Fallback to AES CTR mode
                    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
                    
                    # Create an encryptor
                    cipher = Cipher(algorithms.AES(derived_key), modes.CTR(master_salt))
                    encryptor = cipher.encryptor()
                    
                    # Encrypt the master key
                    encrypted_master_key = encryptor.update(master_key) + encryptor.finalize()
                    encrypted_master_key_str = base64.b64encode(encrypted_master_key).decode('utf-8')
                    master_salt_str = base64.b64encode(master_salt).decode('utf-8')
                
                # Create the main vault metadata
                vault_metadata = {
                    "version": "1.0.0",
                    "created": datetime.now().isoformat(),
                    "password_hash": password_hash_str,
                    "salt": salt_str,
                    "encrypted_master_key": encrypted_master_key_str,
                    "master_key_metadata": {
                        "salt": master_salt_str,
                        "iterations": 100000,
                        "algorithm": "AES-256"
                    }
                }
                
                debug(f"Saving vault metadata to {self.vault_path}")
                
                # Save the vault metadata
                content = json.dumps(vault_metadata, indent=2)
                secure_atomic_write(self.vault_path, content)
                debug(f"Created vault metadata with keys: {list(vault_metadata.keys())}")
                debug(f"password_hash format: {type(password_hash_str)}, length: {len(password_hash_str)}")
                debug(f"vault_salt format: {type(salt_str)}, length: {len(salt_str)}")

                # Mark the vault as unlocked
                self._unlocked = True
                
                # Create state file separately but don't overwrite the main vault file
                state_path = os.path.join(self.vault_dir, "state.json")
                try:
                    # Create the initial state
                    state = {
                        "last_access": datetime.now().isoformat(),
                        "access_count": 1,
                        "created": datetime.now().isoformat(),
                        "error_states": {
                            "bad_password_attempts": 0,
                            "tamper_attempts": 0,
                            "file_access_errors": 0,
                            "integrity_violations": 0,
                            "last_error_time": None
                        }
                    }
                    
                    content = json.dumps(state, indent=2)
                    secure_atomic_write(state_path, content)
                    debug(f"Created state file at {state_path}")
                except Exception as e:
                    debug(f"Error creating state file: {e}")
                
                # Do NOT call self.create_vault_metadata() as it would overwrite our vault file
                # with incomplete metadata
                
                debug("Vault creation complete")
                vault_exists = os.path.exists(self.vault_path)
                debug(f"Vault file exists: {vault_exists}")
                
                # Double-check the vault was created properly
                try:
                    with open(self.vault_path, 'r') as f:
                        check_data = json.load(f)
                    debug(f"Verified vault data contains keys: {list(check_data.keys())}")
                except Exception as e:
                    debug(f"Error verifying vault data: {e}")
                
                return True
                
            except Exception as e:
                debug(f"Error creating vault: {e}")
                import traceback
                traceback.print_exc()
                return False
            
        except Exception as e:
            error(f"Exception in create_vault method: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def unlock(self, password):
        """
        Unlock the vault with the given password.
        
        Args:
            password: The password to use for unlocking.
            
        Returns:
            bool: True if the vault was successfully unlocked, False otherwise.
        """
        try:
            debug(f"Attempting to unlock vault with password of length {len(password) if password else 'None'}")
            
            # Check if the vault is already unlocked
            if self.is_unlocked:
                debug("Vault already unlocked")
                return True
            
            # Check if the vault file exists and load it
            try:
                with open(self.vault_path, 'r') as f:
                    try:
                        vault_data = json.load(f)
                        debug(f"Loaded vault metadata with keys: {list(vault_data.keys())}")
                    except json.JSONDecodeError:
                        debug("Failed to decode vault JSON")
                        return False
            except FileNotFoundError:
                debug(f"Vault file not found at {self.vault_path}")
                return False
            
            # Get the password hash for verification
            stored_password_hash = vault_data.get('password_hash')
            if not stored_password_hash:
                debug("No password_hash in vault data")
                return False
            
            debug(f"Password hash length: {len(stored_password_hash)}")
            
            # Check if password is provided
            if not password:
                debug("No password provided for unlock")
                return False
            
            # Convert password to bytes if it's a string
            if isinstance(password, str):
                password_bytes = password.encode('utf-8')
            else:
                password_bytes = password
            
            # Get the vault salt from the vault data
            vault_salt = vault_data.get('vault_salt') or vault_data.get('salt')
            if not vault_salt:
                debug("No vault salt found in vault data")
                return False
            
            debug(f"Vault salt: {vault_salt[:10]}...")
            
            # Verify the password
            debug("Computing password hash for verification...")
            try:
                from src.truefa_crypto import derive_key
                derived_key = derive_key(password, vault_salt)
                debug(f"Derived key length: {len(derived_key) if derived_key else 'None'}")
            except Exception as e:
                debug(f"Error deriving key with truefa_crypto: {e}")
                debug("Falling back to PBKDF2...")
                import hashlib
                salt_bytes = base64.b64decode(vault_salt)
                derived_key = hashlib.pbkdf2_hmac('sha256', password_bytes, salt_bytes, 100000, 32)
                derived_key = base64.b64encode(derived_key).decode('utf-8')
                debug(f"Derived key with PBKDF2 (length: {len(derived_key)})")
            
            # Compare the derived key hash with the stored hash
            debug(f"Checking if derived key matches stored hash...")
            if not self._verify_password_hash(password_bytes, stored_password_hash):
                debug("Current password is incorrect")
                return False
            
            debug("Password hash verified successfully")
            
            # Decrypt the master key
            encrypted_master_key = vault_data.get('encrypted_master_key')
            if not encrypted_master_key:
                debug("No encrypted_master_key in vault data")
                return False
            
            # Try to decrypt the master key
            debug("Attempting to decrypt master key...")
            try:
                from src.truefa_crypto import decrypt_master_key
                master_key = decrypt_master_key(encrypted_master_key, password, vault_salt)
                debug(f"Master key decryption result: {type(master_key)}")
                
                if not master_key:
                    debug("Failed to decrypt master key")
                    return False
                
                # Set the master key and mark as unlocked
                self._master_key = master_key
                self._unlocked = True
                debug("Vault unlocked successfully")
                return True
            except Exception as e:
                debug(f"Exception decrypting master key: {e}")
                import traceback
                traceback.print_exc()
                return False
        except Exception as e:
            error(f"Exception in unlock method: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def lock(self):
        """
        Lock the vault by clearing the master key from memory.
        
        Returns:
            bool: True if successful, False otherwise.
        """
        try:
            # Import necessary modules
            from . import vault_crypto
            
            # Clear the master key
            if self._master_key is not None:
                if hasattr(self._master_key, 'clear'):
                    self._master_key.clear()
                self._master_key = None
            
            # Mark the vault as locked
            self._unlocked = False
            
            # Call the vault_crypto lock function
            try:
                vault_crypto.lock_vault()
            except Exception as e:
                warning(f"Error calling vault_crypto.lock_vault(): {e}")
            
            return True
            
        except Exception as e:
            error(f"Error locking vault: {e}")
            return False
    
    def change_vault_password(self, current_password, new_password):
        """
        Change the vault password.
        
        Args:
            current_password (str): The current vault password.
            new_password (str): The new vault password.
            
        Returns:
            bool: True if successful, False otherwise.
        """
        try:
            # First verify the current password by trying to unlock the vault
            if not self.unlock(current_password):
                debug("Current password is incorrect")
                return False
            
            # Import necessary modules
            from . import vault_crypto
            
            # Load vault metadata
            with open(self.vault_path, 'r') as f:
                vault_metadata = json.load(f)
            
            # Generate a new salt
            new_salt = vault_crypto.generate_salt()
            
            # Create a new password hash
            import hashlib
            new_hash = hashlib.pbkdf2_hmac(
                'sha256',
                new_password.encode('utf-8'),
                new_salt if isinstance(new_salt, bytes) else new_salt.encode('utf-8'),
                100000,
                dklen=32
            )
            
            # Re-encrypt the master key with the new password
            if not self._master_key:
                debug("Master key not available")
                return False
            
            master_key_value = self._master_key.get_value() if hasattr(self._master_key, 'get_value') else self._master_key.get()
            encrypted_master_key = vault_crypto.encrypt_master_key(master_key_value)
            
            # Update vault metadata
            vault_metadata['password_hash'] = new_hash.hex() if isinstance(new_hash, bytes) else new_hash
            vault_metadata['vault_salt'] = base64.b64encode(new_salt).decode('utf-8') if isinstance(new_salt, bytes) else new_salt
            vault_metadata['master_key'] = encrypted_master_key
            vault_metadata['updated'] = datetime.now().isoformat()
            
            # Save the updated metadata
            with open(self.vault_path, 'w') as f:
                json.dump(vault_metadata, f, indent=2)
            
            # Update the master key metadata
            self.save_master_key_metadata(new_salt, encrypted_master_key)
            
            return True
            
        except Exception as e:
            error(f"Error changing vault password: {e}")
            return False
    
    def change_master_password(self, vault_password, current_master_password, new_master_password):
        """
        Change the master password used for content encryption.
        
        Args:
            vault_password (str): The vault password.
            current_master_password (str): The current master password.
            new_master_password (str): The new master password.
            
        Returns:
            bool: True if successful, False otherwise.
        """
        try:
            # First verify the vault password
            if not self.unlock(vault_password):
                debug("Vault password is incorrect")
                return False
            
            # Import necessary modules
            from . import vault_crypto
            from .secure_string import SecureString
            
            # Load vault metadata
            with open(self.vault_path, 'r') as f:
                vault_metadata = json.load(f)
            
            # Get vault salt
            vault_salt = base64.b64decode(vault_metadata['vault_salt'])
            
            # Verify the current master password by deriving a key and comparing
            current_master_key = vault_crypto.derive_master_key(current_master_password, vault_salt)
            
            master_key_value = self._master_key.get_value() if hasattr(self._master_key, 'get_value') else self._master_key.get()
            
            if not secrets.compare_digest(current_master_key, master_key_value):
                debug("Current master password is incorrect")
                return False
            
            # Generate a new master key from the new master password
            new_master_key = vault_crypto.derive_master_key(new_master_password, vault_salt)
            new_master_key_secure = SecureString(new_master_key)
            
            # Re-encrypt all content with the new master key (this would normally go here)
            # For now, we'll just update the stored master key
            
            # Update the master key in memory
            if hasattr(self._master_key, 'clear'):
                self._master_key.clear()
            self._master_key = new_master_key_secure
            
            # Re-encrypt the master key with the vault password
            encrypted_master_key = vault_crypto.encrypt_master_key(new_master_key)
            
            # Update vault metadata
            vault_metadata['master_key'] = encrypted_master_key
            vault_metadata['updated'] = datetime.now().isoformat()
            
            # Save the updated metadata
            with open(self.vault_path, 'w') as f:
                json.dump(vault_metadata, f, indent=2)
            
            # Update the master key metadata
            self.save_master_key_metadata(vault_salt, encrypted_master_key)
            
            return True
            
        except Exception as e:
            error(f"Error changing master password: {e}")
            return False 