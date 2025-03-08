"""
Vault Master Key Management

This module manages the master key for the secure vault, including:
- Master key generation
- Master key encryption/decryption
- Secure key storage and retrieval
"""

import os
import json
import base64
import logging
from datetime import datetime

from .secure_string import SecureString
from . import vault_crypto
from . import vault_directory

# Configure logging
logger = logging.getLogger(__name__)

class MasterKeyManager:
    """
    Manages the master key used for encrypting vault secrets.
    
    This includes:
    - Generating master keys
    - Safely storing master keys (encrypted using the vault key)
    - Loading and decrypting master keys
    """
    
    def __init__(self, vault_dir):
        """
        Initialize the master key manager.
        
        Args:
            vault_dir: The vault directory where master key metadata is stored
        """
        self.vault_dir = vault_dir
        self.master_key_path = os.path.join(vault_dir, "master.json")
        self._master_key = None
        
    @property
    def has_master_key(self):
        """Check if a master key has been loaded."""
        return self._master_key is not None
        
    def create_master_key(self, master_password=None):
        """
        Create a new master key.
        
        Args:
            master_password: Optional password to derive the master key from.
                If None, a random key is generated.
                
        Returns:
            SecureString: The generated master key
        """
        try:
            # If a master password is provided, derive a key from it
            if master_password:
                # Generate a salt
                master_salt = vault_crypto.generate_salt()
                
                # Derive the master key from the password and salt
                master_key = vault_crypto.derive_master_key(master_password, master_salt)
                
                # Store the master key
                self._master_key = SecureString(base64.b64decode(master_key))
                
                # Save the salt for later verification
                self._save_master_key_metadata(master_salt)
                
            else:
                # Generate a random master key
                master_key_bytes = os.urandom(32)  # 32 bytes = 256 bits
                self._master_key = SecureString(master_key_bytes)
                
            return self._master_key
            
        except Exception as e:
            logger.error(f"Error creating master key: {e}")
            return None
            
    def encrypt_master_key(self, vault_password):
        """
        Encrypt the master key using the vault password.
        
        This creates an encrypted version of the master key that can be
        safely stored on disk, protected by the vault password.
        
        Args:
            vault_password: Password to encrypt the master key with
            
        Returns:
            str: The encrypted master key in base64 format
        """
        try:
            if not self._master_key:
                logger.error("No master key available to encrypt")
                return None
                
            # Convert the master key to a string
            master_key_str = base64.b64encode(self._master_key.get()).decode('utf-8')
            
            # Encrypt using the vault_crypto module
            encrypted_master_key = vault_crypto.encrypt_master_key(master_key_str)
            
            return encrypted_master_key
            
        except Exception as e:
            logger.error(f"Error encrypting master key: {e}")
            return None
            
    def decrypt_master_key(self, encrypted_master_key, vault_password):
        """
        Decrypt the master key using the vault password.
        
        Args:
            encrypted_master_key: The encrypted master key
            vault_password: The password to decrypt with
            
        Returns:
            SecureString: The decrypted master key
        """
        try:
            # Decrypt using vault_crypto
            decrypted_master_key = vault_crypto.decrypt_master_key(encrypted_master_key)
            
            # Convert to a SecureString
            if decrypted_master_key:
                self._master_key = SecureString(base64.b64decode(decrypted_master_key))
                return self._master_key
                
            return None
            
        except Exception as e:
            logger.error(f"Error decrypting master key: {e}")
            return None
            
    def load_master_key(self, vault_password):
        """
        Load and decrypt the master key using the vault password.
        
        Args:
            vault_password: The vault password to decrypt with
            
        Returns:
            SecureString: The decrypted master key, or None if failed
        """
        try:
            # Check if the master key metadata exists
            if not os.path.exists(self.master_key_path):
                logger.error(f"Master key metadata not found at: {self.master_key_path}")
                return None
                
            # Load the master key metadata
            with open(self.master_key_path, 'r') as f:
                meta_data = json.load(f)
                
            # Get the encrypted master key
            encrypted_master_key = meta_data.get('encrypted_master_key')
            
            if not encrypted_master_key:
                logger.error("Encrypted master key not found in metadata")
                return None
                
            # Decrypt the master key
            return self.decrypt_master_key(encrypted_master_key, vault_password)
            
        except Exception as e:
            logger.error(f"Error loading master key: {e}")
            return None
            
    def clear_master_key(self):
        """
        Clear the master key from memory.
        
        Returns:
            bool: True if successful
        """
        try:
            if self._master_key:
                self._master_key.clear()
                self._master_key = None
            return True
        except Exception as e:
            logger.error(f"Error clearing master key: {e}")
            return False
            
    def _save_master_key_metadata(self, master_salt, encrypted_master_key=None):
        """
        Save the master key metadata to disk.
        
        Args:
            master_salt: The salt used to derive the master key
            encrypted_master_key: The encrypted master key (optional)
            
        Returns:
            bool: True if successful
        """
        try:
            # Create the metadata
            meta_data = {
                "version": "1.0",
                "created": datetime.now().isoformat(),
                "master_salt": master_salt
            }
            
            # Add the encrypted master key if provided
            if encrypted_master_key:
                meta_data["encrypted_master_key"] = encrypted_master_key
                
            # Ensure the directory exists
            vault_directory.create_secure_directory(os.path.dirname(self.master_key_path))
                
            # Save the metadata
            with open(self.master_key_path, 'w') as f:
                json.dump(meta_data, f, indent=2)
                
            # Set secure permissions
            vault_directory.secure_file_permissions(self.master_key_path)
                
            return True
            
        except Exception as e:
            logger.error(f"Error saving master key metadata: {e}")
            return False 