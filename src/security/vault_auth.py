"""
Vault Authentication Module

This module handles authentication for the secure vault, including:
- Password verification
- Hash generation and validation
- Authentication state management
"""

import os
import json
import base64
import hashlib
import logging
from pathlib import Path

from .secure_string import SecureString
from . import vault_crypto
from . import vault_directory

# Configure logging
logger = logging.getLogger(__name__)

class VaultAuth:
    """
    Handles authentication for the secure vault.
    
    This class manages:
    - Password verification
    - Cryptographic hash generation
    - Authentication state
    """
    
    def __init__(self, vault_dir):
        """
        Initialize the vault authentication module.
        
        Args:
            vault_dir: Path to the vault directory
        """
        self.vault_dir = vault_dir
        self.vault_path = os.path.join(vault_dir, "vault.json")
        self._is_authenticated = False
    
    @property
    def is_authenticated(self):
        """Check if the vault is authenticated."""
        return self._is_authenticated
    
    def verify_password(self, password, stored_hash, salt):
        """
        Verify a password against a stored hash.
        
        Args:
            password: The password to verify
            stored_hash: The stored hash to compare against
            salt: The salt used for the hash
            
        Returns:
            bool: True if the password is valid
        """
        # Derive key from password and salt
        try:
            # Convert the salt from base64 to bytes if needed
            if isinstance(salt, str):
                salt_bytes = base64.b64decode(salt)
            else:
                salt_bytes = salt
                
            # Convert the stored hash from base64 to bytes if needed
            if isinstance(stored_hash, str):
                stored_hash_bytes = base64.b64decode(stored_hash)
            else:
                stored_hash_bytes = stored_hash
                
            # Derive the key using PBKDF2
            derived_key = hashlib.pbkdf2_hmac(
                'sha256',
                password.encode('utf-8'),
                salt_bytes,
                100000,  # 100,000 iterations
                dklen=32  # 32 bytes = 256 bits
            )
            
            # Compare the derived key with the stored hash
            return derived_key == stored_hash_bytes
        except Exception as e:
            logger.error(f"Error verifying password: {e}")
            return False
    
    def create_password_hash(self, password, salt=None):
        """
        Create a password hash using PBKDF2.
        
        Args:
            password: The password to hash
            salt: Optional salt, generated if None
            
        Returns:
            tuple: (hash (bytes), salt (bytes))
        """
        try:
            # Generate a random salt if not provided
            if salt is None:
                salt = os.urandom(16)  # 16 bytes = 128 bits
            elif isinstance(salt, str):
                # Convert from base64 if it's a string
                salt = base64.b64decode(salt)
                
            # Derive the key using PBKDF2
            key = hashlib.pbkdf2_hmac(
                'sha256',
                password.encode('utf-8'),
                salt,
                100000,  # 100,000 iterations
                dklen=32  # 32 bytes = 256 bits
            )
            
            return key, salt
        except Exception as e:
            logger.error(f"Error creating password hash: {e}")
            return None, None
    
    def authenticate(self, password):
        """
        Authenticate with the provided password.
        
        Args:
            password: The password to authenticate with
            
        Returns:
            bool: True if authentication succeeded
        """
        try:
            # Check if the vault exists
            if not os.path.exists(self.vault_path):
                logger.error(f"Vault metadata not found at: {self.vault_path}")
                return False
                
            # Load the vault metadata
            with open(self.vault_path, 'r') as f:
                meta_data = json.load(f)
                
            # Get the salt and password hash
            vault_salt = meta_data.get('salt')
            stored_hash_b64 = meta_data.get('password_hash')
            
            if not vault_salt:
                logger.error("Vault salt not found in metadata")
                return False
                
            if not stored_hash_b64:
                logger.error("Password hash not found in metadata")
                return False
                
            # Verify the password
            if not self.verify_password(password, stored_hash_b64, vault_salt):
                logger.error("Invalid password for vault")
                return False
                
            # Set authenticated state
            self._is_authenticated = True
            return True
                
        except Exception as e:
            logger.error(f"Error authenticating vault: {e}")
            return False
    
    def deauthenticate(self):
        """
        Deauthenticate from the vault.
        
        Returns:
            bool: True if successful
        """
        self._is_authenticated = False
        return True 