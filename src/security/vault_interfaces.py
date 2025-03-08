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
            print(f"Using default vault directory: {self.vault_dir}")
        else:
            # Use the specified location
            self.vault_dir = storage_path
            print(f"Using specified vault directory: {self.vault_dir}")
        
        # Ensure the vault directory exists and has proper permissions
        from . import vault_directory
        self.vault_dir = vault_directory.create_secure_directory(self.vault_dir)
        print(f"Final vault directory after security checks: {self.vault_dir}")
        
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
        print(f"Checking if vault exists at: {os.path.join(self.vault_dir, 'vault.json')}")
        print(f"Vault exists: {os.path.exists(os.path.join(self.vault_dir, 'vault.json'))}")
        print(f"Vault initialized property: {self.is_initialized}")
        
    @property
    def is_initialized(self):
        """Check if the vault has been initialized."""
        try:
            # Check if the vault directory and required files exist
            vault_json_path = os.path.join(self.vault_dir, "vault.json")
            exists = os.path.exists(vault_json_path)
            
            print(f"DEBUG: Checking vault initialization at: {vault_json_path}")
            print(f"DEBUG: File exists: {exists}")
            
            if exists:
                # Also check that the vault file has the required fields
                try:
                    with open(vault_json_path, 'r') as f:
                        metadata = json.load(f)
                    
                    print(f"DEBUG: Vault metadata keys: {list(metadata.keys())}")
                    
                    # Check for required fields
                    required_fields = ["version", "password_hash", "vault_salt"]
                    missing_fields = [field for field in required_fields if field not in metadata]
                    
                    if missing_fields:
                        print(f"DEBUG: Vault file exists but is missing required fields: {missing_fields}")
                        return False
                        
                    print(f"DEBUG: Vault is properly initialized with all required fields")
                    return True
                except Exception as e:
                    print(f"DEBUG: Error reading vault metadata: {e}")
                    return False
            
            return exists
        except Exception as e:
            print(f"DEBUG: Error checking vault initialization: {e}")
            return False
        
    # Add a __str__ method to properly convert to string
    def __str__(self):
        """Return a string representation of the vault."""
        status = "initialized" if self.is_initialized else "not initialized"
        return f"SecureVault({status})"
        
    @property
    def is_unlocked(self):
        """Check if the vault is currently unlocked."""
        return self._unlocked
        
    def create_vault(self, vault_password, master_password=None):
        """
        Create a new secure vault.
        
        Args:
            vault_password: The password to secure the vault with
            master_password: Optional separate password for the master key.
                If None, a secure random master key is generated.
                
        Returns:
            bool: True if creation was successful
        """
        try:
            # Make sure we're not overwriting an existing vault
            if self.is_initialized:
                logger.error("Vault already exists. Cannot create a new one.")
                return False
                
            # Create the vault using the state manager
            if master_password:
                result = self.state_manager.create_vault(vault_password, master_password)
            else:
                result = self.state_manager.create_vault(vault_password)
                
            if result:
                self._unlocked = True
                
            return result
        except Exception as e:
            logger.error(f"Failed to create vault: {e}")
            return False
            
    def unlock(self, password):
        """
        Unlock the vault with the provided password.
        
        Args:
            password: The vault password
            
        Returns:
            bool: True if unlock was successful
        """
        try:
            # Check if the vault is already unlocked
            if self.is_unlocked:
                return True
                
            # Authenticate with the vault
            if not self.auth.authenticate(password):
                logger.error("Failed to authenticate with vault")
                return False
                
            # Load the vault metadata
            config = self.state_manager.load_config()
            if not config:
                logger.error("Failed to load vault metadata")
                return False
                
            # Extract the encrypted master key
            encrypted_master_key = config.get("encrypted_master_key")
            if not encrypted_master_key:
                logger.error("Encrypted master key not found in vault metadata")
                return False
                
            # Decrypt the master key
            self._master_key = self.master_key_manager.decrypt_master_key(encrypted_master_key, password)
            if not self._master_key:
                logger.error("Failed to decrypt master key")
                return False
                
            # Set vault state to unlocked
            self._unlocked = True
            
            return True
            
        except Exception as e:
            logger.error(f"Error unlocking vault: {e}")
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
        if not self.is_unlocked:
            logger.error("Vault is locked. Cannot access master key.")
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