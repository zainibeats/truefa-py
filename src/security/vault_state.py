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
            print(f"Error loading vault configuration: {e}")
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
            print(f"Error saving vault configuration: {e}")
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
            print(f"Error loading vault state: {e}")
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
            print(f"Error saving vault state: {e}")
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
        # Ensure data is properly encoded as strings for JSON serialization
        if isinstance(master_salt, bytes):
            master_salt = base64.b64encode(master_salt).decode('utf-8')
        
        if isinstance(encrypted_master_key, bytes):
            encrypted_master_key = base64.b64encode(encrypted_master_key).decode('utf-8')
        
        master_meta = {
            "salt": master_salt,
            "encrypted_key": encrypted_master_key,
            "version": "1.0"
        }
        
        try:
            # Ensure the vault directory exists
            os.makedirs(os.path.dirname(self.master_key_path), mode=0o700, exist_ok=True)
            
            # Write the metadata atomically
            content = json.dumps(master_meta, indent=2)
            return secure_atomic_write(self.master_key_path, content)
        except Exception as e:
            print(f"Error saving master key metadata: {e}")
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
            print(f"Error loading master key metadata: {e}")
            return None 