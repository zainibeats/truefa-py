"""
Simplified SecureVault for TrueFA-Py GUI

This module provides a simplified version of the SecureVault class
for use in the GUI application, while ensuring compatibility with
the core vault functionality.
"""

import os
import sys
import json
import hashlib
import logging
from pathlib import Path
import base64
import shutil
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

class SecureVault:
    """
    Simplified SecureVault for storing and retrieving TOTP secrets
    
    This class provides a simplified interface for the GUI application
    to interact with the vault while maintaining compatibility with
    the core functionality.
    """
    
    def __init__(self):
        """Initialize the SecureVault"""
        # Determine vault path
        self.vault_path = self._get_vault_path()
        self.vault_dir = os.path.dirname(self.vault_path)
        
        # Create vault directory if it doesn't exist
        os.makedirs(self.vault_dir, exist_ok=True)
        
        # Initialize state
        self.master_password = None
        self.is_unlocked = False
        
        # Set up logging
        self.logger = logging.getLogger(__name__)
    
    def _get_vault_path(self):
        """Get the path to the vault file"""
        # Check environment variable
        vault_path = os.environ.get('TRUEFA_VAULT_FILE')
        if vault_path:
            return vault_path
        
        # Use default path
        data_dir = os.environ.get('TRUEFA_DATA_DIR')
        if not data_dir:
            if sys.platform == 'win32':
                base_dir = os.environ.get('APPDATA')
                if not base_dir:
                    base_dir = os.path.join(os.path.expanduser('~'), 'AppData', 'Roaming')
                data_dir = os.path.join(base_dir, "TrueFA-Py")
            elif sys.platform == 'darwin':
                data_dir = os.path.join(os.path.expanduser('~'), 'Library', 'Application Support', "TrueFA-Py")
            else:
                data_dir = os.path.join(os.path.expanduser('~'), '.truefa')
        
        # Ensure the vault directory exists
        vault_dir = os.path.join(data_dir, "vault")
        os.makedirs(vault_dir, exist_ok=True)
        
        # Use appropriate permissions on non-Windows systems
        if sys.platform != 'win32':
            try:
                import stat
                os.chmod(vault_dir, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)  # 0o700
            except Exception as e:
                self.logger.warning(f"Failed to set secure permissions: {e}")
        
        return os.path.join(vault_dir, "vault.json")
    
    @property
    def is_initialized(self):
        """Check if the vault exists and is initialized"""
        return os.path.exists(self.vault_path)
    
    def exists(self):
        """
        Check if the vault file exists
        
        Returns:
            bool: True if the vault file exists, False otherwise
        """
        return os.path.exists(self.vault_path)
    
    def create(self, password):
        """
        Create a new vault with the given password
        
        Args:
            password (str): Master password for the vault
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Validate password
            if not password or len(password) < 8:
                self.logger.error("Password must be at least 8 characters long")
                return False
            
            # Create empty secrets dictionary
            secrets = {}
            
            # Encrypt and save
            self._save_encrypted(secrets, password)
            
            # Set state
            self.master_password = password
            self.is_unlocked = True
            
            # Log success
            self.logger.info("Vault created successfully")
            
            return True
        except Exception as e:
            self.logger.error(f"Error creating vault: {str(e)}")
            return False
    
    def unlock(self, password):
        """
        Unlock the vault with the given password
        
        Args:
            password (str): Master password for the vault
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Try to decrypt the vault
            self._load_encrypted(password)
            
            # Set state
            self.master_password = password
            self.is_unlocked = True
            
            # Log success
            self.logger.info("Vault unlocked successfully")
            
            return True
        except Exception as e:
            self.logger.error(f"Error unlocking vault: {str(e)}")
            return False
    
    def lock(self):
        """
        Lock the vault
        
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Clear state
            self.master_password = None
            self.is_unlocked = False
            
            # Log success
            self.logger.info("Vault locked successfully")
            
            return True
        except Exception as e:
            self.logger.error(f"Error locking vault: {str(e)}")
            return False
    
    def delete_vault(self):
        """
        Delete the vault completely
        
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Check if vault exists
            if not os.path.exists(self.vault_path):
                return False
            
            # Lock vault first
            self.lock()
            
            # Delete vault file
            os.remove(self.vault_path)
            
            # Delete any associated files (state files, etc.)
            state_file = os.path.join(self.vault_dir, "state.json")
            if os.path.exists(state_file):
                os.remove(state_file)
                
            master_file = os.path.join(self.vault_dir, "master.json")
            if os.path.exists(master_file):
                os.remove(master_file)
            
            self.logger.info("Vault deleted successfully")
            return True
        except Exception as e:
            self.logger.error(f"Error deleting vault: {str(e)}")
            return False
    
    def load_secrets(self):
        """
        Load secrets from the vault
        
        Returns:
            dict: Dictionary of secrets or None if vault is locked
        """
        if not self.is_unlocked or not self.master_password:
            return None
        
        try:
            return self._load_encrypted(self.master_password)
        except Exception as e:
            self.logger.error(f"Error loading secrets: {str(e)}")
            return None
    
    def save_secrets(self, secrets):
        """
        Save secrets to the vault
        
        Args:
            secrets (dict): Dictionary of secrets
            
        Returns:
            bool: True if successful, False otherwise
        """
        if not self.is_unlocked or not self.master_password:
            return False
        
        try:
            self._save_encrypted(secrets, self.master_password)
            self.logger.info("Secrets saved successfully")
            return True
        except Exception as e:
            self.logger.error(f"Error saving secrets: {str(e)}")
            return False
    
    def verify_password(self, password):
        """
        Verify if the given password is correct
        
        Args:
            password (str): Password to verify
            
        Returns:
            bool: True if password is correct, False otherwise
        """
        try:
            # Try to decrypt the vault
            self._load_encrypted(password)
            return True
        except Exception:
            return False
    
    def change_password(self, old_password, new_password):
        """
        Change the master password
        
        Args:
            old_password (str): Current master password
            new_password (str): New master password
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Validate new password
            if not new_password or len(new_password) < 8:
                self.logger.error("New password must be at least 8 characters long")
                return False
                
            # Verify old password
            if not self.verify_password(old_password):
                return False
            
            # Load secrets with old password
            secrets = self._load_encrypted(old_password)
            
            # Save with new password
            self._save_encrypted(secrets, new_password)
            
            # Update state
            self.master_password = new_password
            
            self.logger.info("Password changed successfully")
            return True
        except Exception as e:
            self.logger.error(f"Error changing password: {str(e)}")
            return False
    
    def _load_encrypted(self, password):
        """
        Load and decrypt the vault
        
        Args:
            password (str): Master password
            
        Returns:
            dict: Decrypted secrets
        """
        if not os.path.exists(self.vault_path):
            raise FileNotFoundError(f"Vault file not found: {self.vault_path}")
        
        # Read encrypted data
        with open(self.vault_path, 'rb') as f:
            encrypted_data = f.read()
        
        # Parse JSON
        try:
            data = json.loads(encrypted_data)
        except json.JSONDecodeError:
            # Legacy format (raw encrypted data)
            return self._decrypt_legacy(encrypted_data, password)
        
        # Extract encryption parameters
        salt = base64.b64decode(data['salt'])
        iv = base64.b64decode(data['iv'])
        tag = base64.b64decode(data['tag'])
        ciphertext = base64.b64decode(data['ciphertext'])
        
        # Derive key
        key = PBKDF2(password.encode(), salt, dkLen=32, count=100000)
        
        # Decrypt
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
        try:
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        except ValueError:
            raise ValueError("Incorrect password or corrupted data")
        
        # Parse JSON
        return json.loads(plaintext.decode('utf-8'))
    
    def _save_encrypted(self, secrets, password):
        """
        Encrypt and save the vault
        
        Args:
            secrets (dict): Secrets to encrypt
            password (str): Master password
        """
        # Convert to JSON
        plaintext = json.dumps(secrets).encode('utf-8')
        
        # Generate encryption parameters
        salt = get_random_bytes(16)
        iv = get_random_bytes(12)
        
        # Derive key
        key = PBKDF2(password.encode(), salt, dkLen=32, count=100000)
        
        # Encrypt
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        
        # Create JSON structure
        data = {
            'salt': base64.b64encode(salt).decode('utf-8'),
            'iv': base64.b64encode(iv).decode('utf-8'),
            'tag': base64.b64encode(tag).decode('utf-8'),
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8')
        }
        
        # Save to file (using atomic write pattern)
        temp_path = f"{self.vault_path}.tmp"
        with open(temp_path, 'w') as f:
            json.dump(data, f)
            f.flush()
            os.fsync(f.fileno())
        
        # Rename for atomic replacement
        if sys.platform == 'win32':
            # Windows requires special handling
            if os.path.exists(self.vault_path):
                os.replace(temp_path, self.vault_path)
            else:
                os.rename(temp_path, self.vault_path)
        else:
            # Unix systems can use atomic rename
            os.rename(temp_path, self.vault_path)
    
    def _decrypt_legacy(self, encrypted_data, password):
        """
        Decrypt legacy vault format
        
        Args:
            encrypted_data (bytes): Encrypted data
            password (str): Master password
            
        Returns:
            dict: Decrypted secrets
        """
        # Legacy format uses AES-CBC
        # Extract salt and IV (first 16 bytes each)
        salt = encrypted_data[:16]
        iv = encrypted_data[16:32]
        ciphertext = encrypted_data[32:]
        
        # Derive key
        key = PBKDF2(password.encode(), salt, dkLen=32, count=100000)
        
        # Decrypt
        cipher = AES.new(key, AES.MODE_CBC, iv)
        try:
            plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
        except ValueError:
            raise ValueError("Incorrect password or corrupted data")
        
        # Parse JSON
        return json.loads(plaintext.decode('utf-8')) 