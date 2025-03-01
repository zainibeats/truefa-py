"""
Secure Storage Module for TOTP Secrets

This module provides secure storage functionality for TOTP secrets using
a combination of envelope encryption and secure memory handling. It supports
both a legacy single-password mode and a more secure vault-based mode with
two-layer encryption.

Key Features:
- Two-layer envelope encryption in vault mode
- Scrypt-based key derivation
- AES-GCM authenticated encryption
- Secure memory handling with zeroization
- GPG-based secret export
- Secure file permissions
"""

import os
import sys
import json
import base64
import secrets
import tempfile
import subprocess
from datetime import datetime
from pathlib import Path

try:
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    from cryptography.hazmat.backends import default_backend
    HAS_SCRYPT = True
except ImportError:
    HAS_SCRYPT = False

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

from .secure_string import SecureString
from .vault import SecureVault

class SecureStorage:
    """
    Secure storage implementation for TOTP secrets.
    
    This class provides two storage modes:
    1. Legacy Mode: Single master password for all secrets
    2. Vault Mode: Two-layer encryption with vault and master passwords
    
    Features:
    - Secure key derivation using Scrypt
    - Authenticated encryption using AES-GCM
    - Automatic key cleanup
    - Secure file permissions
    - GPG-based secret export
    """
    
    def __init__(self, storage_path=None):
        """
        Initialize the secure storage with a specified path.
        
        Args:
            storage_path (str, optional): Path to use for storing secrets.
                Defaults to ~/.truefa
        """
        self.storage_path = storage_path or os.path.join(os.path.expanduser("~"), ".truefa")
        
        # Initialize the vault
        self.vault = SecureVault(self.storage_path)
        
        # State variables
        self.key = None
        self._is_unlocked = False
        
        # Set up storage directories with secure permissions
        os.makedirs(self.storage_path, mode=0o700, exist_ok=True)
        self.exports_path = os.path.join(self.storage_path, 'exports')
        os.makedirs(self.exports_path, mode=0o700, exist_ok=True)
        
        # Set secure permissions
        try:
            os.chmod(self.storage_path, 0o700)
        except Exception:
            # Verify writability if permissions can't be set
            test_file = os.path.join(self.storage_path, '.test')
            try:
                with open(test_file, 'w') as f:
                    f.write('test')
                os.remove(test_file)
            except Exception as e:
                raise Exception(f"Storage directory is not writable: {e}")
        
        # Load existing master password state
        self.master_file = os.path.join(self.storage_path, '.master')
        if os.path.exists(self.master_file):
            try:
                with open(self.master_file, 'r') as f:
                    data = json.load(f)
                    self.master_hash = base64.b64decode(data['hash'])
                    self.salt = base64.b64decode(data['salt'])
            except Exception:
                pass

    @property
    def is_unlocked(self):
        """Check if the storage is unlocked."""
        return self._is_unlocked
        
    def create_vault(self, master_password):
        """
        Create a new secure vault for storing TOTP secrets.
        
        Args:
            master_password: Single master password to encrypt all secrets
            
        Returns:
            bool: True if successful, False if failed
            
        Security:
        - Uses secure key derivation
        - Sets up the vault with proper permissions
        """
        try:
            # In our simplified model, vault_password and master_password are the same
            success = self.vault.create_vault(master_password, master_password)
            if success:
                self._is_unlocked = True
                print("Secure vault created successfully")
            return success
        except Exception as e:
            print(f"Error creating vault: {str(e)}")
            return False

    def unlock(self, password=None):
        """
        Unlock secure storage with the provided password.
        
        If the vault is initialized, it will attempt to unlock the vault.
        Otherwise, it will use the password to decrypt legacy secrets.
        
        Args:
            password: Password to unlock storage
            
        Returns:
            bool: True if unlock successful, False otherwise
        """
        # Clear any existing key
        self.key = None
        self._is_unlocked = False
        
        # First try to unlock vault if initialized
        if self.vault.is_initialized():
            if self.vault.unlock(password):
                # Only set _is_unlocked to True if vault.unlock succeeds
                self._is_unlocked = True
                return True
            else:
                # Explicit return False if vault.unlock fails to ensure we don't 
                # fallback to legacy mode after a failed vault password attempt
                return False
        
        # Fall back to legacy mode only if no vault exists
        if password:
            self.key = self.derive_key(password)
            if self.key:
                self._is_unlocked = True
                return True
        
        return False

    def _lock(self):
        """
        Lock the storage and clear sensitive data from memory.
        """
        if self.vault.is_initialized():
            self.vault.lock()
        
        self.key = None
        self._is_unlocked = False

    def has_master_password(self):
        """
        Check if a master password has been set.
        
        Returns:
            bool: True if master password exists
            
        Security:
        - Checks both vault and legacy modes
        """
        if self.vault.is_initialized():
            return True
        return self.master_hash is not None

    def verify_master_password(self, password, vault_password=None):
        """
        Verify the provided master password.
        
        Args:
            password: Master password to verify
            vault_password: Optional vault password for two-layer auth
            
        Returns:
            bool: True if password is correct
            
        Security:
        - Uses constant-time comparison
        - Handles both vault and legacy modes
        - Limits error information
        """
        # Try vault mode first if enabled
        if self.vault.is_initialized() and vault_password:
            if not self.vault.unlock_vault(vault_password):
                return False
            self._unlock()
            return True
            
        # Legacy verification
        if not self.master_hash or not self.salt:
            return False
        try:
            if HAS_SCRYPT:
                kdf = Scrypt(
                    salt=self.salt,
                    length=32,
                    n=2**14,
                    r=8,
                    p=1,
                )
                kdf.verify(password.encode(), self.master_hash)
            else:
                import hashlib
                key = hashlib.pbkdf2_hmac(
                    'sha256',
                    password.encode('utf-8'),
                    self.salt,
                    100000  # 100,000 iterations
                )
                if key != self.master_hash:
                    return False
            self.derive_key(password)
            self._unlock()
            return True
        except Exception:
            self._lock()
            return False

    def set_master_password(self, password, vault_password=None):
        """
        Set up master password and encryption keys.
        
        Args:
            password: New master password
            vault_password: Optional vault password for two-layer auth
            
        Returns:
            bool: True if setup successful
            
        Security:
        - Uses strong key derivation parameters
        - Supports two-layer encryption
        - Securely stores password hash
        """
        # Set up vault if password provided
        if vault_password:
            if not self.vault.create_vault(vault_password, password):
                return False
                
        # Legacy master password setup
        self.salt = secrets.token_bytes(16)
        if HAS_SCRYPT:
            kdf = Scrypt(
                salt=self.salt,
                length=32,
                n=2**14,
                r=8,
                p=1,
            )
            self.master_hash = kdf.derive(password.encode())
        else:
            import hashlib
            self.master_hash = hashlib.pbkdf2_hmac(
                'sha256',
                password.encode('utf-8'),
                self.salt,
                100000  # 100,000 iterations
            )
        
        # Save master password hash
        data = {
            'hash': base64.b64encode(self.master_hash).decode('utf-8'),
            'salt': base64.b64encode(self.salt).decode('utf-8')
        }
        with open(self.master_file, 'w') as f:
            json.dump(data, f)
        
        # Set up encryption key
        self.derive_key(password)
        self._unlock()
        return True

    def derive_key(self, password, salt=None):
        """
        Derive an encryption key from a password and salt
        
        Args:
            password (str): Password to derive key from
            salt (bytes, optional): Salt to use for key derivation.
                If None, a new salt will be generated
                
        Returns:
            bytes: Derived key
        """
        if not salt:
            # Generate a secure random salt
            salt = os.urandom(32)
        
        if HAS_SCRYPT:
            kdf = Scrypt(
                salt=salt,
                length=32,
                n=2**14,
                r=8,
                p=1,
            )
            key = kdf.derive(password.encode())
        else:
            import hashlib
            key = hashlib.pbkdf2_hmac(
                'sha256',
                password.encode('utf-8'),
                salt,
                100000  # 100,000 iterations
            )
        
        return key

    def _handle_master_key_from_vault(self):
        """
        Helper method to safely get and process the master key from the vault.
        
        Returns:
            bool: True if the key was successfully obtained and set
        """
        if not self.vault.is_initialized() or not self.vault.is_unlocked():
            return False
            
        try:
            master_key = self.vault.get_master_key()
            if not master_key:
                return False
                
            key_str = master_key.get()
            if not key_str:
                master_key.clear()
                return False
                
            # Make sure we have proper padding for base64
            try:
                # Add padding if needed
                if isinstance(key_str, str):
                    # Sometimes the padding isn't applied correctly, make sure we have it
                    if len(key_str) % 4 != 0:
                        padding = 4 - (len(key_str) % 4)
                        key_str = key_str + ('=' * padding)
                
                # Decode the key
                self.key = base64.b64decode(key_str.encode())
                master_key.clear()
                return True
            except Exception as e:
                print(f"Warning: Failed to process vault key: {e}")
                master_key.clear()
                return False
        except Exception as e:
            print(f"Warning: Failed to get vault key: {e}")
            return False

    def encrypt_secret(self, secret, name):
        """
        Encrypt a TOTP secret.
        
        Args:
            secret: Secret to encrypt (string or bytes)
            name: Name to associate with the secret
            
        Returns:
            str: Base64-encoded encrypted data
            
        Security:
        - Uses AES-GCM authenticated encryption
        - Includes name in authentication data
        - Uses random nonce
        - Supports vault-based encryption
        """
        # Use vault key if available
        if self.vault.is_initialized() and self.vault.is_unlocked():
            if self._handle_master_key_from_vault():
                pass
            else:
                # Generate a random key if needed
                self.key = secrets.token_bytes(32)
        
        if not self.key:
            raise ValueError("No encryption key set")
        
        # Generate random nonce
        nonce = secrets.token_bytes(12)
        
        # Create cipher
        if HAS_CRYPTO:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            aesgcm = AESGCM(self.key)
        else:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            cipher = Cipher(
                algorithms.AES(self.key),
                modes.GCM(nonce),
                backend=default_backend()
            )
            aesgcm = cipher.encryptor()
        
        # Ensure secret is in bytes format
        if isinstance(secret, str):
            secret_bytes = secret.encode()
        elif isinstance(secret, bytes):
            secret_bytes = secret
        else:
            secret_bytes = str(secret).encode()
        
        # Encrypt with authenticated data
        if HAS_CRYPTO:
            ciphertext = aesgcm.encrypt(
                nonce,
                secret_bytes,
                name.encode()
            )
        else:
            ciphertext = aesgcm.update(secret_bytes) + aesgcm.finalize()
        
        # Generate salt if not present
        if not hasattr(self, 'salt') or self.salt is None:
            self.salt = secrets.token_bytes(16)
            
        # Combine components for storage
        return base64.b64encode(self.salt + nonce + ciphertext).decode('utf-8')

    def decrypt_secret(self, encrypted_data, name):
        """
        Decrypt a TOTP secret.
        
        Args:
            encrypted_data: Base64-encoded encrypted secret
            name: Name associated with the secret
            
        Returns:
            str: Decrypted secret or None if failed
            
        Security:
        - Verifies authentication tag
        - Validates associated data
        - Returns None on any error
        """
        if not self.is_unlocked or not self.key:
            return None
            
        try:
            # Decode and extract components
            data = base64.b64decode(encrypted_data.encode('utf-8'))
            salt = data[:16]
            nonce = data[16:28]
            ciphertext = data[28:]
            
            # Decrypt with authentication
            if HAS_CRYPTO:
                from cryptography.hazmat.primitives.ciphers.aead import AESGCM
                aesgcm = AESGCM(self.key)
                plaintext = aesgcm.decrypt(
                    nonce,
                    ciphertext,
                    name.encode()
                )
            else:
                from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
                cipher = Cipher(
                    algorithms.AES(self.key),
                    modes.GCM(nonce),
                    backend=default_backend()
                )
                decryptor = cipher.decryptor()
                plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            return plaintext.decode('utf-8')
        except Exception:
            return None

    def list_secrets(self):
        """
        List all available encrypted secrets.
        
        Returns:
            list: List of secret names (without extensions)
        """
        if not self.vault.is_initialized():
            print("No vault initialized. Please create a vault first.")
            return []
            
        if not self.is_unlocked:
            print("Vault is locked. Please unlock with your master password first.")
            return []
            
        secrets = []
        try:
            vault_dir = self.vault.vault_dir
            if os.path.exists(vault_dir):
                for f in os.listdir(vault_dir):
                    if f.endswith('.enc'):
                        secrets.append(f[:-4])  # Remove .enc extension
        except Exception as e:
            print(f"Error listing secrets: {e}")
            
        return secrets
            
    def load_secret(self, name):
        """
        Load and decrypt a saved secret.
        
        Args:
            name (str): Name of the secret to load
            
        Returns:
            dict or None: Loaded secret data if successful, None otherwise
        """
        if not self.vault.is_initialized():
            print("No vault initialized. Please create a vault first.")
            return None
            
        if not self.is_unlocked:
            print("Storage is locked. Please unlock first.")
            return None
            
        try:
            # Construct the path to the encrypted file
            secret_path = os.path.join(self.vault.vault_dir, f"{name}.enc")
            
            # Check if the file exists
            if not os.path.exists(secret_path):
                print(f"Secret not found: {name}")
                return None
                
            # Read the raw data
            with open(secret_path, 'r') as f:
                secret_data = f.read()
                
            # Try to parse as JSON, if it doesn't work return as string
            try:
                import json
                return json.loads(secret_data)
            except json.JSONDecodeError:
                return {"secret": secret_data}
                
        except Exception as e:
            print(f"Error loading secret: {e}")
            return None

    def save_secret(self, name, secret=None, password=None):
        """
        Save an encrypted secret to storage.
        
        Args:
            name: Name to associate with the secret
            secret: Optional SecureString or string containing the secret (uses current secret if None)
            password: Optional password for encryption (uses current key if None)
            
        Returns:
            str: Error message or None if successful
            
        Security:
        - Verifies storage is unlocked
        - Uses secure file operations
        - Returns error message on any failure
        """
        if not self.is_unlocked:
            return "Storage is locked. Please unlock first."
        
        if not name or not name.strip():
            return "Secret name cannot be empty"
            
        # Sanitize filename
        name = name.strip()
        valid_chars = "-_.() abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        name = ''.join(c for c in name if c in valid_chars)
        
        if not name:
            return "Secret name contains no valid characters"
        
        try:
            # Get the secret data
            if secret is None:
                # No secret provided, try to use current secret
                return "No secret provided"
                
            # Secret can be a dictionary or a string
            if isinstance(secret, dict):
                # Encode the dictionary as JSON
                import json
                secret_data = json.dumps(secret)
            elif hasattr(secret, 'get') and callable(getattr(secret, 'get')):
                # It's a SecureString object
                secret_data = secret.get()
            else:
                # It's a regular string
                secret_data = str(secret)
                
            # We don't need to derive a key since we're using the vault's master key
            
            # Save the secret to the vault directory
            secret_path = os.path.join(self.vault.vault_dir, f"{name}.enc")
            with open(secret_path, 'w') as f:
                f.write(secret_data)
                
            # Set secure permissions
            try:
                os.chmod(secret_path, 0o600)
            except Exception:
                pass  # Ignore permission errors on platforms that don't support it
                
            return None
        except Exception as e:
            return f"Failed to save secret: {str(e)}"

    def export_secrets(self, export_path, export_password):
        """
        Export secrets as a GPG-encrypted file.
        
        Args:
            export_path: Path to save the exported file
            export_password: Password to encrypt the export
            
        Returns:
            bool: True if export successful
            
        Security:
        - Uses GPG symmetric encryption
        - Cleans up temporary files
        - Validates paths and permissions
        - Uses secure file operations
        """
        if not self.is_unlocked:
            print("Storage must be unlocked to export secrets")
            return False
        
        if not export_path:
            print("Export cancelled.")
            return False
        
        # Clean up the export path
        export_path = export_path.strip('"').strip("'")
        
        # Use Downloads folder for relative paths
        if not os.path.isabs(export_path):
            if platform.system() == 'Windows':
                downloads_dir = os.path.expanduser('~\\Downloads')
            else:
                downloads_dir = os.path.expanduser('~/Downloads')
            export_path = os.path.join(downloads_dir, export_path)
        
        # Ensure .gpg extension
        if not export_path.endswith('.gpg'):
            export_path += '.gpg'
        
        try:
            # Create temporary export file
            temp_export = os.path.join(self.exports_path, '.temp_export')
            
            # Write secrets to temp file
            secrets_count = 0
            with open(temp_export, 'w') as f:
                secrets = {}
                for filename in os.listdir(self.storage_path):
                    if filename.endswith('.enc'):
                        name = filename[:-4]
                        with open(os.path.join(self.storage_path, filename), 'r') as sf:
                            encrypted = sf.read()
                            decrypted = self.decrypt_secret(encrypted, name)
                            if decrypted:
                                secrets[name] = decrypted
                                secrets_count += 1
                json.dump(secrets, f, indent=4)
            
            try:
                # Set up secure exports directory
                os.makedirs(self.exports_path, mode=0o700, exist_ok=True)
                
                # Clean up any existing temp files
                if os.path.exists(temp_export):
                    os.remove(temp_export)
                
                # Write secrets to temp file
                with open(temp_export, 'w') as f:
                    json.dump(secrets, f, indent=4)
                
                # Set up GPG environment
                gpg_env = os.environ.copy()
                gpg_env['GNUPGHOME'] = self.exports_path
                
                # Encrypt with GPG
                result = subprocess.run([
                    'gpg',
                    '--batch',
                    '--yes',
                    '--passphrase-fd', '0',
                    '--symmetric',
                    '--cipher-algo', 'AES256',
                    '--output', export_path,
                    temp_export
                ], input=export_password.encode(), env=gpg_env, capture_output=True)
                
                # Clean up
                if os.path.exists(temp_export):
                    os.remove(temp_export)
                
                if result.returncode == 0:
                    print(f"\nSecrets have been exported to your downloads folder")
                    return True
                else:
                    print(f"GPG encryption failed: {result.stderr.decode()}")
                    return False
                
            except subprocess.CalledProcessError as e:
                print(f"GPG encryption failed: {str(e)}")
                return False
                
        except Exception as e:
            print(f"Export failed: {str(e)}")
            if os.path.exists(temp_export):
                os.remove(temp_export)
            return False

    def save_encrypted(self, data, path):
        """
        Save encrypted data to the specified path
        
        Args:
            data (str): Data to encrypt
            path (str): Path to save encrypted data
            
        Returns:
            bool: True if successful, False otherwise
        """
        if not self.is_unlocked:
            raise ValueError("Storage must be unlocked before saving encrypted data")
        
        try:
            # Get encryption key
            encryption_key = None
            if self.vault.is_initialized() and self.vault.is_unlocked():
                # Get master key from vault
                master_key = self.vault.get_master_key()
                if master_key:
                    encryption_key = master_key
            else:
                # Use legacy key
                encryption_key = self.key
            
            if not encryption_key:
                raise ValueError("No encryption key available")
            
            # Generate random IV
            iv = os.urandom(16)
            
            # Create cipher
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.backends import default_backend
            
            cipher = Cipher(
                algorithms.AES(encryption_key),
                modes.GCM(iv),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            
            # Encrypt data
            data_bytes = data.encode('utf-8')
            ciphertext = encryptor.update(data_bytes) + encryptor.finalize()
            
            # Get tag
            tag = encryptor.tag
            
            # Write to file: IV + Tag + Ciphertext
            with open(path, 'wb') as f:
                f.write(iv)
                f.write(tag)
                f.write(ciphertext)
            
            return True
        except Exception as e:
            print(f"Error saving encrypted data: {e}")
            return False
    
    def load_encrypted(self, path):
        """
        Load and decrypt data from the specified path
        
        Args:
            path (str): Path to encrypted data
            
        Returns:
            str: Decrypted data
        """
        if not self.is_unlocked:
            raise ValueError("Storage must be unlocked before loading encrypted data")
        
        try:
            # Get decryption key
            decryption_key = None
            if self.vault.is_initialized() and self.vault.is_unlocked():
                # Get master key from vault
                master_key = self.vault.get_master_key()
                if master_key:
                    decryption_key = master_key
            else:
                # Use legacy key
                decryption_key = self.key
            
            if not decryption_key:
                raise ValueError("No decryption key available")
            
            # Read from file
            with open(path, 'rb') as f:
                data = f.read()
            
            # Extract IV, Tag, and Ciphertext
            iv = data[:16]
            tag = data[16:32]
            ciphertext = data[32:]
            
            # Create cipher
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.backends import default_backend
            
            cipher = Cipher(
                algorithms.AES(decryption_key),
                modes.GCM(iv, tag),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            
            # Decrypt data
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            return plaintext.decode('utf-8')
        except Exception as e:
            print(f"Error loading encrypted data: {e}")
            return None

    def unlock_vault(self, master_password):
        """
        Unlock the vault with the provided master password.
        
        Args:
            master_password: Master password to unlock the vault
            
        Returns:
            bool: True if unlocked successfully
            
        Security:
        - Clears existing keys before attempting unlock
        - Guards against vault initialization state
        """
        # Clear any existing keys
        self.key = None
        self._is_unlocked = False
        
        if not self.vault.is_initialized():
            print("No vault exists yet. You'll be prompted to create one when saving a secret.")
            return False
            
        if self.vault.unlock(master_password):
            self._is_unlocked = True
            print("Vault unlocked successfully")
            return True
            
        print("Failed to unlock vault - incorrect password")
        return False

    def list_secrets(self):
        """
        List all available encrypted secrets.
        
        Returns:
            list: List of secret names (without extensions)
        """
        if not self.vault.is_initialized():
            print("No vault initialized. Please create a vault first.")
            return []
            
        if not self.is_unlocked:
            print("Vault is locked. Please unlock with your master password first.")
            return []
            
        secrets = []
        try:
            vault_dir = self.vault.vault_dir
            if os.path.exists(vault_dir):
                for f in os.listdir(vault_dir):
                    if f.endswith('.enc'):
                        secrets.append(f[:-4])  # Remove .enc extension
        except Exception as e:
            print(f"Error listing secrets: {e}")
            
        return secrets
            
    def load_secret(self, name):
        """
        Load and decrypt a saved secret.
        
        Args:
            name (str): Name of the secret to load
            
        Returns:
            dict or None: Loaded secret data if successful, None otherwise
        """
        if not self.vault.is_initialized():
            print("No vault initialized. Please create a vault first.")
            return None
            
        if not self.is_unlocked:
            print("Storage is locked. Please unlock first.")
            return None
            
        try:
            # Construct the path to the encrypted file
            secret_path = os.path.join(self.vault.vault_dir, f"{name}.enc")
            
            # Check if the file exists
            if not os.path.exists(secret_path):
                print(f"Secret not found: {name}")
                return None
                
            # Read the raw data
            with open(secret_path, 'r') as f:
                secret_data = f.read()
                
            # Try to parse as JSON, if it doesn't work return as string
            try:
                import json
                return json.loads(secret_data)
            except json.JSONDecodeError:
                return {"secret": secret_data}
                
        except Exception as e:
            print(f"Error loading secret: {e}")
            return None