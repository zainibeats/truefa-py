import os
import json
import base64
import secrets
import platform
import subprocess
from pathlib import Path
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from .secure_string import SecureString

class SecureStorage:
    """Handles secure storage of TOTP secrets and master password"""
    
    def __init__(self):
        self.salt = None
        self.key = None
        self.master_hash = None
        self._is_unlocked = False  # Private variable for state
        self.storage_path = os.path.expanduser('~/.truefa')
        self.exports_path = os.path.join(self.storage_path, 'exports')
        os.makedirs(self.storage_path, mode=0o700, exist_ok=True)
        os.makedirs(self.exports_path, mode=0o700, exist_ok=True)
        
        # Try to set permissions, but don't fail if we can't (e.g., mounted volume)
        try:
            os.chmod(self.storage_path, 0o700)
        except Exception:
            # Check if we can at least write to the directory
            test_file = os.path.join(self.storage_path, '.test')
            try:
                with open(test_file, 'w') as f:
                    f.write('test')
                os.remove(test_file)
            except Exception as e:
                raise Exception(f"Storage directory is not writable: {e}")
        
        # Load master password hash if it exists
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
        """Check if storage is unlocked"""
        return self._is_unlocked and self.key is not None

    def _unlock(self):
        """Set the unlocked state"""
        self._is_unlocked = True

    def _lock(self):
        """Reset the unlocked state"""
        self._is_unlocked = False
        self.key = None

    def has_master_password(self):
        """Check if a master password has been set"""
        return self.master_hash is not None

    def verify_master_password(self, password):
        """Verify the master password"""
        if not self.master_hash or not self.salt:
            return False
        try:
            kdf = Scrypt(
                salt=self.salt,
                length=32,
                n=2**14,
                r=8,
                p=1,
            )
            kdf.verify(password.encode(), self.master_hash)
            self.derive_key(password)  # Set up encryption key
            self._unlock()  # Set unlocked state
            return True
        except Exception:
            self._lock()  # Reset state on failure
            return False

    def set_master_password(self, password):
        """Set up the master password"""
        self.salt = secrets.token_bytes(16)
        kdf = Scrypt(
            salt=self.salt,
            length=32,
            n=2**14,
            r=8,
            p=1,
        )
        self.master_hash = kdf.derive(password.encode())
        
        # Save master password hash
        data = {
            'hash': base64.b64encode(self.master_hash).decode('utf-8'),
            'salt': base64.b64encode(self.salt).decode('utf-8')
        }
        with open(self.master_file, 'w') as f:
            json.dump(data, f)
        
        # Set up encryption key
        self.derive_key(password)
        self._unlock()  # Set unlocked state

    def derive_key(self, password):
        """Derive encryption key from password using Scrypt"""
        if not self.salt:
            self.salt = secrets.token_bytes(16)
        kdf = Scrypt(
            salt=self.salt,
            length=32,
            n=2**14,
            r=8,
            p=1,
        )
        self.key = kdf.derive(password.encode())

    def encrypt_secret(self, secret, name):
        """Encrypt a TOTP secret"""
        if not self.key:
            raise ValueError("No encryption key set")
        
        # Generate a random nonce
        nonce = secrets.token_bytes(12)
        
        # Create cipher
        aesgcm = AESGCM(self.key)
        
        # Encrypt the secret
        ciphertext = aesgcm.encrypt(
            nonce,
            secret.encode(),
            name.encode()  # Use name as associated data
        )
        
        # Combine salt, nonce, and ciphertext for storage
        return base64.b64encode(self.salt + nonce + ciphertext).decode('utf-8')

    def decrypt_secret(self, encrypted_data, name):
        """Decrypt a TOTP secret"""
        if not self.is_unlocked or not self.key:
            return None
            
        try:
            # Decode the combined data
            data = base64.b64decode(encrypted_data.encode('utf-8'))
            
            # Extract components
            salt = data[:16]
            nonce = data[16:28]
            ciphertext = data[28:]
            
            # Decrypt
            aesgcm = AESGCM(self.key)
            plaintext = aesgcm.decrypt(
                nonce,
                ciphertext,
                name.encode()  # Use name as associated data
            )
            
            return plaintext.decode('utf-8')
        except Exception:
            return None

    def load_secret(self, name):
        """Load a secret from storage."""
        if not self.is_unlocked:
            return None
        
        try:
            with open(os.path.join(self.storage_path, f"{name}.enc"), 'r') as f:
                return f.read()
        except Exception:
            return None

    def load_all_secrets(self):
        """Load all secrets from storage."""
        if not self.is_unlocked:
            return {}
        
        secrets = {}
        try:
            for filename in os.listdir(self.storage_path):
                if filename.endswith('.enc'):
                    name = filename[:-4]  # Remove .enc extension
                    secret = self.load_secret(name)
                    if secret:
                        secrets[name] = secret
        except Exception as e:
            print(f"Error loading secrets: {str(e)}")
            return {}
        
        return secrets

    def export_secrets(self, export_path, export_password):
        """Export secrets as a password-protected file."""
                
        if not self.is_unlocked:
            print("Storage must be unlocked to export secrets")
            return False
        
        if not export_path:
            print("Export cancelled.")
            return False
        
        # Clean up the export path
        export_path = export_path.strip('"').strip("'")
        
        # If it's not a full path, save to Downloads folder
        if not os.path.isabs(export_path):
            # Get Downloads folder path based on OS
            if platform.system() == 'Windows':
                downloads_dir = os.path.expanduser('~\\Downloads')
            else:
                downloads_dir = os.path.expanduser('~/Downloads')
            export_path = os.path.join(downloads_dir, export_path)
        
        # Ensure the export path has .gpg extension
        if not export_path.endswith('.gpg'):
            export_path += '.gpg'
        
        try:
            # Create a temporary file for the export
            temp_export = os.path.join(self.exports_path, '.temp_export')
            
            # Write secrets to temporary file
            secrets_count = 0
            with open(temp_export, 'w') as f:
                secrets = {}
                for filename in os.listdir(self.storage_path):
                    if filename.endswith('.enc'):
                        name = filename[:-4]  # Remove .enc extension
                        with open(os.path.join(self.storage_path, filename), 'r') as sf:
                            encrypted = sf.read()
                            decrypted = self.decrypt_secret(encrypted, name)
                            if decrypted:
                                secrets[name] = decrypted
                                secrets_count += 1
                json.dump(secrets, f, indent=4)
            
            # Use GPG for symmetric encryption only (no keys)
            try:
                # Ensure the exports directory exists with correct permissions
                os.makedirs(self.exports_path, mode=0o700, exist_ok=True)
                
                # Remove any existing temporary files
                if os.path.exists(temp_export):
                    os.remove(temp_export)
                
                # Write secrets to temporary file
                with open(temp_export, 'w') as f:
                    json.dump(secrets, f, indent=4)
                
                # Set up GPG environment
                gpg_env = os.environ.copy()
                gpg_env['GNUPGHOME'] = self.exports_path
                
                # Use process substitution to provide password
                result = subprocess.run([
                    'gpg',
                    '--batch',
                    '--yes',  # Automatically overwrite output file if it exists
                    '--passphrase-fd', '0',
                    '--symmetric',
                    '--cipher-algo', 'AES256',
                    '--output', export_path,
                    temp_export
                ], input=export_password.encode(), env=gpg_env, capture_output=True)
                
                # Clean up temporary files
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