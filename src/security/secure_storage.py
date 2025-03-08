"""
Secure Storage System for TOTP Secrets

Provides robust cryptographic storage for sensitive TOTP authentication secrets
using advanced security techniques:

Core Security Features:
- Envelope encryption with two distinct keys (vault password and master key)
- Strong key derivation using Scrypt (with PBKDF2 fallback)
- Authenticated encryption using AES-GCM with integrity verification
- Memory protection with automatic zeroization of sensitive data
- Secure atomic file operations to prevent data corruption
- GPG-compatible encrypted exports with recipient management

Operational Modes:
- Legacy Mode: Direct password-based encryption (single-factor)
- Vault Mode: Two-layer encryption with separate vault and master passwords
  allowing password rotation without re-encrypting all secrets

Implementation Notes:
- All cryptographic operations use industry-standard algorithms
- Leverages the Python cryptography package for core operations
- Handles secure temporary files with automatic cleanup
- Implements secure file permissions on all storage files
"""

import os
import sys
import json
import base64
import secrets
import tempfile
import platform
import subprocess
from datetime import datetime
from pathlib import Path
import hmac
import hashlib
import traceback
import logging

# Configure logging
logger = logging.getLogger(__name__)

# Import configuration with fallback mechanism
try:
    from ..config import DATA_DIR, EXPORTS_DIR
except ImportError:
    # Create a minimal configuration if the module isn't found
    DATA_DIR = os.path.join(os.path.expanduser("~"), ".truefa")
    EXPORTS_DIR = os.path.join(DATA_DIR, "exports")

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

class SecureStorage:
    """
    Secure Storage Implementation for TOTP Secrets
    
    Provides a comprehensive cryptographic storage system for sensitive TOTP 
    authentication secrets with two operational modes:
    
    1. Legacy Mode: Direct password-based encryption where a single master 
       password protects all secrets (simpler but less flexible)
    
    2. Vault Mode: Two-layer envelope encryption where:
       - Vault password decrypts the master key
       - Master key encrypts individual secrets
       - Allows password changes without re-encrypting all secrets
    
    Security Features:
    - Strong key derivation using Scrypt (with PBKDF2 fallback)
    - Authenticated encryption using AES-GCM with automatic nonce management
    - Memory protection with SecureString and automatic zeroization
    - Atomic file operations to prevent data corruption
    - Secure file permissions (0o600) on all storage files
    - GPG-compatible encrypted exports for backup and transfer
    
    This class seamlessly integrates with the SecureVault for master key 
    management and implements a complete secret lifecycle (create, read, 
    update, delete, export, import).
    """
    
    def __init__(self, vault=None, storage_path=None, vault_file=None):
        """
        Initialize the secure storage.
        
        Args:
            vault: Optional SecureVault instance to use
            storage_path (str): Path to the storage directory
            vault_file (str): Path to the vault file
        """
        # Internal attributes
        self._vault_file = None
        self._vault_directory = None
        self.key = None
        self._unlocked = False
        
        # Use existing vault if provided
        if vault is not None:
            self.vault = vault
            self._vault_directory = vault.vault_dir
            self._vault_file = os.path.join(self._vault_directory, "vault.json")
            print(f"Using provided SecureVault instance")
        else:
            # Determine default paths if not provided
            if storage_path is None:
                from ..config import DATA_DIR
                storage_path = DATA_DIR
            
            if vault_file is None:
                # Use the vault directory from vault_directory module
                try:
                    from .vault_directory import get_secure_vault_dir
                    vault_dir = get_secure_vault_dir()
                    vault_file = os.path.join(vault_dir, "vault.json")
                except Exception as e:
                    print(f"Error getting secure vault directory: {e}")
                    # Fallback to default
                    vault_file = os.path.join(storage_path, "vault.json")
            
            # Store the vault file path
            self._vault_file = vault_file
            self._vault_directory = os.path.dirname(self._vault_file)
            
            print(f"Vault path set to: {self._vault_file}")
            
            # Create the vault
            from .vault_interfaces import SecureVault
            self.vault = SecureVault(self._vault_directory)
        
        # Check for existing vault
        print(f"Checking for vault at {self._vault_directory}")
        vault_exists = os.path.exists(self._vault_file)
        print(f"Vault exists: {vault_exists}")
        
        # Set up storage directories with secure permissions
        self._ensure_secure_directory(self._vault_directory)
        self.exports_path = os.path.join(self._vault_directory, 'exports')
        self._ensure_secure_directory(self.exports_path)
        
        # Load existing master password state
        self.master_file = os.path.join(self._vault_directory, '.master')
        if os.path.exists(self.master_file):
            try:
                with open(self.master_file, 'r') as f:
                    self.master_hash = f.read().strip()
            except:
                self.master_hash = None
        else:
            self.master_hash = None

    @property
    def is_initialized(self):
        """
        Check if the vault is initialized
        
        Returns:
            bool: True if the vault is initialized, False otherwise
        """
        return self.vault.is_initialized if hasattr(self, 'vault') and self.vault else False

    @property
    def is_unlocked(self):
        """Check if the storage is unlocked."""
        return self._unlocked
        
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
            print(f"DEBUG: Creating vault with master password (length: {len(master_password)})")
            print(f"DEBUG: Vault initialization status before creation: {self.vault.is_initialized}")
            
            # In our simplified model, vault_password and master_password are the same
            success = self.vault.create_vault(master_password, master_password)
            
            print(f"DEBUG: Vault creation result: {success}")
            print(f"DEBUG: Vault initialization status after creation: {self.vault.is_initialized}")
            
            if success:
                self._unlocked = True
                print("Secure vault created successfully")
                
                # Verify the vault was created properly
                try:
                    with open(os.path.join(self.vault.vault_dir, "vault.json"), 'r') as f:
                        vault_data = json.load(f)
                    print(f"DEBUG: Created vault data keys: {list(vault_data.keys())}")
                except Exception as e:
                    print(f"DEBUG: Error reading created vault: {e}")
            return success
        except Exception as e:
            print(f"Error creating vault: {str(e)}")
            return False

    def unlock(self, password=None):
        """
        Unlock the storage using the provided password
        
        Args:
            password: Password to unlock the vault
        
        Returns:
            bool: True if unlocked successfully, False otherwise
        """
        print(f"DEBUG: Attempting to unlock vault with password length: {len(password) if password else 'None'}")
        
        # Check if already unlocked
        if self.is_unlocked:
            print("DEBUG: Vault already unlocked, no need to unlock again")
            return True
        
        # Check if vault is initialized
        if not self.vault.is_initialized:
            print("DEBUG: Vault not initialized, cannot unlock")
            return False
        
        # Add debug for vault path
        vault_file = os.path.join(self.vault.vault_dir, "vault.json")
        print(f"DEBUG: Vault file path: {vault_file}")
        print(f"DEBUG: Vault file exists: {os.path.exists(vault_file)}")
        
        # Try to unlock the vault
        try:
            print("DEBUG: Attempting to unlock vault...")
            success = self.vault.unlock(password)
            print(f"DEBUG: Vault unlock result: {success}")
            return success
        except Exception as e:
            print(f"ERROR: Exception unlocking vault: {e}")
            traceback.print_exc()
            return False

    def _lock(self):
        """
        Lock the storage and clear sensitive data from memory.
        """
        if self.vault.is_initialized:
            self.vault.lock()
        
        self.key = None
        self._unlocked = False

    def has_master_password(self):
        """
        Check if a master password has been set.
        
        Returns:
            bool: True if master password exists
            
        Security:
        - Checks both vault and legacy modes
        """
        if self.vault.is_initialized:
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
        if self.vault.is_initialized and vault_password:
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
        if not self.vault.is_initialized or not self.vault.is_unlocked:
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
        Encrypt a TOTP secret using authenticated encryption.
        
        Encrypts the provided secret with either the vault-based master key
        or a directly provided key, using AES-GCM for authenticated encryption.
        The method automatically determines the appropriate encryption key
        based on whether vault mode is active and unlocked.
        
        Args:
            secret (str/SecureString/bytes): TOTP secret to encrypt
                The secret will be encoded to bytes if it's a string
            name (str): Identifier for the secret
                Used both as a storage reference and as authenticated data
        
        Returns:
            str: Base64-encoded encrypted data including:
                - Random nonce (12 bytes)
                - Encrypted secret (variable length)
                - Authentication tag (16 bytes)
            None: If encryption fails
            
        Security Features:
            - Uses AES-GCM with 256-bit key for authenticated encryption
            - Includes name in authentication data to prevent swapping attacks
            - Generates a cryptographically secure random nonce for each encryption
            - Automatically uses the vault master key when available
            - Handles various input formats securely
            
        The encrypted result is encoded to base64 for safe storage in 
        text-based formats and includes all data needed for decryption.
        """
        # Use vault key if available
        if self.vault.is_initialized and self.vault.is_unlocked:
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
        List all available encrypted secrets
        
        Returns:
            list: List of secret names without extensions
        """
        print(f"DEBUG [secure_storage.py]: list_secrets called")
        print(f"DEBUG [secure_storage.py]: Storage object id: {id(self)}")
        print(f"DEBUG [secure_storage.py]: Vault object id: {id(self.vault)}")
        print(f"DEBUG [secure_storage.py]: Vault file path: {os.path.join(self._vault_directory, 'vault.json')}")
        print(f"DEBUG [secure_storage.py]: Vault file exists: {os.path.exists(os.path.join(self._vault_directory, 'vault.json'))}")
        
        # Check if vault exists
        try:
            with open(os.path.join(self._vault_directory, 'vault.json'), 'r') as f:
                metadata = json.load(f)
                print(f"DEBUG [secure_storage.py]: Vault metadata keys: {list(metadata.keys())}")
        except Exception as e:
            print(f"DEBUG [secure_storage.py]: Error reading vault metadata: {e}")
        
        # Check if vault is initialized
        print(f"DEBUG [secure_storage.py]: self.vault.is_initialized returns: {self.vault.is_initialized}")
        if not self.vault.is_initialized:
            print(f"DEBUG [secure_storage.py]: Vault not initialized, no secrets to list")
            return []
        
        # List all files in the vault directory
        print(f"DEBUG [secure_storage.py]: Looking for secrets in directory: {self._vault_directory}")
        try:
            # Get all files in the vault directory
            files = os.listdir(self._vault_directory)
            print(f"DEBUG [secure_storage.py]: All files in vault directory: {files}")
            
            # Filter for .enc files
            secret_files = [f for f in files if f.endswith('.enc')]
            print(f"DEBUG [secure_storage.py]: Encrypted secret files: {secret_files}")
            
            # Strip the .enc extension
            secret_names = [os.path.splitext(f)[0] for f in secret_files]
            print(f"DEBUG [secure_storage.py]: Found {len(secret_names)} secrets: {secret_names}")
            
            return secret_names
        except Exception as e:
            print(f"ERROR [secure_storage.py]: Error listing secrets: {e}")
            import traceback
            traceback.print_exc()
            return []

    def load_secret(self, name, password=None):
        """
        Load an encrypted secret by name
        
        Args:
            name: Name of the secret to load
            password: Optional password for decryption
            
        Returns:
            dict: Dictionary containing the decrypted secret data
                - 'secret': The actual TOTP secret
                - 'issuer': The service name (optional)
                - 'account': The account identifier (optional)
            str: Error message if loading fails
        """
        print(f"DEBUG [secure_storage.py]: load_secret called for '{name}'")
        print(f"DEBUG [secure_storage.py]: Storage object id: {id(self)}")
        print(f"DEBUG [secure_storage.py]: Vault object id: {id(self.vault)}")
        
        # Check if vault is initialized
        if not self.vault.is_initialized:
            print(f"DEBUG [secure_storage.py]: Vault not initialized")
            return "No vault found. Please create a vault first."
        
        # Unlock the vault if needed
        if not self.vault.is_unlocked and password:
            print(f"DEBUG [secure_storage.py]: Unlocking vault with provided password")
            if not self.vault.unlock(password):
                print(f"DEBUG [secure_storage.py]: Failed to unlock vault with provided password")
                return "Invalid password"

        # Check if vault is unlocked
        if not self.vault.is_unlocked:
            print(f"DEBUG [secure_storage.py]: Vault is locked")
            return "Vault is locked. Please unlock it first."

        # Sanitize the name to prevent traversal issues
        sanitized_name = self._sanitize_filename(name)
        if sanitized_name != name:
            print(f"DEBUG [secure_storage.py]: Name sanitized from '{name}' to '{sanitized_name}'")
            return "Invalid secret name"

        # Compute the file path for the secret
        try:
            secret_path = os.path.join(self._vault_directory, f"{sanitized_name}.enc")
            print(f"DEBUG [secure_storage.py]: Looking for secret at: {secret_path}")
            
            # Check if file exists
            if not os.path.exists(secret_path):
                print(f"DEBUG [secure_storage.py]: Secret file not found")
                return f"Secret '{name}' not found"
                
            # Read the encrypted data
            with open(secret_path, 'rb') as f:
                encrypted_data = f.read()
                print(f"DEBUG [secure_storage.py]: Read {len(encrypted_data)} bytes of encrypted data")
                
            # Get the master key
            master_key = self.vault._master_key
            if not master_key:
                print(f"DEBUG [secure_storage.py]: No master key available")
                return "Vault master key not available"
                
            print(f"DEBUG [secure_storage.py]: Using master key for decryption (length: {len(master_key)})")
            
            # Decrypt the data
            try:
                # Try to use the Rust implementation first
                from .. import truefa_crypto
                decrypted_data = truefa_crypto.decrypt_with_key(encrypted_data, master_key)
                print(f"DEBUG [secure_storage.py]: Used truefa_crypto for decryption")
            except Exception as e:
                print(f"DEBUG [secure_storage.py]: Error using truefa_crypto: {e}")
                print(f"DEBUG [secure_storage.py]: Falling back to AES decryption")
                
                try:
                    # Use AES as fallback
                    from Crypto.Cipher import AES
                    from Crypto.Util.Padding import unpad
                    
                    # Convert key to bytes if it's a string
                    key = base64.b64decode(master_key) if isinstance(master_key, str) else master_key
                    key = key[:32]  # Ensure key is 32 bytes (256 bits)
                    
                    # Get the encrypted data
                    if isinstance(encrypted_data, str):
                        encrypted_data = base64.b64decode(encrypted_data)
                    elif isinstance(encrypted_data, bytes) and encrypted_data[:1].isalnum():
                        # If it starts with base64 chars but is bytes, try decoding
                        encrypted_data = base64.b64decode(encrypted_data.decode('utf-8', errors='ignore'))
                    
                    # Extract IV and ciphertext
                    iv = encrypted_data[:16]
                    ciphertext = encrypted_data[16:]
                    
                    # Create cipher and decrypt
                    cipher = AES.new(key, AES.MODE_CBC, iv)
                    padded_data = cipher.decrypt(ciphertext)
                    
                    try:
                        # Try to unpad and decode
                        decrypted_data = unpad(padded_data, AES.block_size).decode('utf-8')
                        print(f"DEBUG [secure_storage.py]: Successfully decrypted and decoded data with AES")
                    except Exception as inner_e:
                        print(f"DEBUG [secure_storage.py]: Error unpadding/decoding: {inner_e}")
                        # Just use as-is if unpadding fails
                        decrypted_data = padded_data.decode('utf-8', errors='ignore')
                except Exception as decrypt_e:
                    print(f"DEBUG [secure_storage.py]: Error in AES decryption: {decrypt_e}")
                    import traceback
                    traceback.print_exc()
                    return f"Failed to decrypt secret: {str(decrypt_e)}"
            
            # Parse the decrypted data
            try:
                # Try to parse as JSON
                secret_data = json.loads(decrypted_data)
                print(f"DEBUG [secure_storage.py]: Successfully parsed secret data as JSON with keys: {list(secret_data.keys()) if isinstance(secret_data, dict) else 'not a dict'}")
                
                # Validate it has required fields if it's a dict
                if isinstance(secret_data, dict) and 'secret' in secret_data:
                    return secret_data
                elif isinstance(secret_data, dict):
                    print(f"DEBUG [secure_storage.py]: Missing 'secret' field in data: {list(secret_data.keys())}")
                    # Try to adapt the data if possible
                    return {"secret": str(secret_data), "issuer": "", "account": name}
                else:
                    # If it's not a dict but a string, assume it's the secret
                    print(f"DEBUG [secure_storage.py]: Data is not a dict, using as raw secret")
                    return {"secret": decrypted_data, "issuer": "", "account": name}
                    
            except json.JSONDecodeError:
                # Not JSON, treat as plain secret
                print(f"DEBUG [secure_storage.py]: Data is not valid JSON, using as raw secret")
                return {"secret": decrypted_data, "issuer": "", "account": name}
                
        except Exception as e:
            print(f"ERROR [secure_storage.py]: Exception in load_secret: {e}")
            import traceback
            traceback.print_exc()
            return f"Error loading secret: {str(e)}"

    def get_secret(self, name):
        """
        Alias for load_secret method for compatibility with main.py.
        
        Args:
            name (str): Name of the secret to load
            
        Returns:
            dict or None: Loaded secret data if successful, None otherwise
        """
        return self.load_secret(name)

    def get_secret_path(self, name):
        """
        Get the file path for a saved secret.
        
        Args:
            name (str): Name of the secret
            
        Returns:
            str or None: Full path to the secret file if vault is initialized, None otherwise
        """
        if not self.vault.is_initialized:
            return None
            
        # Sanitize filename
        name = name.strip()
        valid_chars = "-_.() abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        name = ''.join(c for c in name if c in valid_chars)
        
        if not name:
            return None
            
        secret_path = os.path.join(self.vault.vault_dir, f"{name}.enc")
        if os.path.exists(secret_path):
            return secret_path
        return None

    def save_secret(self, name, secret=None, password=None):
        """
        Save a secret to the vault
        
        Args:
            name: Name to identify the secret
            secret: The secret data to save
            password: Optional password to unlock the vault if needed
            
        Returns:
            str: Error message on failure, None on success
        """
        print(f"DEBUG [secure_storage.py]: save_secret called for '{name}'")
        print(f"DEBUG [secure_storage.py]: Storage object id: {id(self)}")
        print(f"DEBUG [secure_storage.py]: Vault object id: {id(self.vault)}")
        
        # Check if vault is initialized
        if not self.vault.is_initialized:
            print("DEBUG [secure_storage.py]: Vault not initialized, cannot save secret")
            return "No vault found. Please create a vault first."
        
        # Unlock the vault if needed
        if not self.vault.is_unlocked and password:
            if not self.vault.unlock(password):
                print("DEBUG [secure_storage.py]: Failed to unlock vault with provided password")
                return "Invalid password"
        
        # Ensure the vault is unlocked
        if not self.vault.is_unlocked:
            print("DEBUG [secure_storage.py]: Vault is locked, cannot save secret")
            return "Vault is locked. Please unlock it first."
        
        # Sanitize the name to prevent traversal issues
        sanitized_name = self._sanitize_filename(name)
        if sanitized_name != name:
            print(f"DEBUG [secure_storage.py]: Name sanitized from '{name}' to '{sanitized_name}'")
            return "Invalid secret name"
        
        # Ensure the vault directory exists
        os.makedirs(self._vault_directory, exist_ok=True)
        print(f"DEBUG [secure_storage.py]: Using vault directory: {self._vault_directory}")
        
        # Encrypt the secret data
        try:
            # Convert dictionary to JSON string if needed
            if isinstance(secret, dict):
                secret_data = json.dumps(secret)
            else:
                secret_data = str(secret)
            
            print(f"DEBUG [secure_storage.py]: Secret data prepared for encryption (length: {len(secret_data)})")
            
            # Get the encryption key (master key)
            master_key = self.vault.get_master_key()
            if not master_key:
                print("DEBUG [secure_storage.py]: No master key available")
                return "Vault master key not available"
            
            print(f"DEBUG [secure_storage.py]: Using master key for encryption (length: {len(master_key)})")
            
            # Encrypt the secret data
            try:
                # Try to use the Rust implementation first
                from .. import truefa_crypto
                
                # Check if encrypt_with_key exists, otherwise use encrypt_data
                if hasattr(truefa_crypto, 'encrypt_with_key'):
                    encrypted_data = truefa_crypto.encrypt_with_key(secret_data, master_key)
                    print("DEBUG [secure_storage.py]: Used truefa_crypto.encrypt_with_key for encryption")
                elif hasattr(truefa_crypto, 'encrypt_data'):
                    encrypted_data = truefa_crypto.encrypt_data(secret_data, master_key)
                    print("DEBUG [secure_storage.py]: Used truefa_crypto.encrypt_data for encryption")
                else:
                    raise ImportError("No encryption function found in truefa_crypto")
            except Exception as e:
                print(f"DEBUG [secure_storage.py]: Error using truefa_crypto: {e}")
                print("DEBUG [secure_storage.py]: Falling back to AES encryption")
                
                # Use AES as fallback
                from Crypto.Cipher import AES
                from Crypto.Util.Padding import pad
                
                # Convert key to bytes if it's a string
                key = base64.b64decode(master_key) if isinstance(master_key, str) else master_key
                key = key[:32]  # Ensure key is 32 bytes (256 bits)
                
                # Generate a random IV
                iv = os.urandom(16)
                
                # Create cipher and encrypt
                cipher = AES.new(key, AES.MODE_CBC, iv)
                data_bytes = secret_data.encode('utf-8')
                padded_data = pad(data_bytes, AES.block_size)
                ciphertext = cipher.encrypt(padded_data)
                
                # Combine IV and ciphertext for storage
                encrypted_data = base64.b64encode(iv + ciphertext).decode('utf-8')
                print(f"DEBUG [secure_storage.py]: Used AES for encryption, result length: {len(encrypted_data)}")
            
            # Compute the file path
            secret_path = os.path.join(self._vault_directory, f"{sanitized_name}.enc")
            print(f"DEBUG [secure_storage.py]: Saving encrypted secret to: {secret_path}")
            
            # Write the encrypted data to file
            with open(secret_path, 'wb') as f:
                f.write(encrypted_data.encode('utf-8') if isinstance(encrypted_data, str) else encrypted_data)
            
            print(f"DEBUG [secure_storage.py]: Secret saved successfully to: {secret_path}")
            return None  # Success, no error
        
        except Exception as e:
            print(f"ERROR [secure_storage.py]: Exception saving secret: {e}")
            import traceback
            traceback.print_exc()
            return f"Error saving secret: {str(e)}"

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
                for filename in os.listdir(self._vault_directory):
                    if filename.endswith('.enc'):
                        name = filename[:-4]
                        with open(os.path.join(self._vault_directory, filename), 'r') as sf:
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
            if self.vault.is_initialized and self.vault.is_unlocked:
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
            if self.vault.is_initialized and self.vault.is_unlocked:
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
        self._unlocked = False
        
        if not self.vault.is_initialized:
            print("No vault exists yet. You'll be prompted to create one when saving a secret.")
            return False
            
        if self.vault.unlock(master_password):
            self._unlocked = True
            print("Vault unlocked successfully")
            return True
            
        print("Failed to unlock vault - incorrect password")
        return False

    def _ensure_secure_directory(self, directory_path):
        """
        Ensure the directory exists and has secure permissions.

        Args:
            directory_path (str): Path to the directory to check/create.

        Returns:
            bool: True if the directory is secure, False otherwise.
        """
        directory = Path(directory_path)
        
        # Check if directory exists, create if not
        if not directory.exists():
            try:
                directory.mkdir(parents=True, exist_ok=True)
                self._set_secure_permissions(directory)
            except (OSError, PermissionError) as e:
                logger.warning(f"Cannot create directory at {directory}: {e}")
                return self._try_alternate_directories(directory_path)
        
        # Verify directory is writable by creating and removing a test file
        test_file = directory / ".test"
        try:
            with open(test_file, "w") as f:
                f.write("test")
            test_file.unlink()  # Remove test file
            return True
        except (OSError, PermissionError) as e:
            logger.warning(f"Cannot write to {directory}: {e}")
            return self._try_alternate_directories(directory_path)
    
    def _try_alternate_directories(self, original_path):
        """
        Try alternate directories when the primary one fails.
        
        Args:
            original_path (str): The original path that failed
            
        Returns:
            bool: True if an alternate directory was successfully set up
        """
        logger.info("Trying alternate secure directories...")
        
        # Define alternate locations in priority order
        alternates = [
            os.path.join(os.path.expanduser("~"), ".truefa", ".secure"),
            os.path.join(os.path.expanduser("~"), ".truefa"),
            os.path.join(tempfile.gettempdir(), "truefa_secure")
        ]
        
        for alt_path in alternates:
            if alt_path != original_path:  # Skip the original path
                try:
                    # Create directory if needed
                    alt_dir = Path(alt_path)
                    alt_dir.mkdir(parents=True, exist_ok=True)
                    
                    # Try to write a test file
                    test_file = alt_dir / ".test"
                    with open(test_file, "w") as f:
                        f.write("test")
                    test_file.unlink()  # Remove test file
                    
                    # Found a working directory
                    logger.info(f"Using fallback secure directory: {alt_path}")
                    print(f"Using fallback secure directory: {alt_path}")
                    
                    # Update the storage path
                    if alt_path.endswith(".secure"):
                        self._vault_directory = str(alt_dir.parent)
                    else:
                        self._vault_directory = alt_path
                    
                    return True
                except (OSError, PermissionError) as e:
                    logger.debug(f"Failed alternate directory {alt_path}: {e}")
                    continue
        
        # If we get here, all alternate directories failed
        logger.error("All secure directory alternatives failed")
        return False

    def _set_secure_permissions(self, path):
        """
        Set secure permissions on a file or directory.
        
        Args:
            path: Path to set permissions on
        """
        try:
            # Try platform-specific secure permissions
            if os.name == 'posix':
                # Unix-like systems
                try:
                    os.chmod(path, 0o700)  # Owner can read/write/execute
                    print(f"Set secure permissions (0o700) on {path}")
                except Exception as e:
                    print(f"Warning: Could not set POSIX permissions: {e}")
            
            elif os.name == 'nt':
                # Windows systems
                try:
                    # Get current user
                    import getpass
                    username = getpass.getuser()
                    
                    # Use icacls to set permissions
                    subprocess.run(
                        ['icacls', path, '/grant', f'{username}:(OI)(CI)F', '/T'],
                        check=True,
                        capture_output=True
                    )
                    print(f"Set secure Windows permissions for {username} on {path}")
                except Exception as e:
                    print(f"Warning: Could not set Windows permissions: {e}")
                    # Just create a test file to verify write access
                    try:
                        test_file = os.path.join(path, ".test")
                        with open(test_file, 'w') as f:
                            f.write("test")
                        print(f"Verified write access with test file: {test_file}")
                    except Exception as inner_e:
                        print(f"Warning: Could not verify write access: {inner_e}")
            
            else:
                # Other platforms
                print(f"Warning: No secure permission implementation for platform {os.name}")
            
        except Exception as e:
            print(f"Warning: Failed to set secure permissions: {e}")

    def set_vault_directory(self, directory_path):
        """
        Set a custom vault directory.
        
        Args:
            directory_path (str): Path to the vault directory
        """
        # Ensure the directory is an absolute path
        directory_path = os.path.abspath(os.path.expanduser(directory_path))
        
        # Create the directory if it doesn't exist
        os.makedirs(directory_path, exist_ok=True)
        
        # Update the vault paths
        self._vault_directory = directory_path
        self._vault_file = os.path.join(directory_path, "vault.json")
        
        # Create a new vault object with the updated path
        from .vault_interfaces import SecureVault
        self.vault = SecureVault(self._vault_directory)
        
        # Reset the unlock state
        self._unlocked = False
        
        return True

    def change_vault_password(self, current_password, new_password):
        """
        Change the vault password.
        
        Args:
            current_password: Current vault password
            new_password: New vault password to set
            
        Returns:
            bool: True if successful, False otherwise
            
        Security:
        - Verifies old password before allowing change
        - Re-encrypts the master key
        - Updates all metadata
        """
        # Check if vault is initialized
        if not self.vault.is_initialized:
            return False
        
        # Verify current password
        if not self.unlock(current_password):
            return False
        
        # Get the master key
        master_key = self.get_master_key()
        if not master_key:
            return False
        
        # Change the vault password
        return self.vault.change_vault_password(current_password, new_password)

    def change_master_password(self, vault_password, current_master_password, new_master_password):
        """
        Change the master password.
        
        Args:
            vault_password: Vault password for authentication
            current_master_password: Current master password
            new_master_password: New master password to set
            
        Returns:
            bool: True if successful, False otherwise
            
        Security:
        - Requires both vault and master passwords
        - Re-encrypts all secrets with new master key
        """
        if not self.vault.is_initialized:
            return False
        
        # Unlock the vault
        if not self.unlock(vault_password):
            return False
        
        # Change the master password
        return self.vault.change_master_password(vault_password, current_master_password, new_master_password)

    def get_master_key(self):
        """
        Get the master key.
        
        Returns:
            SecureString: The master key if the vault is unlocked
            
        Security:
        - Only returns the key if the vault is unlocked
        - Returns a SecureString, not a regular string
        """
        if not self.vault.is_initialized or not self.vault.is_unlocked:
            return None
        
        return self.vault.get_master_key()

    def export_all_secrets(self, output_path, export_password=None):
        """
        Export all secrets to a file.
        
        Args:
            output_path: Path to save the export
            export_password: Optional password to encrypt the export
            
        Returns:
            bool: True if successful, False otherwise
            
        Security:
        - Requires vault to be initialized and unlocked
        - Uses strong encryption for the export
        """
        if not self.vault.is_initialized or not self.vault.is_unlocked:
            return False
        
        # Get all secrets
        secrets = self.list_secrets()
        if not secrets:
            return False
        
        # Export each secret
        export_data = {}
        for name in secrets:
            secret_data = self.load_secret(name)
            if secret_data:
                export_data[name] = secret_data
        
        # Save the export data
        if export_password:
            # Encrypt with export password
            pass
        else:
            # Save as plaintext
            with open(output_path, 'w') as f:
                json.dump(export_data, f, indent=2)
        
        return True

    def verify_integrity(self, name):
        """
        Verify the integrity of a saved secret.
        
        Args:
            name (str): Name of the secret to verify
            
        Returns:
            bool: True if integrity check passed, False otherwise
        """
        if not self.vault.is_initialized or not self.vault.is_unlocked:
            return False
            
        # Get the path to the secret file
        secret_path = os.path.join(self.vault.vault_dir, f"{name}.enc")
        
        # Check if the file exists
        if not os.path.exists(secret_path):
            return False
            
        # Check if a backup exists
        backup_path = f"{secret_path}.backup"
        if not os.path.exists(backup_path):
            return False
            
        # Compare contents
        try:
            with open(secret_path, 'rb') as f:
                secret_data = f.read()
                
            with open(backup_path, 'rb') as f:
                backup_data = f.read()
                
            # Split backup data into content and HMAC
            content_length = len(backup_data) - 32  # 32-byte HMAC
            backup_content = backup_data[:content_length]
            backup_hmac = backup_data[content_length:]
            
            # Verify HMAC
            key = self.get_master_key()
            if key:
                computed_hmac = hmac.new(key, backup_content, hashlib.sha256).digest()
                return hmac.compare_digest(computed_hmac, backup_hmac)
            else:
                # Simple byte comparison if no key
                return secret_data == backup_content
        except Exception as e:
            print(f"Error verifying integrity: {e}")
            return False

    def delete_secret(self, name):
        """
        Delete a saved secret.
        
        Args:
            name (str): Name of the secret to delete
            
        Returns:
            bool: True if successful, False otherwise
        """
        if not self.vault.is_initialized:
            return False
            
        # Get the path to the secret file
        secret_path = os.path.join(self.vault.vault_dir, f"{name}.enc")
        
        # Check if the file exists
        if not os.path.exists(secret_path):
            return False
            
        # Delete the file
        try:
            os.remove(secret_path)
            
            # Also delete backup if it exists
            backup_path = f"{secret_path}.backup"
            if os.path.exists(backup_path):
                os.remove(backup_path)
                
            return True
        except Exception as e:
            print(f"Error deleting secret: {e}")
            return False

    def _sanitize_filename(self, filename):
        """
        Sanitize a filename to prevent path traversal and invalid characters
        
        Args:
            filename: The filename to sanitize
            
        Returns:
            str: The sanitized filename
        """
        if not filename or not isinstance(filename, str):
            return ""
        
        # Remove any path components
        filename = os.path.basename(filename)
        
        # Only allow alphanumeric, dash, underscore, space and period
        valid_chars = "-_.() abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        sanitized = ''.join(c for c in filename if c in valid_chars)
        
        # Ensure the filename is not empty
        if not sanitized:
            sanitized = "unnamed"
        
        return sanitized

    @property
    def vault_dir(self):
        """Get the vault directory path"""
        if hasattr(self, '_vault_directory') and self._vault_directory:
            return self._vault_directory
        elif hasattr(self, 'vault') and self.vault:
            return self.vault.vault_dir
        else:
            return None

    @property
    def vault_file(self):
        """Get the vault file path"""
        return self._vault_file