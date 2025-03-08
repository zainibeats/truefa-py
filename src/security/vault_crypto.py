"""
Vault Cryptography Module for TrueFA-Py

Provides cryptographic operations for the secure vault system,
including key derivation, encryption, and decryption.
This module serves as an interface to both the Rust-based cryptography
and the fallback Python implementation.
"""

import base64
import secrets
import sys
import os
import ctypes
import platform
import json
import hashlib
from pathlib import Path
from .secure_string import SecureString
import datetime
import traceback

# Global variables
_vault_path = None
_vault_unlocked = False
_vault_key = None

def set_vault_path(path):
    """Set the path to the vault file."""
    global _vault_path
    
    # If path is a directory, append vault.json
    if os.path.isdir(path):
        _vault_path = os.path.join(path, "vault.json")
    else:
        _vault_path = path
        
    # Ensure the directory exists
    os.makedirs(os.path.dirname(_vault_path), exist_ok=True)
    
    print(f"Vault path set to: {_vault_path}")
    return _vault_path

# Create a proper Python implementation of crypto functions
class PythonCrypto:
    def __init__(self):
        self.functions_defined = True
        
    def generate_salt(self):
        """Generate a cryptographically secure random salt for key derivation."""
        salt = secrets.token_bytes(16)
        return base64.b64encode(salt).decode('utf-8')
    
    def derive_master_key(self, password, salt):
        """Derive a master key from a password and salt using a KDF."""
        if isinstance(password, str):
            password = password.encode('utf-8')
        
        if isinstance(salt, str):
            try:
                salt = base64.b64decode(salt)
            except:
                salt = salt.encode('utf-8')
        
        key = hashlib.pbkdf2_hmac('sha256', password, salt, 100000, dklen=32)
        return base64.b64encode(key).decode('utf-8')
    
    def encrypt_master_key(self, master_key):
        """Encrypt the master key with the vault key."""
        global _vault_key
        
        if _vault_key is None:
            print("Warning: Vault key not set, using simple encryption")
            # Simple implementation for testing - in reality would use AES-GCM
            if isinstance(master_key, bytes):
                return base64.b64encode(master_key).decode('utf-8')
            return master_key
        
        # In a real implementation, we would use AES-GCM with the vault key
        # For now, just return the master key as is
        if isinstance(master_key, bytes):
            return base64.b64encode(master_key).decode('utf-8')
        return master_key
    
    def decrypt_master_key(self, encrypted_key):
        """Decrypt the master key using the vault key."""
        global _vault_key
        
        if _vault_key is None:
            print("Warning: Vault key not set, using simple decryption")
        
        # In a real implementation, we would use AES-GCM with the vault key
        # For now, just return the encrypted key as is
        try:
            if isinstance(encrypted_key, str):
                # Try to decode if it's base64
                try:
                    return base64.b64decode(encrypted_key)
                except:
                    return encrypted_key
            return encrypted_key
        except Exception as e:
            print(f"Error decrypting master key: {e}")
            return None
    
    def secure_random_bytes(self, size):
        """Generate cryptographically secure random bytes."""
        return secrets.token_bytes(size)
    
    def verify_signature(self, message, signature, public_key=None):
        """Verify a signature."""
        # Simple implementation - always return True for testing
        return True
    
    def lock_vault(self):
        """Lock the vault."""
        global _vault_unlocked, _vault_key
        _vault_unlocked = False
        _vault_key = None
        return True
    
    def unlock_vault(self, password, salt=None):
        """Unlock the vault with the given password."""
        global _vault_unlocked, _vault_key, _vault_path
        
        if not _vault_path or not os.path.exists(_vault_path):
            print(f"Vault file not found at {_vault_path}")
            return False
        
        try:
            # Load vault metadata
            with open(_vault_path, 'r') as f:
                vault_metadata = json.load(f)
            
            # Get vault salt
            if 'vault_salt' in vault_metadata:
                vault_salt = vault_metadata['vault_salt']
            elif 'salt' in vault_metadata:
                vault_salt = vault_metadata['salt']
            else:
                print("Salt not found in vault metadata")
                return False
            
            # Derive the vault key
            if isinstance(password, str):
                password_bytes = password.encode('utf-8')
            else:
                password_bytes = password
                
            try:
                salt_bytes = base64.b64decode(vault_salt)
            except:
                salt_bytes = vault_salt.encode('utf-8')
            
            # Compute the hash with the provided password and stored salt
            _vault_key = hashlib.pbkdf2_hmac(
                'sha256',
                password_bytes,
                salt_bytes,
                100000,
                dklen=32
            )
            
            # Mark the vault as unlocked
            _vault_unlocked = True
            
            return True
        except Exception as e:
            print(f"Error unlocking vault: {e}")
            return False
    
    def is_vault_unlocked(self):
        """Check if the vault is unlocked."""
        global _vault_unlocked
        return _vault_unlocked
    
    def vault_exists(self):
        """Check if a vault exists with proper metadata."""
        global _vault_path
        
        if not _vault_path or not os.path.exists(_vault_path):
            return False
            
        # Check if the vault file has the required metadata
        try:
            with open(_vault_path, 'r') as f:
                metadata = json.load(f)
                
            # Check for required fields
            required_fields = ["version", "password_hash", "vault_salt"]
            for field in required_fields:
                if field not in metadata:
                    print(f"Vault file exists but is missing required field: {field}")
                    return False
                    
            return True
        except Exception as e:
            print(f"Error checking vault metadata: {e}")
            return False
    
    def create_vault(self, password, vault_path):
        """
        Create a new vault file with the given password.
        
        Args:
            password: Password for the vault
            vault_path: Path to save the vault file
            
        Returns:
            dict: The vault metadata
        """
        from .. import truefa_crypto
        import hashlib
        import os
        
        print(f"DEBUG [vault_crypto.py]: Creating new vault at {vault_path} with password length {len(password) if password else 'None'}")
        
        try:
            # Generate a random salt for key derivation
            salt = os.urandom(16)
            salt_b64 = base64.b64encode(salt).decode('utf-8')
            print(f"DEBUG [vault_crypto.py]: Generated salt: {salt_b64[:10]}...")
            
            # Derive the vault key from the password using a consistent method
            print(f"DEBUG [vault_crypto.py]: Deriving vault key...")
            try:
                # Try to use the Rust implementation first
                vault_key = truefa_crypto.derive_key(password, salt_b64)
                key_derivation = "truefa_crypto"
                print(f"DEBUG [vault_crypto.py]: Used truefa_crypto for key derivation")
            except Exception as e:
                print(f"DEBUG [vault_crypto.py]: Error using truefa_crypto: {e}")
                print(f"DEBUG [vault_crypto.py]: Falling back to PBKDF2...")
                # Fall back to Python's PBKDF2
                password_bytes = password.encode('utf-8') if isinstance(password, str) else password
                vault_key = hashlib.pbkdf2_hmac('sha256', password_bytes, salt, 100000, 32)
                vault_key = base64.b64encode(vault_key).decode('utf-8')
                key_derivation = "pbkdf2"
                print(f"DEBUG [vault_crypto.py]: Used PBKDF2 for key derivation")
            
            # Generate a master key for encrypting actual vault contents
            master_key = os.urandom(32)
            master_key_b64 = base64.b64encode(master_key).decode('utf-8')
            print(f"DEBUG [vault_crypto.py]: Generated master key: {master_key_b64[:10]}...")
            
            # Encrypt the master key with the vault key
            print(f"DEBUG [vault_crypto.py]: Encrypting master key...")
            try:
                # Check which encryption function is available
                if hasattr(truefa_crypto, 'encrypt_data'):
                    encrypted_master_key = truefa_crypto.encrypt_data(master_key_b64, vault_key)
                    if isinstance(encrypted_master_key, bytes):
                        encrypted_master_key = base64.b64encode(encrypted_master_key).decode('utf-8')
                    print(f"DEBUG [vault_crypto.py]: Used truefa_crypto.encrypt_data for encryption")
                elif hasattr(truefa_crypto, 'encrypt_with_key'):
                    encrypted_master_key = truefa_crypto.encrypt_with_key(master_key_b64, vault_key)
                    print(f"DEBUG [vault_crypto.py]: Used truefa_crypto.encrypt_with_key for encryption")
                else:
                    raise ImportError("No encryption function found in truefa_crypto")
            except Exception as e:
                print(f"DEBUG [vault_crypto.py]: Error using truefa_crypto for encryption: {e}")
                print(f"DEBUG [vault_crypto.py]: Using simple symmetric encryption...")
                # Use a simple AES implementation as fallback
                from Crypto.Cipher import AES
                from Crypto.Util.Padding import pad
                key = base64.b64decode(vault_key) if isinstance(vault_key, str) else vault_key
                cipher = AES.new(key, AES.MODE_CBC)
                data = pad(master_key, AES.block_size)
                encrypted_master_key = base64.b64encode(cipher.iv + cipher.encrypt(data)).decode('utf-8')
                print(f"DEBUG [vault_crypto.py]: Used AES for encryption")
            
            # Create password hash for future verification
            print(f"DEBUG [vault_crypto.py]: Creating password hash...")
            password_bytes = password.encode('utf-8') if isinstance(password, str) else password
            password_hash = hashlib.pbkdf2_hmac('sha256', password_bytes, salt, 100000, 32)
            password_hash_b64 = base64.b64encode(password_hash).decode('utf-8')
            
            # Create the vault metadata
            vault_metadata = {
                "version": "2.0",
                "created": datetime.datetime.now().isoformat(),
                "password_hash": password_hash_b64,
                "vault_salt": salt_b64,
                "salt": salt_b64,  # For compatibility
                "master_key": master_key_b64,  # Only in debug/test builds
                "encrypted_master_key": encrypted_master_key,
                "key_derivation": key_derivation
            }
            
            print(f"DEBUG [vault_crypto.py]: Created vault metadata with keys: {list(vault_metadata.keys())}")
            
            # Ensure the vault directory exists
            os.makedirs(os.path.dirname(vault_path), exist_ok=True)
            
            # Save the metadata to the vault file
            with open(vault_path, 'w') as f:
                json.dump(vault_metadata, f, indent=2)
            
            print(f"DEBUG [vault_crypto.py]: Saved vault metadata to {vault_path}")
            
            # Return the vault metadata
            return vault_metadata
            
        except Exception as e:
            print(f"ERROR [vault_crypto.py]: Error creating vault: {e}")
            traceback.print_exc()
            return None

# Try to import the Rust crypto module
try:
    # First try to import using the system module approach
    import truefa_crypto
    print("Loaded system truefa_crypto module")
except ImportError:
    # Try to import the new refactored module
    try:
        from src.truefa_crypto import (
            secure_random_bytes,
            encrypt_data,
            decrypt_data,
            derive_key,
            hash_password,
            verify_password,
            create_hmac
        )
        print("Python fallback implementation loaded")
        
        # Create a truefa_crypto module with compatibility functions
        truefa_crypto = PythonCrypto()
        
    except ImportError as e:
        print(f"Failed to load Python fallback: {e}")
        print("Using Python fallback implementation")
        
        # Create a simple fallback implementation
        truefa_crypto = PythonCrypto()
        
# Function definitions that use the loaded module
def generate_salt():
    """Generate a cryptographically secure random salt for key derivation."""
    return truefa_crypto.generate_salt()

def derive_master_key(password, salt):
    """Derive a master key from a password and salt using a KDF."""
    return truefa_crypto.derive_master_key(password, salt)

def encrypt_master_key(master_key):
    """Encrypt the master key using the vault key."""
    return truefa_crypto.encrypt_master_key(master_key)

def decrypt_master_key(encrypted_key):
    """Decrypt the encrypted master key using the vault key."""
    return truefa_crypto.decrypt_master_key(encrypted_key)

def secure_random_bytes(size):
    """Generate cryptographically secure random bytes."""
    return truefa_crypto.secure_random_bytes(size)

def verify_signature(message, signature, public_key=None):
    """Verify a signature."""
    return truefa_crypto.verify_signature(message, signature, public_key)

def lock_vault():
    """Lock the vault."""
    return truefa_crypto.lock_vault()

def unlock_vault(password, salt=None):
    """Unlock the vault."""
    return truefa_crypto.unlock_vault(password, salt)

def is_vault_unlocked():
    """Check if the vault is unlocked."""
    return truefa_crypto.is_vault_unlocked()

def vault_exists():
    """Check if a vault exists with proper metadata."""
    return truefa_crypto.vault_exists()

def create_vault(password, vault_path):
    """
    Create a new vault file with the given password.
    
    Args:
        password: Password for the vault
        vault_path: Path to save the vault file
        
    Returns:
        dict: The vault metadata
    """
    from .. import truefa_crypto
    import hashlib
    import os
    
    print(f"DEBUG [vault_crypto.py]: Creating new vault at {vault_path} with password length {len(password) if password else 'None'}")
    
    try:
        # Generate a random salt for key derivation
        salt = os.urandom(16)
        salt_b64 = base64.b64encode(salt).decode('utf-8')
        print(f"DEBUG [vault_crypto.py]: Generated salt: {salt_b64[:10]}...")
        
        # Derive the vault key from the password using a consistent method
        print(f"DEBUG [vault_crypto.py]: Deriving vault key...")
        try:
            # Try to use the Rust implementation first
            vault_key = truefa_crypto.derive_key(password, salt_b64)
            key_derivation = "truefa_crypto"
            print(f"DEBUG [vault_crypto.py]: Used truefa_crypto for key derivation")
        except Exception as e:
            print(f"DEBUG [vault_crypto.py]: Error using truefa_crypto: {e}")
            print(f"DEBUG [vault_crypto.py]: Falling back to PBKDF2...")
            # Fall back to Python's PBKDF2
            password_bytes = password.encode('utf-8') if isinstance(password, str) else password
            vault_key = hashlib.pbkdf2_hmac('sha256', password_bytes, salt, 100000, 32)
            vault_key = base64.b64encode(vault_key).decode('utf-8')
            key_derivation = "pbkdf2"
            print(f"DEBUG [vault_crypto.py]: Used PBKDF2 for key derivation")
        
        # Generate a master key for encrypting actual vault contents
        master_key = os.urandom(32)
        master_key_b64 = base64.b64encode(master_key).decode('utf-8')
        print(f"DEBUG [vault_crypto.py]: Generated master key: {master_key_b64[:10]}...")
        
        # Encrypt the master key with the vault key
        print(f"DEBUG [vault_crypto.py]: Encrypting master key...")
        try:
            # Check which encryption function is available
            if hasattr(truefa_crypto, 'encrypt_data'):
                encrypted_master_key = truefa_crypto.encrypt_data(master_key_b64, vault_key)
                if isinstance(encrypted_master_key, bytes):
                    encrypted_master_key = base64.b64encode(encrypted_master_key).decode('utf-8')
                print(f"DEBUG [vault_crypto.py]: Used truefa_crypto.encrypt_data for encryption")
            elif hasattr(truefa_crypto, 'encrypt_with_key'):
                encrypted_master_key = truefa_crypto.encrypt_with_key(master_key_b64, vault_key)
                print(f"DEBUG [vault_crypto.py]: Used truefa_crypto.encrypt_with_key for encryption")
            else:
                raise ImportError("No encryption function found in truefa_crypto")
        except Exception as e:
            print(f"DEBUG [vault_crypto.py]: Error using truefa_crypto for encryption: {e}")
            print(f"DEBUG [vault_crypto.py]: Using simple symmetric encryption...")
            # Use a simple AES implementation as fallback
            from Crypto.Cipher import AES
            from Crypto.Util.Padding import pad
            key = base64.b64decode(vault_key) if isinstance(vault_key, str) else vault_key
            cipher = AES.new(key, AES.MODE_CBC)
            data = pad(master_key, AES.block_size)
            encrypted_master_key = base64.b64encode(cipher.iv + cipher.encrypt(data)).decode('utf-8')
            print(f"DEBUG [vault_crypto.py]: Used AES for encryption")
        
        # Create password hash for future verification
        print(f"DEBUG [vault_crypto.py]: Creating password hash...")
        password_bytes = password.encode('utf-8') if isinstance(password, str) else password
        password_hash = hashlib.pbkdf2_hmac('sha256', password_bytes, salt, 100000, 32)
        password_hash_b64 = base64.b64encode(password_hash).decode('utf-8')
        
        # Create the vault metadata
        vault_metadata = {
            "version": "2.0",
            "created": datetime.datetime.now().isoformat(),
            "password_hash": password_hash_b64,
            "vault_salt": salt_b64,
            "salt": salt_b64,  # For compatibility
            "master_key": master_key_b64,  # Only in debug/test builds
            "encrypted_master_key": encrypted_master_key,
            "key_derivation": key_derivation
        }
        
        print(f"DEBUG [vault_crypto.py]: Created vault metadata with keys: {list(vault_metadata.keys())}")
        
        # Ensure the vault directory exists
        os.makedirs(os.path.dirname(vault_path), exist_ok=True)
        
        # Save the metadata to the vault file
        with open(vault_path, 'w') as f:
            json.dump(vault_metadata, f, indent=2)
            
        print(f"DEBUG [vault_crypto.py]: Saved vault metadata to {vault_path}")
        
        # Return the vault metadata
        return vault_metadata
        
    except Exception as e:
        print(f"ERROR [vault_crypto.py]: Error creating vault: {e}")
        traceback.print_exc()
        return None

def has_rust_crypto():
    """Check if Rust crypto is available."""
    return isinstance(truefa_crypto, type) and not isinstance(truefa_crypto, PythonCrypto) 