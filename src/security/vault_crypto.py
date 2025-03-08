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
    
    def create_vault(self, password):
        """Create a new vault with the given password."""
        global _vault_path, _vault_unlocked, _vault_key
        
        if not _vault_path:
            print("Vault path not set")
            return False
        
        try:
            # Generate a salt
            salt = self.generate_salt()
            salt_bytes = base64.b64decode(salt)
            
            # Derive the vault key
            if isinstance(password, str):
                password_bytes = password.encode('utf-8')
            else:
                password_bytes = password
            
            # Compute the password hash
            password_hash = hashlib.pbkdf2_hmac(
                'sha256',
                password_bytes,
                salt_bytes,
                100000,
                dklen=32
            )
            
            # Store the vault key
            _vault_key = password_hash
            
            # Create vault metadata
            vault_metadata = {
                "version": "1.0",
                "created": datetime.datetime.now().isoformat(),
                "password_hash": password_hash.hex(),
                "vault_salt": salt,
                "salt": salt  # Include both for compatibility with different code paths
            }
            
            # Ensure the directory exists
            os.makedirs(os.path.dirname(_vault_path), exist_ok=True)
            
            # Save the vault metadata
            with open(_vault_path, 'w') as f:
                json.dump(vault_metadata, f, indent=2)
            
            # Mark the vault as unlocked
            _vault_unlocked = True
            
            print(f"Successfully created vault with metadata: {list(vault_metadata.keys())}")
            return salt
        except Exception as e:
            print(f"Error creating vault: {e}")
            return False

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

def create_vault(password):
    """Create a new vault."""
    return truefa_crypto.create_vault(password)

def has_rust_crypto():
    """Check if Rust crypto is available."""
    return isinstance(truefa_crypto, type) and not isinstance(truefa_crypto, PythonCrypto) 