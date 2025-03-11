"""
TrueFA Crypto Python Fallback Implementation

Pure Python implementations of cryptographic functions that serve as a fallback
when the Rust native library cannot be loaded. Provides feature compatibility
at the expense of some security benefits offered by the Rust implementation.

SECURITY NOTE: This implementation lacks memory protection features like automatic
zeroing that the Rust version provides. Use only when the native library is unavailable.
"""

import os
import time
import base64
import warnings
import hashlib
import hmac
from .secure_string import SecureString, create_secure_string, secure_random_bytes
import logging

# Add logger import:
logger = logging.getLogger(__name__)

# Replace:
warnings.warn("Using Python fallback implementation for crypto operations. Security is REDUCED.")

# With:
logger.warning("Using Python fallback implementation for crypto operations. Security is REDUCED.")

def encrypt_data(data, key):
    """
    Encrypt data using AES-GCM with a random nonce.
    
    Args:
        data (bytes): Plaintext data
        key (bytes): 32-byte encryption key
        
    Returns:
        bytes: Encrypted data (12-byte nonce + ciphertext)
    """
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        raise ImportError("cryptography package is required for encryption")
    
    # Generate a random nonce
    nonce = os.urandom(12)
    
    # Create AES-GCM cipher with the key
    cipher = AESGCM(key)
    
    # Encrypt the data
    ciphertext = cipher.encrypt(nonce, data, None)
    
    # Return nonce + ciphertext
    return nonce + ciphertext

def decrypt_data(encrypted_data, key):
    """
    Decrypt AES-GCM encrypted data.
    
    Args:
        encrypted_data (bytes): Combined nonce and ciphertext
        key (bytes): 32-byte decryption key
        
    Returns:
        bytes: Decrypted plaintext
        
    Raises:
        ValueError: If decryption fails (likely due to incorrect key or data corruption)
    """
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        raise ImportError("cryptography package is required for decryption")
    
    # Extract nonce (first 12 bytes) and ciphertext
    nonce = encrypted_data[:12]
    ciphertext = encrypted_data[12:]
    
    # Create AES-GCM cipher with the key
    cipher = AESGCM(key)
    
    try:
        # Decrypt the data
        plaintext = cipher.decrypt(nonce, ciphertext, None)
        return plaintext
    except Exception as e:
        raise ValueError(f"Decryption failed: {str(e)}")

def derive_key(password, salt=None, iterations=100000):
    """
    Derive cryptographic key from password using PBKDF2-HMAC-SHA256.
    
    Args:
        password (str or bytes): User password
        salt (bytes, optional): 16-byte salt (randomly generated if None)
        iterations (int, optional): PBKDF2 iteration count (higher is more secure)
        
    Returns:
        tuple: (derived_key, salt) where derived_key is 32 bytes
    """
    try:
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives import hashes
    except ImportError:
        raise ImportError("cryptography package is required for key derivation")
    
    # Convert password to bytes if it's a string
    if isinstance(password, str):
        password = password.encode('utf-8')
    
    # If salt is not provided, generate a random one
    if salt is None:
        salt = os.urandom(16)
    
    # Create PBKDF2 with SHA-256
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 256 bits
        salt=salt,
        iterations=iterations,
    )
    
    # Derive the key
    key = kdf.derive(password)
    
    return key, salt

def hash_password(password, salt=None):
    """
    Create password hash for secure storage.
    
    Args:
        password (str or bytes): Password to hash
        salt (bytes, optional): Salt value (randomly generated if None)
        
    Returns:
        tuple: (password_hash, salt) for storage and verification
    """
    # This is essentially the same as derive_key
    return derive_key(password, salt)

def verify_password(password, password_hash, salt):
    """
    Verify a password against stored hash using constant-time comparison.
    
    Args:
        password (str or bytes): Password to verify
        password_hash (bytes): Previously stored password hash
        salt (bytes): Salt used for the original hash
        
    Returns:
        bool: True if password matches, False otherwise
    """
    # Generate hash of the provided password using the same salt
    calculated_hash, _ = hash_password(password, salt)
    
    # Compare with the stored hash
    return calculated_hash == password_hash

def create_hmac(data, key):
    """
    Generate HMAC-SHA256 for data authentication.
    
    Args:
        data (bytes or str): Data to authenticate
        key (bytes): Secret key for HMAC generation
        
    Returns:
        bytes: 32-byte HMAC digest
    """
    # Convert data to bytes if it's a string
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    # Create HMAC using SHA-256
    h = hmac.new(key, data, hashlib.sha256)
    
    return h.digest()
