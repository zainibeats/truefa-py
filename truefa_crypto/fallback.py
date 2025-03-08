"""
Fallback Implementations for TrueFA Crypto

This module provides pure Python implementations of the cryptographic functions
that would normally be provided by the Rust DLL. These are used as a fallback
when the DLL cannot be loaded.

WARNING: These implementations may be less secure than the Rust implementations
due to lack of memory zeroing and other security features that the Rust DLL provides.
"""

import os
import time
import base64
import warnings
import hashlib
import hmac
from .secure_string import SecureString, create_secure_string, secure_random_bytes

# Emit a warning when this module is loaded
warnings.warn("Using Python fallback implementation for crypto operations. Security is REDUCED.")

def encrypt_data(data, key):
    """
    Encrypt data using AES-GCM.
    
    Args:
        data (bytes): Data to encrypt
        key (bytes): Encryption key
        
    Returns:
        bytes: Encrypted data with nonce prepended
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
    Decrypt data using AES-GCM.
    
    Args:
        encrypted_data (bytes): Encrypted data with nonce prepended
        key (bytes): Decryption key
        
    Returns:
        bytes: Decrypted data
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
    Derive a key from a password using PBKDF2.
    
    Args:
        password (str or bytes): The password
        salt (bytes, optional): The salt. If None, a random salt is generated.
        iterations (int, optional): Number of iterations for key derivation
        
    Returns:
        tuple: (key, salt) where key is the derived key and salt is the salt used
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
    Hash a password for storage using PBKDF2.
    
    Args:
        password (str or bytes): The password to hash
        salt (bytes, optional): The salt. If None, a random salt is generated.
        
    Returns:
        tuple: (hash, salt) where hash is the hashed password and salt is the salt used
    """
    # This is essentially the same as derive_key
    return derive_key(password, salt)

def verify_password(password, password_hash, salt):
    """
    Verify a password against a stored hash.
    
    Args:
        password (str or bytes): The password to verify
        password_hash (bytes): The stored password hash
        salt (bytes): The salt used to generate the hash
        
    Returns:
        bool: True if the password matches, False otherwise
    """
    # Generate hash of the provided password using the same salt
    calculated_hash, _ = hash_password(password, salt)
    
    # Compare with the stored hash
    return calculated_hash == password_hash

def create_hmac(data, key):
    """
    Create an HMAC for the provided data using the key.
    
    Args:
        data (bytes): The data to create an HMAC for
        key (bytes): The key to use for the HMAC
        
    Returns:
        bytes: The HMAC
    """
    # Convert data to bytes if it's a string
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    # Create HMAC using SHA-256
    h = hmac.new(key, data, hashlib.sha256)
    
    return h.digest()
