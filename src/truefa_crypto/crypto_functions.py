"""
Cryptographic Functions

This module provides the main cryptographic functions used by TrueFA.
It dynamically loads functions from either the Rust DLL or Python fallback implementation.
"""

import os
import base64
import logging
from functools import wraps
import ctypes

from .loader import get_lib, is_using_fallback

# Configure logging
logger = logging.getLogger("truefa_crypto.functions")

def _lazy_load(func_name):
    """
    Decorator to lazy-load functions from the DLL or fallback implementation.
    
    Args:
        func_name (str): The name of the function to load
        
    Returns:
        function: A wrapper function that loads and calls the actual implementation
    """
    def decorator(default_impl):
        @wraps(default_impl)
        def wrapper(*args, **kwargs):
            # Get the library module
            lib = get_lib()
            
            # Try to get the function from the library
            if hasattr(lib, func_name):
                try:
                    return getattr(lib, func_name)(*args, **kwargs)
                except Exception as e:
                    logger.warning(f"Error calling {func_name} from library: {e}")
                    # Fall back to default implementation
            
            # If function not found in lib or if an error occurred, use default implementation
            return default_impl(*args, **kwargs)
        return wrapper
    return decorator

@_lazy_load("encrypt_data")
def encrypt_data(data, key):
    """
    Encrypt data using the provided key.
    
    Args:
        data (bytes or str): The data to encrypt
        key (bytes or str): The encryption key
        
    Returns:
        bytes: The encrypted data with nonce
    """
    # Convert input types if needed
    if isinstance(data, str):
        data = data.encode('utf-8')
    if isinstance(key, str):
        key = key.encode('utf-8')
    
    try:
        # Try to use the DLL directly with c_ prefix
        lib = get_lib()
        if hasattr(lib, 'c_encrypt_data'):
            try:
                return lib.c_encrypt_data(data, key)
            except Exception as e:
                logger.warning(f"Error calling c_encrypt_data: {e}")
                # Fall through to fallback
    except Exception as e:
        logger.warning(f"Error accessing DLL: {e}")
    
    # Python fallback implementation
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    import os
    
    # Generate a random nonce
    nonce = os.urandom(12)
    
    # Ensure key is right size (256 bits = 32 bytes)
    if len(key) != 32:
        import hashlib
        key = hashlib.sha256(key).digest()
    
    # Create AES-GCM cipher with the key
    cipher = AESGCM(key)
    
    # Encrypt the data
    ciphertext = cipher.encrypt(nonce, data, None)
    
    # Return nonce + ciphertext
    return nonce + ciphertext

@_lazy_load("decrypt_data")
def decrypt_data(encrypted_data, key):
    """
    Decrypt data using the provided key.
    
    Args:
        encrypted_data (bytes): The data to decrypt (nonce + ciphertext)
        key (bytes or str): The decryption key
        
    Returns:
        bytes: The decrypted data
    """
    # Convert key if needed
    if isinstance(key, str):
        key = key.encode('utf-8')
        
    try:
        # Try to use the DLL directly with c_ prefix
        lib = get_lib()
        if hasattr(lib, 'c_decrypt_data'):
            try:
                return lib.c_decrypt_data(encrypted_data, key)
            except Exception as e:
                logger.warning(f"Error calling c_decrypt_data: {e}")
                # Fall through to fallback
    except Exception as e:
        logger.warning(f"Error accessing DLL: {e}")
    
    # Python fallback implementation
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    
    # Ensure key is right size (256 bits = 32 bytes)
    if len(key) != 32:
        import hashlib
        key = hashlib.sha256(key).digest()
    
    # Extract nonce (first 12 bytes) and ciphertext
    nonce = encrypted_data[:12]
    ciphertext = encrypted_data[12:]
    
    # Create AES-GCM cipher with the key
    cipher = AESGCM(key)
    
    # Decrypt the data
    plaintext = cipher.decrypt(nonce, ciphertext, None)
    
    return plaintext

@_lazy_load("derive_key")
def derive_key(password, salt=None, iterations=100000):
    """
    Derive a key from a password and salt.
    
    Args:
        password (str or bytes): The password
        salt (bytes, optional): The salt. If None, a random salt is generated.
        iterations (int, optional): Number of iterations for key derivation
        
    Returns:
        tuple: (key, salt) where key is the derived key and salt is the salt used
    """
    # Python fallback implementation
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    import os
    
    # If password is a string, convert to bytes
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

@_lazy_load("hash_password")
def hash_password(password, salt=None):
    """
    Hash a password for storage.
    
    Args:
        password (str or bytes): The password to hash
        salt (bytes, optional): The salt. If None, a random salt is generated.
        
    Returns:
        tuple: (hash, salt) where hash is the hashed password and salt is the salt used
    """
    # This is essentially the same as derive_key, but we're giving it a separate name
    # for semantic clarity when used for password hashing
    key, salt = derive_key(password, salt)
    return key, salt

@_lazy_load("verify_password")
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
    # Python fallback implementation
    calculated_hash, _ = hash_password(password, salt)
    return calculated_hash == password_hash

@_lazy_load("create_hmac")
def create_hmac(data, key):
    """
    Create an HMAC for the provided data using the key.
    
    Args:
        data (bytes): The data to create an HMAC for
        key (bytes): The key to use for the HMAC
        
    Returns:
        bytes: The HMAC
    """
    # Python fallback implementation
    import hmac
    import hashlib
    
    # Convert data to bytes if it's a string
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    # Create HMAC using SHA-256
    h = hmac.new(key, data, hashlib.sha256)
    
    return h.digest()

@_lazy_load("create_secure_string")
def create_secure_string(data):
    """
    Create a secure string that will be automatically zeroed when no longer needed.
    
    This function uses memory-protected storage when available through the Rust implementation.
    
    Args:
        data (str or bytes): The sensitive data to protect
        
    Returns:
        SecureString: A secure string object
    """
    # Convert input types if needed
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    try:
        # Try to use the DLL directly with c_ prefix
        lib = get_lib()
        if hasattr(lib, 'c_create_secure_string'):
            try:
                # Convert data for C function call
                data_array = (ctypes.c_ubyte * len(data))(*data)
                result = lib.c_create_secure_string(data_array, len(data))
                
                if result:
                    # Successfully created a secure string using Rust
                    # We need to wrap it in Python (implementation dependent)
                    logger.debug("Created SecureString using Rust implementation")
                    return result
                
                logger.warning("c_create_secure_string returned null pointer")
            except Exception as e:
                logger.warning(f"Error calling c_create_secure_string: {e}")
                # Fall through to fallback
    except Exception as e:
        logger.warning(f"Error accessing DLL for secure string creation: {e}")
    
    # Python fallback implementation
    from .secure_string import SecureString
    return SecureString(data) 