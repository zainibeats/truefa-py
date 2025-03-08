"""
TrueFA Crypto Module

This module provides secure cryptographic operations through a Rust-based implementation.
It handles loading the Rust DLL and provides Python bindings for secure operations.
"""

# Import core functionality from dedicated modules
from .loader import find_dll, get_lib, is_using_fallback
from .secure_string import SecureString, create_secure_string, secure_random_bytes

# Use __all__ to control what's exported from the package
__all__ = [
    'SecureString',
    'create_secure_string',
    'secure_random_bytes',
    'find_dll',
    'get_lib',
    'is_using_fallback',
    'encrypt_data',
    'decrypt_data',
    'derive_key',
    'hash_password',
    'verify_password',
    'create_hmac'
]

# Expose the main crypto functions which will be dynamically loaded
# from either the Rust DLL or Python fallback implementation
from .crypto_functions import (
    encrypt_data,
    decrypt_data,
    derive_key,
    hash_password,
    verify_password,
    create_hmac
)

# Initialize the DLL or fallback implementations
_lib = None

def _initialize():
    """Initialize the module by loading the DLL or fallback implementations."""
    global _lib
    if _lib is None:
        _lib = get_lib()
    return _lib

# Initialize on first import
_initialize() 