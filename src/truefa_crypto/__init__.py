"""
TrueFA Cryptography Module

Provides a unified cryptographic interface with dual implementation strategy:
1. Primary: High-performance Rust implementation with memory safety features
2. Fallback: Pure Python implementation for cross-platform compatibility

The module automatically handles loading the appropriate implementation
with transparent function-level monitoring and intelligent fallback.

Security features:
- Memory-protected string handling
- Automatic zeroization of sensitive data
- AES-256-GCM authenticated encryption
- Strong key derivation (PBKDF2/Scrypt)
- Secure random number generation
"""

import logging
import os

# Configure logging
logging.basicConfig(level=logging.DEBUG if os.environ.get('DEBUG', '').lower() in ('true', '1', 'yes') else logging.INFO)
logger = logging.getLogger("truefa_crypto")

# Import core functionality from dedicated modules
from .loader import find_dll, get_lib, is_using_fallback

# Reset the cached state to force a fresh attempt to load the DLL
# This helps during development when the DLL might have been updated
if os.environ.get('TRUEFA_RESET_DLL_CACHE', '').lower() in ('true', '1', 'yes'):
    logger.info("Resetting DLL cache")
    from .loader import _reset_dll_cache
    _reset_dll_cache()

# Import secure string functionality
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
        
        # Log the implementation being used
        if is_using_fallback():
            logger.warning("Using Python fallback implementation")
        else:
            logger.info("Using native Rust implementation")
            
    return _lib

# Initialize on first import
_initialize() 