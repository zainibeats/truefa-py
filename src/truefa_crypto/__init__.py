"""
TrueFA Crypto Module

This module provides secure cryptographic operations for the TrueFA application.
It imports all functionality from the main truefa_crypto package.
"""

# Import all functionality from the main truefa_crypto package
from truefa_crypto import (
    SecureString,
    create_secure_string,
    secure_random_bytes,
    find_dll,
    get_lib,
    is_using_fallback,
    encrypt_data,
    decrypt_data,
    derive_key,
    hash_password,
    verify_password,
    create_hmac
)

# Re-export everything
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