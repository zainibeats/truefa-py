"""
Secure Memory Management Module

This module provides Python wrappers around the Rust-based secure memory implementation.
It ensures that sensitive data (like TOTP secrets) is properly protected in memory
through automatic zeroization and secure cleanup.

Key Features:
- SecureString class for protected memory storage
- Vault-based secret management
- Secure random number generation
- Automatic cleanup on process termination

The module uses the Rust truefa_crypto library for the actual implementation
of security-critical operations.
"""

import sys
import os

# Add the project root to Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from truefa_crypto import (
    SecureString as RustSecureString,
    create_vault,
    unlock_vault,
    lock_vault,
    is_vault_unlocked,
    vault_exists,
    secure_random_bytes
)

class SecureString:
    """
    Python wrapper for Rust's SecureString implementation.
    
    This class provides a secure way to store sensitive strings in memory.
    The underlying data is automatically zeroized when the object is destroyed
    or when clear() is explicitly called.
    
    Usage:
        secret = SecureString("sensitive_data")
        # Use the secret
        print(str(secret))  # Temporarily exposes the secret
        secret.clear()      # Explicitly clear when done
    """
    def __init__(self, value):
        """Initialize with a string value to be protected."""
        self._inner = RustSecureString(value)
        
    def __str__(self):
        """
        Get the protected string value.
        Note: This temporarily exposes the secret in memory.
        """
        return str(self._inner)
        
    def clear(self):
        """
        Explicitly clear the protected data.
        The memory is securely zeroized.
        """
        self._inner.clear()
        
    def __del__(self):
        """
        Ensure secure cleanup when the object is destroyed.
        Ignores cleanup errors during destruction.
        """
        try:
            self.clear()
        except:
            pass  # Ignore cleanup errors in destructor

# Export Rust functions directly with their original docstrings
__all__ = [
    'SecureString',
    'create_vault',
    'unlock_vault',
    'lock_vault',
    'is_vault_unlocked',
    'vault_exists',
    'secure_random_bytes'
]