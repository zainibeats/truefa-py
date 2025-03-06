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
from pathlib import Path
from .secure_string import SecureString

# Try to import the Rust crypto module
try:
    import truefa_crypto
    _HAVE_RUST_CRYPTO = True
    print("Using Rust cryptographic module")
except ImportError as e:
    _HAVE_RUST_CRYPTO = False
    print(f"Rust crypto module not available: {e}")
    print("Using Python fallback implementation")
    
    # Try to import the Python fallback
    try:
        from truefa_crypto import fallback as truefa_crypto
        print("Python fallback implementation loaded")
    except ImportError as e:
        print(f"Failed to load Python fallback: {e}")
        sys.exit("Critical error: No cryptographic implementation available")

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

def verify_signature(message, signature, public_key):
    """Verify a signature using a public key."""
    return truefa_crypto.verify_signature(message, signature, public_key)

def lock_vault():
    """Lock the vault, clearing sensitive data from memory."""
    return truefa_crypto.lock_vault()

def unlock_vault(password, salt=None):
    """Unlock the vault with the provided password and salt."""
    return truefa_crypto.unlock_vault(password, salt)

def is_vault_unlocked():
    """Check if the vault is currently unlocked."""
    return truefa_crypto.is_vault_unlocked()

def vault_exists():
    """Check if a vault exists at the configured location."""
    return truefa_crypto.vault_exists()

def create_vault(password):
    """Create a new vault with the provided password."""
    return truefa_crypto.create_vault(password)

def has_rust_crypto():
    """Check if the Rust cryptographic module is available."""
    return _HAVE_RUST_CRYPTO 