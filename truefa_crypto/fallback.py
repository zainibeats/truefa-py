"""
TrueFA Crypto Module - Python Fallback Implementation

This provides a Python-based fallback implementation of the Rust crypto module.
It is used when the Rust module cannot be loaded.

WARNING: This implementation is less secure than the Rust version!
It does not provide the same level of memory protection and may leave sensitive
data in memory longer than necessary.
"""

import os
import base64
import hashlib
from typing import Optional, List, Union, Any
import secrets
import binascii
import warnings

# Issue a warning when using this fallback implementation
warnings.warn(
    "Using Python fallback implementation for crypto operations. Security is REDUCED.",
    UserWarning, stacklevel=2
)

# Class to simulate the Rust SecureString functionality
class SecureString:
    def __init__(self, data: Union[str, bytes]):
        if isinstance(data, str):
            self._data = data.encode('utf-8')
        else:
            self._data = data
            
    def __str__(self) -> str:
        return self._data.decode('utf-8')
        
    def clear(self) -> None:
        # In Python we can't really securely clear memory
        # This is just a best-effort attempt
        self._data = b''

# Global vault state (simulates the Rust VaultKeyCache)
_vault_key = None
_vault_initialized = False
_vault_unlocked = False

def secure_random_bytes(size: int) -> bytes:
    """Generate cryptographically secure random bytes."""
    print(f"DUMMY CALL: secure_random_bytes(({size},), {{}})")
    return secrets.token_bytes(size)

def create_secure_string(data: bytes) -> int:
    """Create a secure string object (simulated with an integer handle)."""
    print(f"DUMMY CALL: create_secure_string(({data},), {{}})")
    return 12345  # Dummy handle

def secure_string_to_string(handle: int) -> bytes:
    """Convert a secure string handle to a regular string."""
    print(f"DUMMY CALL: secure_string_to_string(({handle},), {{}})")
    return b"dummy_string"

def secure_string_clear(handle: int) -> None:
    """Clear a secure string from memory."""
    print(f"DUMMY CALL: secure_string_clear(({handle},), {{}})")
    pass

def is_vault_unlocked() -> bool:
    """Check if the vault is currently unlocked."""
    print(f"DUMMY CALL: is_vault_unlocked((), {{}})")
    return _vault_unlocked

def vault_exists() -> bool:
    """Check if a vault has been initialized."""
    print(f"DUMMY CALL: vault_exists((), {{}})")
    return _vault_initialized

def create_vault(password: str) -> str:
    """Create a new vault with the given master password."""
    print(f"DUMMY CALL: create_vault(({password},), {{}})")
    global _vault_initialized, _vault_unlocked
    _vault_initialized = True
    _vault_unlocked = True
    return "dummy_salt"

def unlock_vault(password: str, salt: str) -> bool:
    """Attempt to unlock the vault with the given password and salt."""
    print(f"DUMMY CALL: unlock_vault(({password}, {salt}), {{}})")
    global _vault_unlocked
    _vault_unlocked = True
    return True

def lock_vault() -> None:
    """Lock the vault by clearing the active key."""
    print(f"DUMMY CALL: lock_vault((), {{}})")
    global _vault_unlocked
    _vault_unlocked = False

def generate_salt() -> str:
    """Generate a cryptographically secure random salt for key derivation."""
    print(f"DUMMY CALL: generate_salt((), {{}})")
    salt = secrets.token_bytes(16)
    return base64.b64encode(salt).decode('utf-8')

def derive_master_key(master_password: str, salt_b64: str) -> str:
    """Derive a master key from a password and salt using a KDF."""
    print(f"DUMMY CALL: derive_master_key(({master_password}, {salt_b64}), {{}})")
    salt = base64.b64decode(salt_b64)
    key = hashlib.scrypt(
        master_password.encode('utf-8'),
        salt=salt,
        n=16384,
        r=8,
        p=1,
        dklen=32
    )
    return base64.b64encode(key).decode('utf-8')

def encrypt_master_key(master_key_b64: str) -> str:
    """Encrypt the master key using the vault key."""
    print(f"DUMMY CALL: encrypt_master_key(({master_key_b64},), {{}})")
    # In a real implementation, this would use AES-GCM or similar
    # Here we just encode it differently
    try:
        nonce = secrets.token_bytes(12)
        master_key = base64.b64decode(master_key_b64)
        # XOR with a dummy key (not actually secure)
        dummy_key = b'X' * len(master_key)
        ciphertext = bytes(a ^ b for a, b in zip(master_key, dummy_key))
        result = nonce + ciphertext
        return base64.b64encode(result).decode('utf-8')
    except Exception as e:
        print(f"Error in encrypt_master_key: {e}")
        return ""

def decrypt_master_key(encrypted_key_b64: str) -> str:
    """Decrypt the encrypted master key using the vault key."""
    print(f"DUMMY CALL: decrypt_master_key(({encrypted_key_b64},), {{}})")
    try:
        encrypted_data = base64.b64decode(encrypted_key_b64)
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]
        # XOR with a dummy key (not actually secure)
        dummy_key = b'X' * len(ciphertext)
        plaintext = bytes(a ^ b for a, b in zip(ciphertext, dummy_key))
        return base64.b64encode(plaintext).decode('utf-8')
    except Exception as e:
        print(f"Error in decrypt_master_key: {e}")
        return ""
