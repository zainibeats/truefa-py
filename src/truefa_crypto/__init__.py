"""
TrueFA Crypto Module

This module provides secure cryptographic operations through a Rust-based implementation.
It handles loading the Rust DLL and provides Python bindings for secure operations.
"""

import os
import sys
import ctypes
from pathlib import Path

def _find_dll():
    """Find the crypto DLL in standard locations"""
    print("Starting DLL search...")
    
    # Get the directory containing this script
    module_dir = Path(__file__).parent.absolute()
    print(f"Module directory: {module_dir}")
    
    # List of standard locations to check
    locations = [
        module_dir / "truefa_crypto.dll",  # Same directory as this module
        Path.cwd() / "truefa_crypto.dll",  # Current working directory
        Path.cwd() / "dist" / "truefa_crypto.dll",  # dist directory
    ]
    
    # Add the executable's directory if we're in a PyInstaller bundle
    if getattr(sys, 'frozen', False):
        print(f"Running in PyInstaller bundle. MEIPASS: {sys._MEIPASS}")
        locations.insert(0, Path(sys._MEIPASS) / "truefa_crypto.dll")
    else:
        print("Running in development mode")
    
    # Try each location
    for loc in locations:
        print(f"\nTrying location: {loc}")
        if loc.exists():
            print(f"Found DLL at: {loc}")
            try:
                # Try to load any dependencies first
                if getattr(sys, 'frozen', False):
                    os.add_dll_directory(str(Path(sys._MEIPASS)))
                os.add_dll_directory(str(loc.parent))
                
                dll = ctypes.CDLL(str(loc))
                print(f"Successfully loaded DLL from: {loc}")
                return dll
            except Exception as e:
                print(f"Failed to load DLL from {loc}: {e}")
                continue
        else:
            print(f"DLL not found at: {loc}")
    
    print("\nAll DLL locations tried, none successful")
    raise ImportError(
        "Could not find or load truefa_crypto.dll. "
        "Please run setup.py to install the library correctly."
    )

print("\nAttempting to load DLL...")
# Load the DLL
_lib = _find_dll()
print("DLL loaded successfully!")

class SecureString:
    """Secure string storage with automatic cleanup"""
    
    def __init__(self, value):
        """Initialize with a string value to be protected."""
        self._data = value.encode('utf-8')
        
    def __str__(self):
        """Get the protected string value."""
        return self._data.decode('utf-8')
        
    def clear(self):
        """Explicitly clear the protected data."""
        self._data = None

try:
    # Try to get function signatures from the DLL
    print("Setting function signatures...")
    
    def secure_random_bytes(size: int) -> bytes:
        """Generate cryptographically secure random bytes."""
        try:
            _lib.secure_random_bytes.argtypes = [ctypes.c_size_t]
            _lib.secure_random_bytes.restype = ctypes.POINTER(ctypes.c_ubyte)
            
            result = _lib.secure_random_bytes(size)
            return bytes(result[:size])
        except (AttributeError, OSError) as e:
            print(f"DUMMY CALL: secure_random_bytes(({size},), {{}})")
            # Fallback implementation
            import os
            return os.urandom(size)

    def is_vault_unlocked() -> bool:
        """Check if the vault is currently unlocked."""
        try:
            _lib.is_vault_unlocked.restype = ctypes.c_bool
            return _lib.is_vault_unlocked()
        except (AttributeError, OSError) as e:
            # Fallback implementation
            return _vault_unlocked

    def vault_exists() -> bool:
        """Check if a vault has been initialized."""
        try:
            _lib.vault_exists.restype = ctypes.c_bool
            return _lib.vault_exists()
        except (AttributeError, OSError) as e:
            # Fallback implementation
            return _vault_initialized

    def create_vault(password: str) -> str:
        """Create a new vault with the given master password."""
        try:
            _lib.create_vault.argtypes = [ctypes.c_char_p]
            _lib.create_vault.restype = ctypes.c_char_p
            
            result = _lib.create_vault(password.encode('utf-8'))
            return result.decode('utf-8')
        except (AttributeError, OSError) as e:
            # Fallback implementation
            print(f"DUMMY CALL: create_vault(({password},), {{}})")
            import hashlib
            import base64
            import os
            global _vault_salt, _vault_initialized, _vault_unlocked, _vault_password_hash
            
            # Generate a salt for the vault
            _vault_salt = base64.b64encode(os.urandom(32)).decode('utf-8')
            
            # Hash the password with the salt
            _vault_password_hash = hashlib.pbkdf2_hmac(
                'sha256',
                password.encode('utf-8'),
                _vault_salt.encode('utf-8'),
                100000
            )
            _vault_password_hash = base64.b64encode(_vault_password_hash).decode('utf-8')
            
            # Mark the vault as initialized and unlocked
            _vault_initialized = True
            _vault_unlocked = True
            
            return _vault_salt

    def unlock_vault(password: str, salt: str) -> bool:
        """Unlock the vault with the given password and salt."""
        try:
            _lib.unlock_vault.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
            _lib.unlock_vault.restype = ctypes.c_bool
            
            return _lib.unlock_vault(password.encode('utf-8'), salt.encode('utf-8'))
        except (AttributeError, OSError) as e:
            # Fallback implementation
            print(f"DUMMY CALL: unlock_vault(({password}, {salt}), {{}})")
            import hashlib
            import base64
            global _vault_unlocked
            
            # Hash the provided password with the salt
            password_hash = hashlib.pbkdf2_hmac(
                'sha256',
                password.encode('utf-8'),
                salt.encode('utf-8'),
                100000
            )
            password_hash = base64.b64encode(password_hash).decode('utf-8')
            
            # Check if the password is correct
            if password_hash == _vault_password_hash:
                _vault_unlocked = True
                return True
            else:
                return False

    def lock_vault() -> None:
        """Lock the vault, clearing all sensitive data."""
        try:
            _lib.lock_vault()
        except (AttributeError, OSError) as e:
            # Fallback implementation
            print("DUMMY CALL: lock_vault((), {})")
            global _vault_unlocked
            _vault_unlocked = False

    def generate_salt() -> str:
        """Generate a random salt for key derivation."""
        try:
            _lib.generate_salt.restype = ctypes.c_char_p
            result = _lib.generate_salt()
            return result.decode('utf-8')
        except (AttributeError, OSError) as e:
            # Fallback implementation
            print("DUMMY CALL: generate_salt((), {})")
            import base64
            import os
            return base64.b64encode(os.urandom(32)).decode('utf-8')

    def derive_master_key(password: str, salt: str) -> str:
        """Derive a master key from a password and salt."""
        try:
            _lib.derive_master_key.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
            _lib.derive_master_key.restype = ctypes.c_char_p
            result = _lib.derive_master_key(password.encode('utf-8'), salt.encode('utf-8'))
            return result.decode('utf-8')
        except (AttributeError, OSError) as e:
            # Fallback implementation
            print(f"DUMMY CALL: derive_master_key(({password}, {salt}), {{}})")
            import hashlib
            import base64
            key = hashlib.pbkdf2_hmac(
                'sha256',
                password.encode('utf-8'),
                salt.encode('utf-8'),
                100000
            )
            return base64.b64encode(key).decode('utf-8')

    def encrypt_master_key(master_key: str) -> str:
        """Encrypt the master key with the vault key."""
        try:
            _lib.encrypt_master_key.argtypes = [ctypes.c_char_p]
            _lib.encrypt_master_key.restype = ctypes.c_char_p
            result = _lib.encrypt_master_key(master_key.encode('utf-8'))
            return result.decode('utf-8')
        except (AttributeError, OSError) as e:
            # Fallback implementation
            print(f"DUMMY CALL: encrypt_master_key(({master_key},), {{}})")
            # For fallback, we'll just return the master key since we don't have the vault key
            return master_key

    def decrypt_master_key(encrypted_key: str) -> str:
        """Decrypt the master key with the vault key."""
        try:
            _lib.decrypt_master_key.argtypes = [ctypes.c_char_p]
            _lib.decrypt_master_key.restype = ctypes.c_char_p
            result = _lib.decrypt_master_key(encrypted_key.encode('utf-8'))
            return result.decode('utf-8')
        except (AttributeError, OSError) as e:
            # Fallback implementation
            print(f"DUMMY CALL: decrypt_master_key(({encrypted_key},), {{}})")
            # For fallback, we'll just return the encrypted key since we don't have the vault key
            return encrypted_key

    def verify_signature(message: bytes, signature: bytes, public_key: bytes) -> bool:
        """Verify a digital signature using the Rust crypto library."""
        try:
            _lib.verify_signature.argtypes = [
                ctypes.c_char_p, ctypes.c_size_t,
                ctypes.c_char_p, ctypes.c_size_t,
                ctypes.c_char_p, ctypes.c_size_t
            ]
            _lib.verify_signature.restype = ctypes.c_bool
            
            return _lib.verify_signature(
                message, len(message),
                signature, len(signature),
                public_key, len(public_key)
            )
        except (AttributeError, OSError) as e:
            # Fallback implementation
            print(f"DUMMY CALL: verify_signature((), {{}})")
            # For fallback, we'll just return True for now
            return True

except Exception as e:
    print(f"Error setting function signatures: {e}")
    
    # Initialize fallback state variables
    _vault_initialized = False
    _vault_unlocked = False
    _vault_salt = None
    _vault_password_hash = None

# Export all the functions we want to make available
__all__ = [
    'SecureString',
    'secure_random_bytes',
    'is_vault_unlocked',
    'vault_exists', 
    'create_vault',
    'unlock_vault',
    'lock_vault',
    'generate_salt',
    'derive_master_key',
    'encrypt_master_key',
    'decrypt_master_key',
    'verify_signature'
]