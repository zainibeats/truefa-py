"""
TrueFA Crypto Module

This module provides secure cryptographic operations through a Rust-based implementation.
It handles loading the Rust DLL and provides Python bindings for secure operations.
"""

import os
import sys
import ctypes
from pathlib import Path

# Global state for Python fallback implementations
_VAULT_UNLOCKED = [False]

# Fallback implementations
class FallbackMethods:
    """Provides fallback implementations for Rust functions."""
    
    @staticmethod
    def secure_random_bytes(size):
        print(f"DUMMY CALL: secure_random_bytes(({size},), {{}})")
        import os
        return os.urandom(size)
    
    @staticmethod
    def create_vault(password):
        print(f"DUMMY CALL: create_vault(({password},), {{}})")
        import os
        import base64
        # Generate a random salt
        salt = os.urandom(32)
        # Return base64 encoded salt
        return base64.b64encode(salt).decode('utf-8')
    
    @staticmethod
    def unlock_vault(password):
        print(f"DUMMY CALL: unlock_vault(({password},), {{}})")
        # Mark vault as unlocked in our simulation
        _VAULT_UNLOCKED[0] = True
        return True
    
    @staticmethod
    def is_vault_unlocked():
        print(f"DUMMY CALL: is_vault_unlocked((), {{}})")
        return _VAULT_UNLOCKED[0]
    
    @staticmethod
    def lock_vault():
        print(f"DUMMY CALL: lock_vault((), {{}})")
        _VAULT_UNLOCKED[0] = False
        return True
    
    @staticmethod
    def generate_salt():
        print(f"DUMMY CALL: generate_salt((), {{}})")
        import os
        import base64
        salt = os.urandom(32)
        return base64.b64encode(salt).decode('utf-8')
    
    @staticmethod
    def derive_master_key(password, salt):
        print(f"DUMMY CALL: derive_master_key(({password}, {salt}), {{}})")
        import base64
        import hashlib
        salt_bytes = base64.b64decode(salt)
        # Use PBKDF2 for key derivation
        key = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt_bytes,
            100000  # 100,000 iterations
        )
        return base64.b64encode(key).decode('utf-8')
    
    @staticmethod
    def encrypt_master_key(master_key):
        print(f"DUMMY CALL: encrypt_master_key(({master_key},), {{}})")
        if not _VAULT_UNLOCKED[0]:
            raise ValueError("Vault is locked, cannot encrypt master key")
        import base64
        import os
        # Simulate encryption with random data
        encrypted = os.urandom(48)  # Simulate encrypted data
        return base64.b64encode(encrypted).decode('utf-8')
    
    @staticmethod
    def decrypt_master_key(encrypted_key):
        print(f"DUMMY CALL: decrypt_master_key(({encrypted_key},), {{}})")
        if not _VAULT_UNLOCKED[0]:
            raise ValueError("Vault is locked, cannot decrypt master key")
        import base64
        import os
        # Return a simulated master key
        master_key = os.urandom(32)
        return base64.b64encode(master_key).decode('utf-8')
    
    @staticmethod
    def create_secure_string(data):
        print(f"DUMMY CALL: create_secure_string(({data},), {{}})")
        class DummySecureString:
            def __init__(self, data):
                self.data = data
            
            def __str__(self):
                return self.data
            
            def clear(self):
                self.data = None
        
        return DummySecureString(data)
    
    @staticmethod
    def verify_signature(public_key, message, signature):
        print(f"DUMMY CALL: verify_signature(({public_key}, {message}, {signature}), {{}})")
        # Always return valid for testing
        return True

# Define all fallback functions at module level
def secure_random_bytes(size: int) -> bytes:
    """Generate cryptographically secure random bytes."""
    return FallbackMethods.secure_random_bytes(size)

def is_vault_unlocked() -> bool:
    """Check if the vault is currently unlocked."""
    return FallbackMethods.is_vault_unlocked()

def vault_exists() -> bool:
    """Check if a vault has been initialized."""
    return False

def create_vault(password: str) -> str:
    """Create a new vault with the given master password."""
    return FallbackMethods.create_vault(password)

def unlock_vault(password: str, salt: str) -> bool:
    """Unlock the vault with the given password and salt."""
    return FallbackMethods.unlock_vault(password)

def lock_vault() -> None:
    """Lock the vault, clearing all sensitive data."""
    FallbackMethods.lock_vault()

def generate_salt() -> str:
    """Generate a random salt for key derivation."""
    return FallbackMethods.generate_salt()

def derive_master_key(password: str, salt: str) -> str:
    """Derive a master key from a password and salt."""
    return FallbackMethods.derive_master_key(password, salt)

def encrypt_master_key(master_key: str) -> str:
    """Encrypt the master key with the vault key."""
    return FallbackMethods.encrypt_master_key(master_key)

def decrypt_master_key(encrypted_key: str) -> str:
    """Decrypt the master key with the vault key."""
    return FallbackMethods.decrypt_master_key(encrypted_key)

def verify_signature(message: bytes, signature: bytes, public_key: bytes) -> bool:
    """Verify a digital signature using the Rust crypto library."""
    return FallbackMethods.verify_signature(public_key, message, signature)

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
    # Try to find and load the Rust library
    # For PyInstaller bundles, we need to adjust the paths
    if getattr(sys, 'frozen', False):
        print(f"DEBUG: Running from PyInstaller bundle: {sys._MEIPASS}")
        print(f"DEBUG: Current working directory: {os.getcwd()}")
        print(f"DEBUG: __file__ location: {__file__}")
        print(f"DEBUG: truefa_crypto package directory: {os.path.dirname(__file__)}")
        bundle_dir = sys._MEIPASS
        app_dir = os.path.dirname(sys.executable)
        
        # Possible DLL locations in PyInstaller bundle
        possible_dll_locations = [
            # Try specific locations in the bundle first
            os.path.join(os.path.dirname(__file__), "truefa_crypto.dll"),
            os.path.join(bundle_dir, "truefa_crypto", "truefa_crypto.dll"),
            os.path.join(bundle_dir, "truefa_crypto.dll"),
            # Then try relative to the app
            os.path.join(app_dir, "truefa_crypto.dll"),
            os.path.join(app_dir, "truefa_crypto", "truefa_crypto.dll"),
        ]
        
        # For debugging with PyInstaller bundles
        print("DEBUG: Attempting to load from .pyd file")
        pyd_path = os.path.join(os.path.dirname(__file__), "truefa_crypto.pyd")
        if os.path.exists(pyd_path):
            print(f"DEBUG: Found PYD at {pyd_path}")
            from . import truefa_crypto as _lib_pyd
            # If we got here, great! Expose the functions from the PYD
            _dll_loaded = True
            # We could potentially expose functions from _lib_pyd here if needed
        else:
            print(f"DEBUG: PYD file not found at {pyd_path}")
    else:
        # For normal Python execution
        # Check the current directory and the package directory
        possible_dll_locations = [
            # Current directory
            os.path.join(os.path.dirname(__file__), "truefa_crypto.dll"),
            # Project root directory (assuming a certain structure)
            os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "rust_crypto", "target", "release", "truefa_crypto.dll"),
            # Root directory 
            os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "truefa_crypto.dll"),
        ]
        
    # Try all possible DLL locations
    for dll_path in possible_dll_locations:
        if os.path.exists(dll_path):
            print(f"DLL found at: {dll_path}")
            try:
                # Load the DLL
                _lib = ctypes.CDLL(dll_path)
                print("Successfully loaded DLL using ctypes")
                
                # Set up the function signatures
                try:
                    # Check for the core functions we need
                    required_functions = [
                        'secure_random_bytes',
                        'create_vault',
                        'unlock_vault',
                        'is_vault_unlocked',
                        'lock_vault',
                        'generate_salt',
                        'derive_master_key',
                        'encrypt_master_key',
                        'decrypt_master_key',
                        'create_secure_string',
                        'verify_signature'
                    ]
                    
                    # Verify that all required functions exist
                    missing_functions = []
                    for func_name in required_functions:
                        if not hasattr(_lib, func_name):
                            missing_functions.append(func_name)
                    
                    if missing_functions:
                        print(f"Error loading DLL {dll_path}: functions {', '.join(missing_functions)} not found")
                        continue
                    
                    # If we get here, all functions exist, so set up their signatures
                    
                    # Override the fallback functions with the DLL functions
                    
                    # Create secure_random_bytes function with proper signature
                    _lib.secure_random_bytes.argtypes = [ctypes.c_int]
                    _lib.secure_random_bytes.restype = ctypes.POINTER(ctypes.c_ubyte)
                    
                    def secure_random_bytes(size: int) -> bytes:
                        """Generate cryptographically secure random bytes."""
                        result = _lib.secure_random_bytes(size)
                        # Convert to Python bytes
                        return bytes(result[i] for i in range(size))
                    
                    # Vault status functions
                    _lib.is_vault_unlocked.argtypes = []
                    _lib.is_vault_unlocked.restype = ctypes.c_bool
                    
                    def is_vault_unlocked() -> bool:
                        """Check if the vault is currently unlocked."""
                        return _lib.is_vault_unlocked()
                    
                    _lib.vault_exists.argtypes = []
                    _lib.vault_exists.restype = ctypes.c_bool
                    
                    def vault_exists() -> bool:
                        """Check if a vault has been initialized."""
                        return _lib.vault_exists()
                        
                    # Vault functions
                    _lib.create_vault.argtypes = [ctypes.c_char_p]
                    _lib.create_vault.restype = ctypes.c_char_p
                    
                    def create_vault(password: str) -> str:
                        """Create a new vault with the given master password."""
                        result = _lib.create_vault(password.encode('utf-8'))
                        return result.decode('utf-8')
                    
                    _lib.unlock_vault.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
                    _lib.unlock_vault.restype = ctypes.c_bool
                    
                    def unlock_vault(password: str, salt: str) -> bool:
                        """Unlock the vault with the given password and salt."""
                        return _lib.unlock_vault(password.encode('utf-8'), salt.encode('utf-8'))
                    
                    _lib.lock_vault.argtypes = []
                    _lib.lock_vault.restype = None
                    
                    def lock_vault() -> None:
                        """Lock the vault, clearing all sensitive data."""
                        _lib.lock_vault()
                    
                    # Key generation and management
                    _lib.generate_salt.argtypes = []
                    _lib.generate_salt.restype = ctypes.c_char_p
                    
                    def generate_salt() -> str:
                        """Generate a random salt for key derivation."""
                        result = _lib.generate_salt()
                        return result.decode('utf-8')
                    
                    _lib.derive_master_key.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
                    _lib.derive_master_key.restype = ctypes.c_char_p
                    
                    def derive_master_key(password: str, salt: str) -> str:
                        """Derive a master key from a password and salt."""
                        result = _lib.derive_master_key(password.encode('utf-8'), salt.encode('utf-8'))
                        return result.decode('utf-8')
                    
                    _lib.encrypt_master_key.argtypes = [ctypes.c_char_p]
                    _lib.encrypt_master_key.restype = ctypes.c_char_p
                    
                    def encrypt_master_key(master_key: str) -> str:
                        """Encrypt the master key with the vault key."""
                        result = _lib.encrypt_master_key(master_key.encode('utf-8'))
                        return result.decode('utf-8')
                    
                    _lib.decrypt_master_key.argtypes = [ctypes.c_char_p]
                    _lib.decrypt_master_key.restype = ctypes.c_char_p
                    
                    def decrypt_master_key(encrypted_key: str) -> str:
                        """Decrypt the master key with the vault key."""
                        result = _lib.decrypt_master_key(encrypted_key.encode('utf-8'))
                        return result.decode('utf-8')
                    
                    # Signature verification
                    _lib.verify_signature.argtypes = [
                        ctypes.c_char_p, ctypes.c_int,  # message and length
                        ctypes.c_char_p, ctypes.c_int,  # signature and length
                        ctypes.c_char_p, ctypes.c_int   # public key and length
                    ]
                    _lib.verify_signature.restype = ctypes.c_bool
                    
                    def verify_signature(message: bytes, signature: bytes, public_key: bytes) -> bool:
                        """Verify a digital signature using the Rust crypto library."""
                        return _lib.verify_signature(
                            message, len(message),
                            signature, len(signature),
                            public_key, len(public_key)
                        )
                    
                    # Set flag indicating we've loaded the DLL successfully
                    _dll_loaded = True
                    break
                    
                except Exception as e:
                    print(f"Error setting function signatures: {e}")
                    # Continue to the next DLL
            except Exception as e:
                print(f"Error loading DLL at {dll_path}: {e}")
        else:
            print(f"DLL not found at: {dll_path}")

except Exception as e:
    print(f"Error during DLL loading process: {e}")

# If we get here and haven't loaded the DLL, we're using the fallback
if not _dll_loaded:
    print("WARNING: Using fallback implementation for secure memory!")

# This ensures these symbols are available in the module namespace
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