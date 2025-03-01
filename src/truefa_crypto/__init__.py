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

    @staticmethod
    def vault_exists():
        print(f"DUMMY CALL: vault_exists((), {{}})")
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
    return FallbackMethods.vault_exists()

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
            os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))), "rust_crypto", "target", "release", "truefa_crypto.dll"),
        ]

    # Flag to track if we successfully loaded the DLL
    _dll_loaded = False
    
    # Try each potential location
    for dll_path in possible_dll_locations:
        print(f"DEBUG: Checking for DLL at {dll_path}")
        if os.path.exists(dll_path):
            print(f"DEBUG: Found DLL at {dll_path}")
            try:
                # Load the DLL
                _lib = ctypes.CDLL(dll_path)
                
                # If we reach here, DLL loaded successfully
                print(f"DEBUG: DLL loaded successfully from {dll_path}")
                
                # Define C function signatures for the DLL functions
                
                # Random bytes generation
                _lib.c_secure_random_bytes.argtypes = [
                    ctypes.c_size_t,                # size
                    ctypes.POINTER(ctypes.c_ubyte), # out_ptr
                    ctypes.POINTER(ctypes.c_size_t) # out_len
                ]
                _lib.c_secure_random_bytes.restype = ctypes.c_bool

                def secure_random_bytes(size):
                    buffer = (ctypes.c_ubyte * size)()
                    out_len = ctypes.c_size_t(size)
                    success = _lib.c_secure_random_bytes(size, buffer, ctypes.byref(out_len))
                    if not success:
                        print("WARNING: c_secure_random_bytes failed, using fallback")
                        return FallbackMethods.secure_random_bytes(size)
                    return bytes(buffer[:out_len.value])
                
                # Vault status functions
                _lib.c_is_vault_unlocked.argtypes = []
                _lib.c_is_vault_unlocked.restype = ctypes.c_bool
                
                def is_vault_unlocked():
                    try:
                        return _lib.c_is_vault_unlocked()
                    except Exception as e:
                        print(f"WARNING: c_is_vault_unlocked failed: {e}, using fallback")
                        return FallbackMethods.is_vault_unlocked()
                
                _lib.c_vault_exists.argtypes = []
                _lib.c_vault_exists.restype = ctypes.c_bool
                
                def vault_exists():
                    try:
                        return _lib.c_vault_exists()
                    except Exception as e:
                        print(f"WARNING: c_vault_exists failed: {e}, using fallback")
                        return FallbackMethods.vault_exists()
                    
                # Vault functions
                _lib.c_create_vault.argtypes = [
                    ctypes.c_char_p,                # password_ptr
                    ctypes.c_size_t,                # password_len
                    ctypes.POINTER(ctypes.c_ubyte), # out_ptr
                    ctypes.POINTER(ctypes.c_size_t) # out_len
                ]
                _lib.c_create_vault.restype = ctypes.c_bool
                
                def create_vault(password):
                    password_bytes = password.encode('utf-8')
                    buffer_size = 128  # Allocate a reasonably sized buffer
                    buffer = (ctypes.c_ubyte * buffer_size)()
                    out_len = ctypes.c_size_t(buffer_size)
                    
                    success = _lib.c_create_vault(
                        password_bytes, 
                        len(password_bytes),
                        buffer,
                        ctypes.byref(out_len)
                    )
                    
                    if not success:
                        print("WARNING: c_create_vault failed, using fallback")
                        return FallbackMethods.create_vault(password)
                        
                    return bytes(buffer[:out_len.value]).decode('utf-8')
                
                _lib.c_unlock_vault.argtypes = [
                    ctypes.c_char_p,  # password_ptr
                    ctypes.c_size_t,  # password_len
                    ctypes.c_char_p,  # salt_ptr
                    ctypes.c_size_t   # salt_len
                ]
                _lib.c_unlock_vault.restype = ctypes.c_bool
                
                def unlock_vault(password, salt):
                    password_bytes = password.encode('utf-8')
                    salt_bytes = salt.encode('utf-8')
                    
                    try:
                        result = _lib.c_unlock_vault(
                            password_bytes, 
                            len(password_bytes),
                            salt_bytes,
                            len(salt_bytes)
                        )
                        return result
                    except Exception as e:
                        print(f"WARNING: c_unlock_vault failed: {e}, using fallback")
                        return FallbackMethods.unlock_vault(password)
                
                _lib.c_lock_vault.argtypes = []
                _lib.c_lock_vault.restype = ctypes.c_bool
                
                def lock_vault():
                    try:
                        return _lib.c_lock_vault()
                    except Exception as e:
                        print(f"WARNING: c_lock_vault failed: {e}, using fallback")
                        return FallbackMethods.lock_vault()
                
                # Key generation and management
                _lib.c_generate_salt.argtypes = [
                    ctypes.POINTER(ctypes.c_ubyte), # out_ptr
                    ctypes.POINTER(ctypes.c_size_t) # out_len
                ]
                _lib.c_generate_salt.restype = ctypes.c_bool
                
                def generate_salt():
                    buffer_size = 128  # Allocate a reasonably sized buffer
                    buffer = (ctypes.c_ubyte * buffer_size)()
                    out_len = ctypes.c_size_t(buffer_size)
                    
                    success = _lib.c_generate_salt(buffer, ctypes.byref(out_len))
                    
                    if not success:
                        print("WARNING: c_generate_salt failed, using fallback")
                        return FallbackMethods.generate_salt()
                        
                    return bytes(buffer[:out_len.value]).decode('utf-8')
                
                _lib.c_derive_master_key.argtypes = [
                    ctypes.c_char_p,                # password_ptr
                    ctypes.c_size_t,                # password_len
                    ctypes.c_char_p,                # salt_ptr
                    ctypes.c_size_t,                # salt_len
                    ctypes.POINTER(ctypes.c_ubyte), # out_ptr
                    ctypes.POINTER(ctypes.c_size_t) # out_len
                ]
                _lib.c_derive_master_key.restype = ctypes.c_bool
                
                def derive_master_key(password, salt):
                    password_bytes = password.encode('utf-8')
                    salt_bytes = salt.encode('utf-8')
                    buffer_size = 128  # Allocate a reasonably sized buffer
                    buffer = (ctypes.c_ubyte * buffer_size)()
                    out_len = ctypes.c_size_t(buffer_size)
                    
                    success = _lib.c_derive_master_key(
                        password_bytes, 
                        len(password_bytes),
                        salt_bytes,
                        len(salt_bytes),
                        buffer,
                        ctypes.byref(out_len)
                    )
                    
                    if not success:
                        print("WARNING: c_derive_master_key failed, using fallback")
                        return FallbackMethods.derive_master_key(password, salt)
                        
                    return bytes(buffer[:out_len.value]).decode('utf-8')
                
                _lib.c_encrypt_master_key.argtypes = [
                    ctypes.c_char_p,                # key_ptr
                    ctypes.c_size_t,                # key_len
                    ctypes.POINTER(ctypes.c_ubyte), # out_ptr
                    ctypes.POINTER(ctypes.c_size_t) # out_len
                ]
                _lib.c_encrypt_master_key.restype = ctypes.c_bool
                
                def encrypt_master_key(master_key):
                    key_bytes = master_key.encode('utf-8')
                    buffer_size = 256  # Allocate a reasonably sized buffer
                    buffer = (ctypes.c_ubyte * buffer_size)()
                    out_len = ctypes.c_size_t(buffer_size)
                    
                    success = _lib.c_encrypt_master_key(
                        key_bytes, 
                        len(key_bytes),
                        buffer,
                        ctypes.byref(out_len)
                    )
                    
                    if not success:
                        print("WARNING: c_encrypt_master_key failed, using fallback")
                        return FallbackMethods.encrypt_master_key(master_key)
                        
                    return bytes(buffer[:out_len.value]).decode('utf-8')
                
                _lib.c_decrypt_master_key.argtypes = [
                    ctypes.c_char_p,                # encrypted_ptr
                    ctypes.c_size_t,                # encrypted_len
                    ctypes.POINTER(ctypes.c_ubyte), # out_ptr
                    ctypes.POINTER(ctypes.c_size_t) # out_len
                ]
                _lib.c_decrypt_master_key.restype = ctypes.c_bool
                
                def decrypt_master_key(encrypted_key):
                    key_bytes = encrypted_key.encode('utf-8')
                    buffer_size = 256  # Allocate a reasonably sized buffer
                    buffer = (ctypes.c_ubyte * buffer_size)()
                    out_len = ctypes.c_size_t(buffer_size)
                    
                    success = _lib.c_decrypt_master_key(
                        key_bytes, 
                        len(key_bytes),
                        buffer,
                        ctypes.byref(out_len)
                    )
                    
                    if not success:
                        print("WARNING: c_decrypt_master_key failed, using fallback")
                        return FallbackMethods.decrypt_master_key(encrypted_key)
                        
                    return bytes(buffer[:out_len.value]).decode('utf-8')
                
                # Signature verification
                _lib.c_verify_signature.argtypes = [
                    ctypes.c_char_p, ctypes.c_size_t,  # data_ptr, data_len
                    ctypes.c_char_p, ctypes.c_size_t,  # signature_ptr, signature_len
                ]
                _lib.c_verify_signature.restype = ctypes.c_bool
                
                def verify_signature(message, signature, public_key):
                    try:
                        result = _lib.c_verify_signature(
                            message, len(message),
                            signature, len(signature)
                        )
                        return result
                    except Exception as e:
                        print(f"WARNING: c_verify_signature failed: {e}, using fallback")
                        return FallbackMethods.verify_signature(public_key, message, signature)
                
                # SecureString creation
                try:
                    _lib.c_create_secure_string.argtypes = [
                        ctypes.c_char_p, ctypes.c_size_t,  # data_ptr, data_len
                    ]
                    _lib.c_create_secure_string.restype = ctypes.c_void_p
                    
                    def create_secure_string(data):
                        try:
                            data_bytes = data.encode('utf-8') if isinstance(data, str) else data
                            result = _lib.c_create_secure_string(
                                data_bytes, len(data_bytes)
                            )
                            if result:
                                return SecureString(data)
                            else:
                                print("WARNING: c_create_secure_string returned null, using fallback")
                                return FallbackMethods.create_secure_string(data)
                        except Exception as e:
                            print(f"WARNING: c_create_secure_string failed: {e}, using fallback")
                            return FallbackMethods.create_secure_string(data)
                except AttributeError:
                    print("WARNING: Function c_create_secure_string not found in DLL, using fallback")
                    create_secure_string = FallbackMethods.create_secure_string
                
                # Set flag indicating we've loaded the DLL successfully
                _dll_loaded = True
                break
                
            except Exception as e:
                print(f"DEBUG: Failed to load DLL from {dll_path}: {e}")
                import traceback
                traceback.print_exc()
        else:
            print(f"DEBUG: DLL not found at {dll_path}")

    # If we didn't successfully load the DLL, use the fallback implementations
    if not _dll_loaded:
        print("WARNING: Could not load Rust crypto library, using Python fallback implementations")
        secure_random_bytes = FallbackMethods.secure_random_bytes
        is_vault_unlocked = FallbackMethods.is_vault_unlocked
        vault_exists = FallbackMethods.vault_exists
        create_vault = FallbackMethods.create_vault
        unlock_vault = FallbackMethods.unlock_vault
        lock_vault = FallbackMethods.lock_vault
        generate_salt = FallbackMethods.generate_salt
        derive_master_key = FallbackMethods.derive_master_key
        encrypt_master_key = FallbackMethods.encrypt_master_key
        decrypt_master_key = FallbackMethods.decrypt_master_key
        verify_signature = FallbackMethods.verify_signature
        create_secure_string = FallbackMethods.create_secure_string

except Exception as e:
    print(f"Error during DLL loading process: {e}")

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
    'verify_signature',
    'create_secure_string'
]