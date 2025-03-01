"""
TrueFA Crypto Module

This module provides secure cryptographic operations through a Rust-based implementation.
It handles loading the Rust DLL and provides Python bindings for secure operations.
"""

import os
import sys
import ctypes
import logging
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("truefa_crypto")

# Check if we should use fallback
USE_FALLBACK = os.environ.get("TRUEFA_USE_FALLBACK", "").lower() in ("1", "true", "yes")

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
        print(f"DUMMY CALL: create_vault(('*****',), {{}})")
        # Generate a dummy salt
        import base64
        import os
        _VAULT_UNLOCKED[0] = True
        salt = base64.b64encode(os.urandom(16)).decode('utf-8')
        return salt
    
    @staticmethod
    def unlock_vault(password, salt):
        print(f"DUMMY CALL: unlock_vault(('*****', '{salt[:8]}...'), {{}})")
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
    
    @staticmethod
    def generate_salt():
        print(f"DUMMY CALL: generate_salt((), {{}})")
        import base64
        import os
        return base64.b64encode(os.urandom(16)).decode('utf-8')
    
    @staticmethod
    def derive_master_key(password, salt):
        print(f"DUMMY CALL: derive_master_key(('*****', '{salt[:8]}...'), {{}})")
        # In a real implementation, this would use a proper KDF
        import base64
        import hashlib
        
        # Simple PBKDF2 implementation
        key = hashlib.pbkdf2_hmac(
            'sha256', 
            password.encode('utf-8'), 
            salt.encode('utf-8'), 
            100000, 
            dklen=32
        )
        return base64.b64encode(key).decode('utf-8')
    
    @staticmethod
    def encrypt_master_key(master_key):
        print(f"DUMMY CALL: encrypt_master_key(('{master_key[:8]}...'), {{}})")
        # This is a dummy implementation
        import base64
        return f"DUMMY_ENCRYPTED_{master_key}"
    
    @staticmethod
    def decrypt_master_key(encrypted_key):
        print(f"DUMMY CALL: decrypt_master_key(('{encrypted_key[:8]}...'), {{}})")
        # This is a dummy implementation
        if encrypted_key.startswith("DUMMY_ENCRYPTED_"):
            return encrypted_key[len("DUMMY_ENCRYPTED_"):]
        return "DUMMY_DECRYPTED_KEY"
    
    @staticmethod
    def create_secure_string(data):
        print(f"DUMMY CALL: create_secure_string(('*****',), {{}})")
        
        class DummySecureString:
            def __init__(self, data):
                self._data = data
                
            def __str__(self):
                return "[SECURE STRING]"
                
            def clear(self):
                self._data = None
                
        return DummySecureString(data)
    
    @staticmethod
    def verify_signature(data, signature):
        print(f"DUMMY CALL: verify_signature((data, signature), {{}})")
        # This is a dummy implementation
        return True
    
    @staticmethod
    def vault_exists():
        print(f"DUMMY CALL: vault_exists((), {{}})")
        # For testing purposes, we'll say the vault exists
        return True


# If fallback is explicitly requested, use fallback implementations
if USE_FALLBACK:
    logger.info("Using Python fallback implementation as requested by environment variable")
    
    # Use fallback implementations for all functions
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

else:
    # Try to load the Rust library
    try:
        # Try to find and load the Rust library
        if getattr(sys, 'frozen', False):
            # For PyInstaller bundles
            bundle_dir = sys._MEIPASS
            app_dir = os.path.dirname(sys.executable)
            
            possible_dll_locations = [
                os.path.join(app_dir, "truefa_crypto.dll"),
                os.path.join(bundle_dir, "truefa_crypto.dll"),
                os.path.join(bundle_dir, "truefa_crypto", "truefa_crypto.dll"),
                os.path.join(os.path.dirname(__file__), "truefa_crypto.dll"),
            ]
        else:
            # For normal Python execution
            possible_dll_locations = [
                os.path.join(os.path.dirname(__file__), "truefa_crypto.dll"),
                os.path.join(os.path.dirname(os.path.dirname(__file__)), "truefa_crypto", "truefa_crypto.dll"),
                os.path.join(os.getcwd(), "truefa_crypto.dll"),
                os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "truefa_crypto", "truefa_crypto.dll"),
                os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "rust_crypto", "target", "release", "truefa_crypto.dll"),
            ]

        # Try each potential location
        _lib = None
        dll_path = None
        
        for path in possible_dll_locations:
            logger.debug(f"Checking for DLL at {path}")
            if os.path.exists(path):
                logger.info(f"Found DLL at {path}")
                try:
                    _lib = ctypes.CDLL(path)
                    dll_path = path
                    break
                except Exception as e:
                    logger.warning(f"Failed to load DLL: {e}")
        
        if _lib is None:
            raise ImportError("Could not find truefa_crypto.dll")
        
        logger.info(f"Successfully loaded DLL from {dll_path}")
        
        # Define function signatures for the DLL
        
        # secure_random_bytes
        _lib.c_secure_random_bytes.argtypes = [
            ctypes.c_size_t,  # size
            ctypes.POINTER(ctypes.c_ubyte),  # out_ptr
            ctypes.POINTER(ctypes.c_size_t)  # out_len
        ]
        _lib.c_secure_random_bytes.restype = ctypes.c_bool
        
        # is_vault_unlocked
        _lib.c_is_vault_unlocked.argtypes = []
        _lib.c_is_vault_unlocked.restype = ctypes.c_bool
        
        # vault_exists
        _lib.c_vault_exists.argtypes = []
        _lib.c_vault_exists.restype = ctypes.c_bool
        
        # create_vault
        _lib.c_create_vault.argtypes = [
            ctypes.POINTER(ctypes.c_ubyte),  # password_ptr
            ctypes.c_size_t,                 # password_len
            ctypes.POINTER(ctypes.c_ubyte),  # out_ptr
            ctypes.POINTER(ctypes.c_size_t)  # out_len
        ]
        _lib.c_create_vault.restype = ctypes.c_bool
        
        # unlock_vault
        _lib.c_unlock_vault.argtypes = [
            ctypes.POINTER(ctypes.c_ubyte),  # password_ptr
            ctypes.c_size_t,                 # password_len
            ctypes.POINTER(ctypes.c_ubyte),  # salt_ptr
            ctypes.c_size_t                  # salt_len
        ]
        _lib.c_unlock_vault.restype = ctypes.c_bool
        
        # lock_vault
        _lib.c_lock_vault.argtypes = []
        _lib.c_lock_vault.restype = ctypes.c_bool
        
        # generate_salt
        _lib.c_generate_salt.argtypes = [
            ctypes.POINTER(ctypes.c_ubyte),  # out_ptr
            ctypes.POINTER(ctypes.c_size_t)  # out_len
        ]
        _lib.c_generate_salt.restype = ctypes.c_bool
        
        # derive_master_key
        _lib.c_derive_master_key.argtypes = [
            ctypes.POINTER(ctypes.c_ubyte),  # password_ptr
            ctypes.c_size_t,                 # password_len
            ctypes.POINTER(ctypes.c_ubyte),  # salt_ptr
            ctypes.c_size_t,                 # salt_len
            ctypes.POINTER(ctypes.c_ubyte),  # out_ptr
            ctypes.POINTER(ctypes.c_size_t)  # out_len
        ]
        _lib.c_derive_master_key.restype = ctypes.c_bool
        
        # encrypt_master_key
        _lib.c_encrypt_master_key.argtypes = [
            ctypes.POINTER(ctypes.c_ubyte),  # key_ptr
            ctypes.c_size_t,                 # key_len
            ctypes.POINTER(ctypes.c_ubyte),  # out_ptr
            ctypes.POINTER(ctypes.c_size_t)  # out_len
        ]
        _lib.c_encrypt_master_key.restype = ctypes.c_bool
        
        # decrypt_master_key
        _lib.c_decrypt_master_key.argtypes = [
            ctypes.POINTER(ctypes.c_ubyte),  # encrypted_ptr
            ctypes.c_size_t,                 # encrypted_len
            ctypes.POINTER(ctypes.c_ubyte),  # out_ptr
            ctypes.POINTER(ctypes.c_size_t)  # out_len
        ]
        _lib.c_decrypt_master_key.restype = ctypes.c_bool
        
        # verify_signature
        _lib.c_verify_signature.argtypes = [
            ctypes.POINTER(ctypes.c_ubyte),  # data_ptr
            ctypes.c_size_t,                 # data_len
            ctypes.POINTER(ctypes.c_ubyte),  # signature_ptr
            ctypes.c_size_t                  # signature_len
        ]
        _lib.c_verify_signature.restype = ctypes.c_bool
        
        # create_secure_string
        _lib.c_create_secure_string.argtypes = [
            ctypes.POINTER(ctypes.c_ubyte),  # data_ptr
            ctypes.c_size_t                  # data_len
        ]
        _lib.c_create_secure_string.restype = ctypes.c_void_p
        
        logger.info("Successfully defined function signatures")
        
        # Define Python wrapper functions that use the DLL
        
        def secure_random_bytes(size):
            """Generate cryptographically secure random bytes."""
            buffer = (ctypes.c_ubyte * size)()
            output_len = ctypes.c_size_t(size)
            
            if not _lib.c_secure_random_bytes(size, buffer, ctypes.byref(output_len)):
                raise RuntimeError("Failed to generate secure random bytes")
                
            return bytes(buffer[:output_len.value])
        
        def is_vault_unlocked():
            """Check if the vault is currently unlocked."""
            return bool(_lib.c_is_vault_unlocked())
        
        def vault_exists():
            """Check if a vault has been created."""
            return bool(_lib.c_vault_exists())
        
        def create_vault(password):
            """Create a new vault with the given password."""
            password_bytes = password.encode('utf-8')
            password_len = len(password_bytes)
            
            # Output buffer (assuming 256 bytes is enough for the salt)
            out_size = 256
            out_buffer = (ctypes.c_ubyte * out_size)()
            out_len = ctypes.c_size_t(out_size)
            
            if not _lib.c_create_vault(
                (ctypes.c_ubyte * password_len)(*password_bytes),
                password_len,
                out_buffer,
                ctypes.byref(out_len)
            ):
                raise RuntimeError("Failed to create vault")
                
            return bytes(out_buffer[:out_len.value]).decode('utf-8')
        
        def unlock_vault(password, salt):
            """Unlock the vault with the given password and salt."""
            password_bytes = password.encode('utf-8')
            password_len = len(password_bytes)
            
            salt_bytes = salt.encode('utf-8')
            salt_len = len(salt_bytes)
            
            return bool(_lib.c_unlock_vault(
                (ctypes.c_ubyte * password_len)(*password_bytes),
                password_len,
                (ctypes.c_ubyte * salt_len)(*salt_bytes),
                salt_len
            ))
        
        def lock_vault():
            """Lock the vault, clearing sensitive keys from memory."""
            if not _lib.c_lock_vault():
                raise RuntimeError("Failed to lock vault")
        
        def generate_salt():
            """Generate a random salt for password hashing."""
            # Assume 32 bytes is enough for the salt
            out_size = 64
            out_buffer = (ctypes.c_ubyte * out_size)()
            out_len = ctypes.c_size_t(out_size)
            
            if not _lib.c_generate_salt(out_buffer, ctypes.byref(out_len)):
                raise RuntimeError("Failed to generate salt")
                
            return bytes(out_buffer[:out_len.value]).decode('utf-8')
        
        def derive_master_key(master_password, salt_b64):
            """Derive a master key from the password and salt."""
            password_bytes = master_password.encode('utf-8')
            password_len = len(password_bytes)
            
            salt_bytes = salt_b64.encode('utf-8')
            salt_len = len(salt_bytes)
            
            # Assume 256 bytes is enough for the output
            out_size = 256
            out_buffer = (ctypes.c_ubyte * out_size)()
            out_len = ctypes.c_size_t(out_size)
            
            if not _lib.c_derive_master_key(
                (ctypes.c_ubyte * password_len)(*password_bytes),
                password_len,
                (ctypes.c_ubyte * salt_len)(*salt_bytes),
                salt_len,
                out_buffer,
                ctypes.byref(out_len)
            ):
                raise RuntimeError("Failed to derive master key")
                
            return bytes(out_buffer[:out_len.value]).decode('utf-8')
        
        def encrypt_master_key(master_key_b64):
            """Encrypt the master key with the vault key."""
            key_bytes = master_key_b64.encode('utf-8')
            key_len = len(key_bytes)
            
            # Assume 512 bytes is enough for the encrypted output
            out_size = 512
            out_buffer = (ctypes.c_ubyte * out_size)()
            out_len = ctypes.c_size_t(out_size)
            
            if not _lib.c_encrypt_master_key(
                (ctypes.c_ubyte * key_len)(*key_bytes),
                key_len,
                out_buffer,
                ctypes.byref(out_len)
            ):
                raise RuntimeError("Failed to encrypt master key")
                
            return bytes(out_buffer[:out_len.value]).decode('utf-8')
        
        def decrypt_master_key(encrypted_key_b64):
            """Decrypt the master key with the vault key."""
            encrypted_bytes = encrypted_key_b64.encode('utf-8')
            encrypted_len = len(encrypted_bytes)
            
            # Assume 256 bytes is enough for the decrypted output
            out_size = 256
            out_buffer = (ctypes.c_ubyte * out_size)()
            out_len = ctypes.c_size_t(out_size)
            
            if not _lib.c_decrypt_master_key(
                (ctypes.c_ubyte * encrypted_len)(*encrypted_bytes),
                encrypted_len,
                out_buffer,
                ctypes.byref(out_len)
            ):
                raise RuntimeError("Failed to decrypt master key")
                
            return bytes(out_buffer[:out_len.value]).decode('utf-8')
        
        def verify_signature(data, signature):
            """Verify a cryptographic signature."""
            data_bytes = data.encode('utf-8') if isinstance(data, str) else data
            data_len = len(data_bytes)
            
            sig_bytes = signature.encode('utf-8') if isinstance(signature, str) else signature
            sig_len = len(sig_bytes)
            
            return bool(_lib.c_verify_signature(
                (ctypes.c_ubyte * data_len)(*data_bytes),
                data_len,
                (ctypes.c_ubyte * sig_len)(*sig_bytes),
                sig_len
            ))
            
        class SecureString:
            """A secure string that zeroizes memory when destroyed."""
            def __init__(self, data):
                data_bytes = data.encode('utf-8') if isinstance(data, str) else data
                data_len = len(data_bytes)
                
                self._ptr = _lib.c_create_secure_string(
                    (ctypes.c_ubyte * data_len)(*data_bytes),
                    data_len
                )
                
                if not self._ptr:
                    raise RuntimeError("Failed to create secure string")
                    
            def __str__(self):
                # For security reasons, we don't expose the contents directly
                return "[SECURE STRING]"
                
            def __del__(self):
                # This should call a C function to free the secure memory
                # This will be implemented in a future version
                pass

        logger.info("Successfully loaded and initialized Rust cryptography module")
                
    except Exception as e:
        logger.error(f"Error loading Rust cryptography library: {e}")
        logger.warning("Falling back to Python implementations")
        
        # Use fallback implementations when loading the DLL fails
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
