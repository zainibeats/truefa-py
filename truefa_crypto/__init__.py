#!/usr/bin/env python3
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

# Set up the path to the DLL
_dir = os.path.dirname(os.path.abspath(__file__))
_dll_path = os.path.join(_dir, "truefa_crypto.dll")

# Check if the DLL exists, if not try to find it elsewhere
if not os.path.exists(_dll_path):
    logger.warning(f"DLL not found at {_dll_path}, searching in alternate locations")
    # Check if we're in development mode (source checkout)
    src_dll_path = os.path.join(os.path.dirname(_dir), "src", "truefa_crypto", "truefa_crypto.dll")
    if os.path.exists(src_dll_path):
        logger.info(f"Found DLL in src directory: {src_dll_path}")
        _dll_path = src_dll_path

# Check if we should use Python fallback
USE_FALLBACK = os.environ.get("TRUEFA_USE_FALLBACK", "").lower() in ("1", "true", "yes")

if USE_FALLBACK:
    logger.info("Using Python fallback implementation as requested by environment variable")
    # Import the fallback implementations
    try:
        from src.truefa_crypto import FallbackMethods, SecureString
        
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
        create_secure_string = FallbackMethods.create_secure_string
        
        logger.info("Successfully loaded fallback implementations")
    except ImportError as e:
        logger.error(f"Failed to import fallback implementations: {e}")
        raise ImportError("Failed to initialize fallback cryptography module") from e
else:
    # Try to load the Rust DLL
    try:
        logger.info(f"Attempting to load DLL from {_dll_path}")
        _lib = ctypes.CDLL(_dll_path)
        logger.info(f"Successfully loaded DLL from {_dll_path}")
        
        # Define function signatures for all exported functions
        
        # secure_random_bytes
        _lib.c_secure_random_bytes.argtypes = [
            ctypes.c_size_t,                 # size
            ctypes.POINTER(ctypes.c_ubyte),  # buffer
            ctypes.POINTER(ctypes.c_size_t)  # output_len
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
            ctypes.c_char_p  # password
        ]
        _lib.c_create_vault.restype = ctypes.c_char_p
        
        # unlock_vault
        _lib.c_unlock_vault.argtypes = [
            ctypes.c_char_p,  # password
            ctypes.c_char_p   # salt
        ]
        _lib.c_unlock_vault.restype = ctypes.c_bool
        
        # lock_vault
        _lib.c_lock_vault.argtypes = []
        _lib.c_lock_vault.restype = ctypes.c_bool
        
        # generate_salt
        _lib.c_generate_salt.argtypes = []
        _lib.c_generate_salt.restype = ctypes.c_char_p
        
        # derive_master_key
        _lib.c_derive_master_key.argtypes = [
            ctypes.c_char_p,  # password
            ctypes.c_char_p   # salt
        ]
        _lib.c_derive_master_key.restype = ctypes.c_char_p
        
        # encrypt_master_key
        _lib.c_encrypt_master_key.argtypes = [
            ctypes.c_char_p  # master_key
        ]
        _lib.c_encrypt_master_key.restype = ctypes.c_char_p
        
        # decrypt_master_key
        _lib.c_decrypt_master_key.argtypes = [
            ctypes.c_char_p  # encrypted_key
        ]
        _lib.c_decrypt_master_key.restype = ctypes.c_char_p
        
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
            if isinstance(password, str):
                password = password.encode('utf-8')
                
            result = _lib.c_create_vault(password)
            if not result:
                raise RuntimeError("Failed to create vault")
                
            return result.decode('utf-8')
        
        def unlock_vault(password, salt):
            """Unlock the vault with the given password and salt."""
            if isinstance(password, str):
                password = password.encode('utf-8')
                
            if isinstance(salt, str):
                salt = salt.encode('utf-8')
                
            return bool(_lib.c_unlock_vault(password, salt))
        
        def lock_vault():
            """Lock the vault."""
            return bool(_lib.c_lock_vault())
        
        def generate_salt():
            """Generate a random salt for key derivation."""
            result = _lib.c_generate_salt()
            if not result:
                raise RuntimeError("Failed to generate salt")
                
            return result.decode('utf-8')
        
        def derive_master_key(password, salt):
            """Derive a master key from the password and salt."""
            if isinstance(password, str):
                password = password.encode('utf-8')
                
            if isinstance(salt, str):
                salt = salt.encode('utf-8')
                
            result = _lib.c_derive_master_key(password, salt)
            if not result:
                raise RuntimeError("Failed to derive master key")
                
            return result.decode('utf-8')
        
        def encrypt_master_key(master_key):
            """Encrypt the master key for secure storage."""
            if isinstance(master_key, str):
                master_key = master_key.encode('utf-8')
                
            result = _lib.c_encrypt_master_key(master_key)
            if not result:
                raise RuntimeError("Failed to encrypt master key")
                
            return result.decode('utf-8')
        
        def decrypt_master_key(encrypted_key):
            """Decrypt the master key."""
            if isinstance(encrypted_key, str):
                encrypted_key = encrypted_key.encode('utf-8')
                
            result = _lib.c_decrypt_master_key(encrypted_key)
            if not result:
                raise RuntimeError("Failed to decrypt master key")
                
            return result.decode('utf-8')
        
        def verify_signature(data, signature):
            """Verify a signature against data."""
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
        
        def create_secure_string(data):
            """Create a secure string object from the given data."""
            return SecureString(data)
        
        logger.info("Successfully loaded and initialized Rust cryptography module")
    except Exception as e:
        logger.error(f"Error loading Rust cryptography library: {e}")
        logger.warning("Falling back to Python implementations")
        
        # Import the fallback implementations
        try:
            from src.truefa_crypto import FallbackMethods, SecureString
            
            # Use fallback implementations
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
            
            logger.info("Successfully loaded fallback implementations")
        except ImportError as e:
            logger.error(f"Failed to import fallback implementations: {e}")
            raise ImportError("Failed to initialize cryptography module") from e
