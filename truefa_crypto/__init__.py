"""
TrueFA Crypto Module

This module provides cryptographic operations for the TrueFA application.
It attempts to load the Rust-based implementation first, then falls back to Python.
"""

import os
import sys
import ctypes
from ctypes import c_void_p, c_char_p, c_size_t, c_int
import base64
import importlib
from pathlib import Path

# Set global flag to use fallback implementation initially
USING_FALLBACK = True

def get_module_path():
    """Get the path of the current module for DLL loading."""
    if getattr(sys, 'frozen', False):
        # Running as a PyInstaller bundle
        return Path(sys._MEIPASS)
    else:
        # Running from regular Python
        print(f"Running from regular Python. Searching in: {os.getcwd()}")
        return Path(os.getcwd())

def init_module():
    """
    Initialize the crypto module.
    Attempt to load the Rust library, and fall back to Python if not available.
    """
    global USING_FALLBACK
    
    try:
        # First try to directly import as a Python module (PyO3 method)
        try:
            sys.path.append(str(get_module_path()))
            from rust_crypto.target.release import truefa_crypto as rust_crypto
            
            # Define all the functions we need
            globals().update({
                'secure_random_bytes': rust_crypto.secure_random_bytes,
                'create_secure_string': rust_crypto.create_secure_string,
                'is_vault_unlocked': rust_crypto.is_vault_unlocked,
                'vault_exists': rust_crypto.vault_exists,
                'create_vault': rust_crypto.create_vault,
                'unlock_vault': rust_crypto.unlock_vault,
                'lock_vault': rust_crypto.lock_vault,
                'generate_salt': rust_crypto.generate_salt,
                'derive_master_key': rust_crypto.derive_master_key,
                'encrypt_master_key': rust_crypto.encrypt_master_key,
                'decrypt_master_key': rust_crypto.decrypt_master_key,
            })
            
            USING_FALLBACK = False
            return True
        except ImportError as e:
            print(f"Could not import rust_crypto module as Python module: {e}")
            
            # If PyO3 import failed, try loading the DLL directly with ctypes
            dll_paths = [
                get_module_path() / "truefa_crypto.dll",
                get_module_path() / "truefa_crypto" / "truefa_crypto.dll",
                get_module_path() / "rust_crypto" / "target" / "release" / "truefa_crypto.dll",
            ]
            
            for dll_path in dll_paths:
                if dll_path.exists():
                    print(f"Found DLL at: {dll_path}")
                    try:
                        # Load the DLL
                        dll = ctypes.CDLL(str(dll_path))
                        
                        # Define function prototypes
                        dll.secure_random_bytes.argtypes = [c_int]
                        dll.secure_random_bytes.restype = c_void_p
                        
                        dll.create_secure_string.argtypes = [c_char_p]
                        dll.create_secure_string.restype = c_void_p
                        
                        dll.is_vault_unlocked.argtypes = []
                        dll.is_vault_unlocked.restype = c_int
                        
                        dll.vault_exists.argtypes = []
                        dll.vault_exists.restype = c_int
                        
                        dll.create_vault.argtypes = [c_char_p]
                        dll.create_vault.restype = c_char_p
                        
                        dll.unlock_vault.argtypes = [c_char_p, c_char_p]
                        dll.unlock_vault.restype = c_int
                        
                        dll.lock_vault.argtypes = []
                        dll.lock_vault.restype = c_int
                        
                        dll.generate_salt.argtypes = []
                        dll.generate_salt.restype = c_char_p
                        
                        dll.derive_master_key.argtypes = [c_char_p, c_char_p]
                        dll.derive_master_key.restype = c_char_p
                        
                        dll.encrypt_master_key.argtypes = [c_char_p]
                        dll.encrypt_master_key.restype = c_char_p
                        
                        dll.decrypt_master_key.argtypes = [c_char_p]
                        dll.decrypt_master_key.restype = c_char_p
                        
                        # Create wrapper functions
                        def wrap_secure_random_bytes(size):
                            result = dll.secure_random_bytes(size)
                            # TODO: Convert result to Python bytes
                            return bytes(result)
                            
                        def wrap_create_secure_string(data):
                            if isinstance(data, str):
                                data = data.encode('utf-8')
                            return dll.create_secure_string(data)
                            
                        def wrap_is_vault_unlocked():
                            return bool(dll.is_vault_unlocked())
                            
                        def wrap_vault_exists():
                            return bool(dll.vault_exists())
                            
                        def wrap_create_vault(password):
                            if isinstance(password, str):
                                password = password.encode('utf-8')
                            result = dll.create_vault(password)
                            return result.decode('utf-8') if result else None
                            
                        def wrap_unlock_vault(password, salt):
                            if isinstance(password, str):
                                password = password.encode('utf-8')
                            if isinstance(salt, str):
                                salt = salt.encode('utf-8')
                            return bool(dll.unlock_vault(password, salt))
                            
                        def wrap_lock_vault():
                            return bool(dll.lock_vault())
                            
                        def wrap_generate_salt():
                            result = dll.generate_salt()
                            return result.decode('utf-8') if result else None
                            
                        def wrap_derive_master_key(password, salt):
                            if isinstance(password, str):
                                password = password.encode('utf-8')
                            if isinstance(salt, str):
                                salt = salt.encode('utf-8')
                            result = dll.derive_master_key(password, salt)
                            return result.decode('utf-8') if result else None
                            
                        def wrap_encrypt_master_key(master_key):
                            if isinstance(master_key, str):
                                master_key = master_key.encode('utf-8')
                            result = dll.encrypt_master_key(master_key)
                            return result.decode('utf-8') if result else None
                            
                        def wrap_decrypt_master_key(encrypted_key):
                            if isinstance(encrypted_key, str):
                                encrypted_key = encrypted_key.encode('utf-8')
                            result = dll.decrypt_master_key(encrypted_key)
                            return result.decode('utf-8') if result else None
                        
                        # Expose wrapper functions globally
                        globals().update({
                            'secure_random_bytes': wrap_secure_random_bytes,
                            'create_secure_string': wrap_create_secure_string,
                            'is_vault_unlocked': wrap_is_vault_unlocked,
                            'vault_exists': wrap_vault_exists,
                            'create_vault': wrap_create_vault,
                            'unlock_vault': wrap_unlock_vault,
                            'lock_vault': wrap_lock_vault,
                            'generate_salt': wrap_generate_salt,
                            'derive_master_key': wrap_derive_master_key,
                            'encrypt_master_key': wrap_encrypt_master_key,
                            'decrypt_master_key': wrap_decrypt_master_key,
                        })
                        
                        USING_FALLBACK = False
                        return True
                    except Exception as e:
                        print(f"Error loading DLL {dll_path}: {e}")
    
    except Exception as e:
        print(f"DEBUG: Exception during module initialization: {e}")
    
    # If we get here, we need to use the fallback
    USING_FALLBACK = True
    return False

# Initialize Rust module
init_success = init_module()

if not init_success:
    print("Creating fallback implementation")
    # Import the fallback implementation if the Rust library is not available
    from .fallback import *
    print("Initialized dummy truefa_crypto module")

def get_implementation_status():
    """Return the implementation status (Rust or Python fallback)"""
    return "Rust" if not USING_FALLBACK else "Python fallback"

print("Created fallback truefa_crypto module with function proxies")
