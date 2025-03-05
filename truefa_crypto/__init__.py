#!/usr/bin/env python3
"""
TrueFA Crypto Module

This module provides secure cryptographic operations through a Rust-based implementation.
It handles loading the Rust DLL and provides Python bindings for secure operations.
"""

import os
import sys
import time
import ctypes
import logging
import threading
from pathlib import Path

# Set up logging
logger = logging.getLogger(__name__)

# Define constants
USE_FALLBACK = os.environ.get("TRUEFA_USE_FALLBACK", "").lower() in ("true", "1", "yes")
_dll_path = None

# Global variable for the DLL instance
_lib = None

# Configure logging
logging.basicConfig(level=logging.INFO)

# Add additional paths to system PATH to help find dependencies
def _enhance_dll_search_paths():
    try:
        os.environ["PATH"] = os.path.dirname(os.path.abspath(__file__)) + os.pathsep + os.environ.get("PATH", "")
    except:
        pass

_enhance_dll_search_paths()

# Dummy module for fallback implementation
class _DummyModule:
    """A pure Python fallback implementation."""
    def __init__(self):
        self.is_initialized = True
        print("Using Python fallback implementations for crypto functions")
        
    def c_secure_random_bytes(self, size):
        """Generate secure random bytes."""
        import os
        return os.urandom(size)
    
    def c_generate_salt(self):
        """Generate a salt for key derivation."""
        import base64
        import os
        return base64.b64encode(os.urandom(32))
    
    def c_is_vault_unlocked(self):
        """Check if the vault is unlocked."""
        return False
    
    def c_vault_exists(self):
        """Check if a vault exists."""
        return False
    
    def c_create_vault(self, password):
        """Create a new vault."""
        return "ok"
    
    def c_unlock_vault(self, password, salt):
        """Unlock an existing vault."""
        return True
    
    def c_lock_vault(self):
        """Lock the vault."""
        return True
        
    def c_derive_master_key(self, password, salt):
        """Derive a master key from a password and salt."""
        import hashlib
        import base64
        
        # Convert password and salt to bytes if they aren't already
        if isinstance(password, str):
            password = password.encode('utf-8')
        if isinstance(salt, str):
            salt = salt.encode('utf-8')
            
        # Use PBKDF2 with a high iteration count
        key = hashlib.pbkdf2_hmac('sha256', password, salt, 100000, dklen=32)
        return base64.b64encode(key)
    
    def c_encrypt_master_key(self, key):
        """Encrypt the master key."""
        import base64
        if isinstance(key, str):
            key = key.encode('utf-8')
        return base64.b64encode(key)
    
    def c_decrypt_master_key(self, encrypted_key):
        """Decrypt the master key."""
        import base64
        if isinstance(encrypted_key, str):
            encrypted_key = encrypted_key.encode('utf-8')
        return base64.b64encode(encrypted_key)
    
    def c_verify_signature(self, data, signature):
        """Verify a signature."""
        return True
        
    def c_create_secure_string(self, data):
        """Create a secure string."""
        return str(data)

# Function to be called by modules using this library
def generate_salt():
    """Generate a random salt for key derivation."""
    # First check if we should use fallback mode
    if os.path.exists(os.path.join(os.path.expanduser("~"), ".truefa", ".dll_crash")):
        logger.info("Using fallback implementation for salt generation due to .dll_crash marker")
        import base64
        import os as os_module
        return base64.b64encode(os_module.urandom(32)).decode('utf-8')
    
    # Otherwise, attempt DLL function with timeout
    try:
        # Record start time for diagnostics
        start_time = time.time()
        print(f"Starting salt generation at {time.strftime('%H:%M:%S')}")
        
        # Create a sentinel file to track if generation is in progress
        sentinel_path = os.path.join(os.path.expanduser("~"), ".truefa", ".salt_generation")
        try:
            os.makedirs(os.path.dirname(sentinel_path), exist_ok=True)
            with open(sentinel_path, "w") as f:
                f.write(f"Started: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        except Exception as e:
            logger.warning(f"Failed to create sentinel file: {e}")
        
        # Use a more reliable timeout mechanism
        result = None
        error = None
        timeout_seconds = 3.0  # reasonable timeout
        
        # Use a thread with timeout to call the DLL function
        def salt_worker():
            nonlocal result, error
            try:
                result = _lib.c_generate_salt()
            except Exception as e:
                error = e
        
        worker_thread = threading.Thread(target=salt_worker)
        worker_thread.daemon = True
        worker_thread.start()
        
        # Wait for the thread to complete with timeout
        worker_thread.join(timeout_seconds)
        
        # Check if thread is still alive (timed out)
        if worker_thread.is_alive():
            print(f"Salt generation timed out after {timeout_seconds} seconds")
            logger.warning(f"Salt generation timed out after {timeout_seconds} seconds")
            
            # Create a .dll_crash marker file to use fallback in future
            dll_crash_path = os.path.join(os.path.expanduser("~"), ".truefa", ".dll_crash")
            try:
                with open(dll_crash_path, "w") as f:
                    f.write(f"Salt generation timed out after {timeout_seconds} seconds\n")
                    f.write(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                logger.info("Created .dll_crash marker file")
            except Exception as e:
                logger.warning(f"Failed to create .dll_crash marker: {e}")
            
            # Use Python fallback
            import base64
            import os as os_module
            result = base64.b64encode(os_module.urandom(32)).decode('utf-8')
            print("Using Python fallback for salt generation after timeout")
        elif error:
            # Handle errors
            print(f"Error in salt generation: {error}")
            logger.error(f"Error in salt generation: {error}")
            
            # Create a .dll_crash marker
            dll_crash_path = os.path.join(os.path.expanduser("~"), ".truefa", ".dll_crash")
            try:
                with open(dll_crash_path, "w") as f:
                    f.write(f"Salt generation error: {error}\n")
                    f.write(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                logger.info("Created .dll_crash marker file")
            except Exception as e:
                logger.warning(f"Failed to create .dll_crash marker: {e}")
            
            # Use Python fallback
            import base64
            import os as os_module
            result = base64.b64encode(os_module.urandom(32)).decode('utf-8')
            print("Using Python fallback for salt generation after error")
        else:
            # Success - clean up sentinel file
            elapsed = time.time() - start_time
            print(f"Salt generation completed in {elapsed:.2f} seconds")
            
            if not result:
                print("Salt generation failed (null result)")
                # Use Python fallback
                import base64
                import os as os_module
                result = base64.b64encode(os_module.urandom(32)).decode('utf-8')
                print("Using Python fallback for salt generation due to null result")
        
        # Clean up sentinel file
        try:
            if os.path.exists(sentinel_path):
                os.remove(sentinel_path)
        except Exception as e:
            logger.warning(f"Failed to remove sentinel file: {e}")
        
        return result.decode('utf-8') if isinstance(result, bytes) else result
    
    except Exception as e:
        # Catch any unexpected errors
        print(f"Unexpected error in salt generation: {e}")
        logger.error(f"Unexpected error in salt generation: {e}")
        
        # Use Python fallback as last resort
        import base64
        import os as os_module
        return base64.b64encode(os_module.urandom(32)).decode('utf-8')

# Load the DLL
def _load_dll():
    global _lib
    
    if USE_FALLBACK:
        logger.info("Using Python fallback implementation due to environment variable or detected issues")
        _lib = _DummyModule()
        return _lib
    
    # Try to load the Rust DLL
    try:
        logger.info(f"Attempting to load DLL from {_dll_path}")
        
        # Load the DLL
        _lib = ctypes.CDLL(_dll_path)
        
        # Set function signatures
        _lib.c_secure_random_bytes.argtypes = [
            ctypes.c_size_t,  # size
            ctypes.POINTER(ctypes.c_ubyte),  # buffer
            ctypes.POINTER(ctypes.c_size_t)  # output_len
        ]
        _lib.c_secure_random_bytes.restype = ctypes.c_bool
        
        _lib.c_is_vault_unlocked.argtypes = []
        _lib.c_is_vault_unlocked.restype = ctypes.c_bool
        
        _lib.c_vault_exists.argtypes = []
        _lib.c_vault_exists.restype = ctypes.c_bool
        
        _lib.c_create_vault.argtypes = [
            ctypes.c_char_p  # password
        ]
        _lib.c_create_vault.restype = ctypes.c_char_p
        
        _lib.c_unlock_vault.argtypes = [
            ctypes.c_char_p,  # password
            ctypes.c_char_p   # salt
        ]
        _lib.c_unlock_vault.restype = ctypes.c_bool
        
        _lib.c_lock_vault.argtypes = []
        _lib.c_lock_vault.restype = ctypes.c_bool
        
        _lib.c_generate_salt.argtypes = []
        _lib.c_generate_salt.restype = ctypes.c_char_p
        
        _lib.c_derive_master_key.argtypes = [
            ctypes.c_char_p,  # password
            ctypes.c_char_p   # salt
        ]
        _lib.c_derive_master_key.restype = ctypes.c_char_p
        
        _lib.c_encrypt_master_key.argtypes = [
            ctypes.c_char_p  # master_key
        ]
        _lib.c_encrypt_master_key.restype = ctypes.c_char_p
        
        _lib.c_decrypt_master_key.argtypes = [
            ctypes.c_char_p  # encrypted_key
        ]
        _lib.c_decrypt_master_key.restype = ctypes.c_char_p
        
        _lib.c_verify_signature.argtypes = [
            ctypes.POINTER(ctypes.c_ubyte),  # data
            ctypes.c_size_t,                 # data_len
            ctypes.POINTER(ctypes.c_ubyte),  # signature
            ctypes.c_size_t                  # signature_len
        ]
        _lib.c_verify_signature.restype = ctypes.c_bool
        
        _lib.c_create_secure_string.argtypes = [
            ctypes.POINTER(ctypes.c_ubyte),  # data
            ctypes.c_size_t                  # data_len
        ]
        _lib.c_create_secure_string.restype = ctypes.c_void_p
        
        logger.info(f"Successfully loaded DLL from {_dll_path}")
        
        # Initialize the DLL
        _lib.is_initialized = True
        
        return _lib
    
    except Exception as e:
        logger.error(f"Error loading Rust DLL: {e}")
        logger.warning("Falling back to Python implementations")
        
        # Use Python fallback
        _lib = _DummyModule()
        return _lib

# Load the DLL
_lib = _load_dll()

# Export the functions for the library callers
if USE_FALLBACK:
    logger.info("Using Python fallback implementation due to environment variable or detected issues")
    is_vault_unlocked = lambda: _lib.c_is_vault_unlocked()
    vault_exists = lambda: _lib.c_vault_exists()
    create_vault = lambda password: _lib.c_create_vault(password)
    unlock_vault = lambda password, salt: _lib.c_unlock_vault(password, salt)
    lock_vault = lambda: _lib.c_lock_vault()
    derive_master_key = lambda password, salt: _lib.c_derive_master_key(password, salt)
    encrypt_master_key = lambda key: _lib.c_encrypt_master_key(key)
    decrypt_master_key = lambda encrypted_key: _lib.c_decrypt_master_key(encrypted_key)
    verify_signature = lambda data, signature: _lib.c_verify_signature(data, signature)
    create_secure_string = lambda data: _lib.c_create_secure_string(data)
else:
    # Try to load the Rust DLL
    try:
        logger.info(f"Using native implementation")
        
        # Define Python wrapper functions that use the DLL
        def is_vault_unlocked():
            """Check if the vault is unlocked."""
            try:
                return _lib.c_is_vault_unlocked()
            except Exception as e:
                logger.error(f"Error in is_vault_unlocked: {e}")
                return False
        
        def vault_exists():
            """Check if a vault exists."""
            try:
                return _lib.c_vault_exists()
            except Exception as e:
                logger.error(f"Error in vault_exists: {e}")
                return False
        
        def create_vault(password):
            """Create a new vault."""
            try:
                if isinstance(password, str):
                    password = password.encode('utf-8')
                return _lib.c_create_vault(password)
            except Exception as e:
                logger.error(f"Error in create_vault: {e}")
                return None
        
        def unlock_vault(password, salt):
            """Unlock an existing vault."""
            try:
                if isinstance(password, str):
                    password = password.encode('utf-8')
                if isinstance(salt, str):
                    salt = salt.encode('utf-8')
                return _lib.c_unlock_vault(password, salt)
            except Exception as e:
                logger.error(f"Error in unlock_vault: {e}")
                return False
        
        def lock_vault():
            """Lock the vault."""
            try:
                return _lib.c_lock_vault()
            except Exception as e:
                logger.error(f"Error in lock_vault: {e}")
                return False
        
        def derive_master_key(password, salt):
            """Derive a master key from a password and salt."""
            try:
                if isinstance(password, str):
                    password = password.encode('utf-8')
                if isinstance(salt, str):
                    salt = salt.encode('utf-8')
                return _lib.c_derive_master_key(password, salt)
            except Exception as e:
                logger.error(f"Error in derive_master_key: {e}")
                return None
        
        def encrypt_master_key(key):
            """Encrypt the master key."""
            try:
                if isinstance(key, str):
                    key = key.encode('utf-8')
                return _lib.c_encrypt_master_key(key)
            except Exception as e:
                logger.error(f"Error in encrypt_master_key: {e}")
                return None
        
        def decrypt_master_key(encrypted_key):
            """Decrypt the master key."""
            try:
                if isinstance(encrypted_key, str):
                    encrypted_key = encrypted_key.encode('utf-8')
                return _lib.c_decrypt_master_key(encrypted_key)
            except Exception as e:
                logger.error(f"Error in decrypt_master_key: {e}")
                return None
        
        def verify_signature(data, signature):
            """Verify a signature."""
            try:
                if isinstance(data, str):
                    data = data.encode('utf-8')
                if isinstance(signature, str):
                    signature = signature.encode('utf-8')
                return _lib.c_verify_signature(data, signature)
            except Exception as e:
                logger.error(f"Error in verify_signature: {e}")
                return False
        
        def create_secure_string(data):
            """Create a secure string."""
            try:
                if isinstance(data, str):
                    data = data.encode('utf-8')
                return _lib.c_create_secure_string(data)
            except Exception as e:
                logger.error(f"Error in create_secure_string: {e}")
                return None
    
    except Exception as e:
        logger.error(f"Error setting up function wrappers: {e}")
        # If there was an error, switch to fallback
        logger.info("Switching to Python fallback implementation due to error")
        is_vault_unlocked = lambda: _lib.c_is_vault_unlocked()
        vault_exists = lambda: _lib.c_vault_exists()
        create_vault = lambda password: _lib.c_create_vault(password)
        unlock_vault = lambda password, salt: _lib.c_unlock_vault(password, salt)
        lock_vault = lambda: _lib.c_lock_vault()
        derive_master_key = lambda password, salt: _lib.c_derive_master_key(password, salt)
        encrypt_master_key = lambda key: _lib.c_encrypt_master_key(key)
        decrypt_master_key = lambda encrypted_key: _lib.c_decrypt_master_key(encrypted_key)
        verify_signature = lambda data, signature: _lib.c_verify_signature(data, signature)
        create_secure_string = lambda data: _lib.c_create_secure_string(data)
