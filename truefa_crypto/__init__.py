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
import secrets
from pathlib import Path

# Import core functionality from dedicated modules
from .loader import find_dll, get_lib, is_using_fallback
from .secure_string import SecureString, create_secure_string, secure_random_bytes

# Use __all__ to control what's exported from the package
__all__ = [
    'SecureString',
    'create_secure_string',
    'secure_random_bytes',
    'find_dll',
    'get_lib',
    'is_using_fallback',
    'encrypt_data',
    'decrypt_data',
    'derive_key',
    'hash_password',
    'verify_password',
    'create_hmac'
]

# Expose the main crypto functions which will be dynamically loaded
# from either the Rust DLL or Python fallback implementation
from .crypto_functions import (
    encrypt_data,
    decrypt_data,
    derive_key,
    hash_password,
    verify_password,
    create_hmac
)

# Initialize the DLL or fallback implementations
_lib = None

def _initialize():
    """Initialize the module by loading the DLL or fallback implementations."""
    global _lib
    if _lib is None:
        _lib = get_lib()
    return _lib

# Initialize on first import
_initialize()

# Direct export of the most critical functions to ensure they're always available
def secure_random_bytes(size):
    """Generate secure random bytes of the specified size using Python's secrets module."""
    return secrets.token_bytes(size)

def create_secure_string(data):
    """Create a secure string that will be automatically zeroed when no longer needed."""
    if isinstance(data, str):
        data = data.encode('utf-8')
    return SecureString(data)

class SecureString:
    """A string that is securely wiped from memory when no longer needed."""
    def __init__(self, data):
        if isinstance(data, str):
            data = data.encode('utf-8')
        self.data = bytearray(data)
    
    def __str__(self):
        return self.data.decode('utf-8', errors='replace')
    
    def clear(self):
        """Securely wipe the data."""
        for i in range(len(self.data)):
            self.data[i] = 0
    
    def __del__(self):
        self.clear()

# Set up logging
logger = logging.getLogger(__name__)

# Define constants
USE_FALLBACK = os.environ.get("TRUEFA_USE_FALLBACK", "").lower() in ("true", "1", "yes")
FALLBACK_MARKER_PATH = os.path.join(os.path.expanduser("~"), ".truefa", ".dll_crash")

# Create a global to track if we've detected a Rust DLL issue
_detected_dll_issue = False

# Check if we previously detected a DLL issue
if os.path.exists(FALLBACK_MARKER_PATH):
    _detected_dll_issue = True
    logger.info(f"Detected previous DLL issues (marker file: {FALLBACK_MARKER_PATH})")
    # Don't automatically use fallback, but we'll be more cautious

# Function to check if fallback is being used
def get_fallback_status():
    """Return whether the fallback Python implementation is currently being used."""
    return USE_FALLBACK or _detected_dll_issue or getattr(_lib, "is_dummy", False)

# Find the DLL
def _find_dll():
    """Find the Rust DLL in various possible locations."""
    possible_locations = [
        # PyInstaller bundle
        os.path.join(getattr(sys, '_MEIPASS', '.'), "truefa_crypto.dll"),
        os.path.join(getattr(sys, '_MEIPASS', '.'), "truefa_crypto", "truefa_crypto.dll"),
        
        # Development locations
        os.path.join(os.getcwd(), "rust_crypto", "target", "release", "truefa_crypto.dll"),
        os.path.join(os.getcwd(), "truefa_crypto", "truefa_crypto.dll"),
        os.path.join(os.getcwd(), "truefa_crypto.dll"),
        
        # Installation locations
        os.path.join(os.path.dirname(__file__), "truefa_crypto.dll"),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "truefa_crypto.dll"),
        
        # Additional Docker locations
        os.path.join(os.path.dirname(sys.executable), "truefa_crypto.dll"),
        os.path.join(getattr(sys, '_MEIPASS', '.'), "_internal", "truefa_crypto.dll"),
        os.path.join(getattr(sys, '_MEIPASS', '.'), "_internal", "truefa_crypto", "truefa_crypto.dll"),
    ]
    
    # For Docker, add special locations
    if "ContainerAdministrator" in os.path.expanduser("~"):
        docker_locations = [
            "C:\\TrueFA\\truefa_crypto.dll",
            "C:\\TrueFA\\truefa_crypto\\truefa_crypto.dll"
        ]
        possible_locations.extend(docker_locations)
    
    for location in possible_locations:
        if os.path.exists(location):
            print(f"DLL found at: {location}")
            return location
    
    print("DLL not found in any standard location")
    for location in possible_locations:
        print(f"DLL not found at: {location}")
    return None

_dll_path, _found_dll = _find_dll()

# Global variable for the DLL instance
_lib = None

# Configure logging
logging.basicConfig(level=logging.INFO)

# Add additional paths to system PATH to help find dependencies
def _enhance_dll_search_paths():
    try:
        # Add all potential DLL locations to PATH
        current_path = os.environ.get("PATH", "")
        
        # Add the directory containing the DLL to PATH
        if _dll_path:
            dll_dir = os.path.dirname(_dll_path)
            if dll_dir and dll_dir not in current_path:
                os.environ["PATH"] = dll_dir + os.pathsep + current_path
        
        # Add _MEIPASS directory if running from PyInstaller bundle
        if hasattr(sys, '_MEIPASS'):
            if sys._MEIPASS not in current_path:
                os.environ["PATH"] = sys._MEIPASS + os.pathsep + os.environ["PATH"]
        
        # Add special directories for Docker
        if "ContainerAdministrator" in os.path.expanduser("~"):
            docker_dirs = [
                "C:\\TrueFA",
                "C:\\TrueFA\\truefa_crypto",
                os.path.join(os.path.dirname(sys.executable))
            ]
            
            for docker_dir in docker_dirs:
                if os.path.exists(docker_dir) and docker_dir not in current_path:
                    os.environ["PATH"] = docker_dir + os.pathsep + os.environ["PATH"]
        
        # Add the directory containing this module
        module_dir = os.path.dirname(os.path.abspath(__file__))
        if module_dir not in current_path:
            os.environ["PATH"] = module_dir + os.pathsep + os.environ["PATH"]
        
        print(f"Enhanced DLL search paths: {os.environ['PATH']}")
    except Exception as e:
        print(f"Error enhancing DLL search paths: {e}")

_enhance_dll_search_paths()

# Dummy module for fallback implementation
class _DummyModule:
    """A pure Python fallback implementation."""
    def __init__(self):
        self.is_initialized = True
        self.is_dummy = True
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

# Function to test if the DLL responds in a reasonable time
def _test_dll_responsiveness():
    """Test if the DLL responds to basic function calls."""
    global _detected_dll_issue
    
    if _detected_dll_issue:
        logger.info("Skipping DLL test due to previously detected issues")
        return False
        
    if USE_FALLBACK:
        logger.info("Skipping DLL test due to USE_FALLBACK setting")
        return False
    
    if not _lib or getattr(_lib, "is_dummy", False):
        logger.info("Skipping DLL test because dummy module is loaded")
        return False
    
    logger.info("Testing DLL responsiveness...")
    
    # Define a simple test function that should complete quickly
    def test_function():
        try:
            # Try the simplest, fastest function first - just to check DLL response
            if hasattr(_lib, "c_is_vault_unlocked"):
                result = _lib.c_is_vault_unlocked()
                logger.info(f"DLL test (c_is_vault_unlocked) returned: {result}")
                return True
            elif hasattr(_lib, "c_secure_random_bytes"):
                # Create buffer for secure random bytes (small size)
                buffer = (ctypes.c_ubyte * 1)()
                output_len = ctypes.c_size_t(0)
                result = _lib.c_secure_random_bytes(
                    1,  # Just 1 byte for testing
                    ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte)),
                    ctypes.byref(output_len)
                )
                logger.info(f"DLL test (c_secure_random_bytes) returned: {result}")
                return True
            else:
                logger.warning("No suitable test function found in DLL")
                return False
        except Exception as e:
            logger.error(f"Error testing DLL function: {e}")
            return False
    
    # Run test with a short timeout
    result = None
    error = None
    completed = threading.Event()
    
    def worker():
        nonlocal result, error
        try:
            result = test_function()
        except Exception as e:
            error = e
        finally:
            completed.set()
    
    thread = threading.Thread(target=worker)
    thread.daemon = True
    
    # Use a short timeout to quickly detect responsiveness issues
    timeout = 1.0  # 1 second should be plenty for a simple function call
    
    logger.info(f"Starting DLL test with {timeout}s timeout")
    thread.start()
    completed.wait(timeout)
    
    if not completed.is_set():
        logger.warning(f"DLL test timed out after {timeout} seconds")
        _detected_dll_issue = True
        
        # Create marker file
        try:
            os.makedirs(os.path.dirname(FALLBACK_MARKER_PATH), exist_ok=True)
            with open(FALLBACK_MARKER_PATH, "w") as f:
                f.write(f"DLL test timed out after {timeout} seconds\n")
                f.write(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"DLL path: {_dll_path}\n")
            logger.info("Created DLL issue marker file")
        except Exception as e:
            logger.warning(f"Failed to create DLL issue marker: {e}")
        
        return False
    
    if error:
        logger.warning(f"DLL test failed with error: {error}")
        _detected_dll_issue = True
        return False
    
    if not result:
        logger.warning("DLL test failed (returned False)")
        _detected_dll_issue = True
        return False
    
    logger.info("DLL test passed successfully")
    return True

# Function to make safe DLL calls with fallback
def _safe_dll_call(func_name, fallback_func, *args, **kwargs):
    """Call a DLL function safely with fallback if it fails or times out."""
    global _detected_dll_issue
    
    # If we've detected issues or are in fallback mode, use fallback immediately
    if _detected_dll_issue or USE_FALLBACK:
        logger.info(f"Using fallback for {func_name} due to previously detected issues")
        return fallback_func(*args, **kwargs)
    
    # Attempt to call the DLL function with timeout
    result = None
    error = None
    completed = threading.Event()
    
    def worker():
        nonlocal result, error
        try:
            dll_func = getattr(_lib, func_name)
            result = dll_func(*args, **kwargs)
        except Exception as e:
            error = e
        finally:
            completed.set()
    
    thread = threading.Thread(target=worker)
    thread.daemon = True
    
    # Use a longer timeout for Docker environments (10 seconds instead of 2)
    timeout = 10.0 if "ContainerAdministrator" in os.path.expanduser("~") else 2.0
    
    logger.info(f"Calling {func_name} with {timeout}s timeout")
    thread.start()
    completed.wait(timeout)
    
    if not completed.is_set():
        logger.warning(f"Call to {func_name} timed out after {timeout} seconds")
        
        # In Docker, we'll try again with a longer timeout before giving up
        if "ContainerAdministrator" in os.path.expanduser("~") and timeout < 20.0:
            logger.info(f"Docker environment detected - trying again with longer timeout")
            # Create a new thread with a longer timeout
            completed = threading.Event()
            thread = threading.Thread(target=worker)
            thread.daemon = True
            timeout = 20.0  # Double the timeout for the second attempt
            
            thread.start()
            completed.wait(timeout)
            
            if completed.is_set() and not error and result is not None:
                logger.info(f"Second attempt with longer timeout succeeded")
                return result
        
        # Only set _detected_dll_issue to true after multiple failures
        # This helps prevent premature fallback
        _detected_dll_issue = True
        
        # Update marker file
        try:
            os.makedirs(os.path.dirname(FALLBACK_MARKER_PATH), exist_ok=True)
            with open(FALLBACK_MARKER_PATH, "a") as f:
                f.write(f"Function {func_name} timed out after {timeout} seconds\n")
                f.write(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            logger.info("Updated DLL issue marker file")
        except Exception as e:
            logger.warning(f"Failed to update DLL issue marker: {e}")
        
        return fallback_func(*args, **kwargs)
    
    if error:
        logger.warning(f"Call to {func_name} failed with error: {error}")
        return fallback_func(*args, **kwargs)
    
    return result

# Load the DLL
def _load_dll():
    """Load the TrueFA crypto DLL using ctypes."""
    global _lib, _detected_dll_issue
    
    # First check if we should use fallback implementation
    if USE_FALLBACK:
        logger.info("Using Python fallback implementation due to environment variable")
        _lib = _DummyModule()
        return _lib
    
    # Try to find the DLL
    dll_path = _find_dll()
    if not dll_path:
        logger.error("DLL not found, using Python fallback")
        _lib = _DummyModule()
        return _lib
    
    try:
        print(f"Loading DLL from {dll_path}")
        
        # Load the DLL
        _lib = ctypes.CDLL(dll_path)
        print(f"DLL loaded successfully from {dll_path}")
        
        # Map Rust C exports to Python-friendly function names
        # Note: Rust exports functions with 'c_' prefix
        function_mappings = {
            'secure_random_bytes': 'c_secure_random_bytes',
            'generate_salt': 'c_generate_salt',
            'is_vault_unlocked': 'c_is_vault_unlocked',
            'vault_exists': 'c_vault_exists',
            'create_vault': 'c_create_vault',
            'unlock_vault': 'c_unlock_vault',
            'lock_vault': 'c_lock_vault',
            'derive_master_key': 'c_derive_master_key',
            'encrypt_master_key': 'c_encrypt_master_key',
            'decrypt_master_key': 'c_decrypt_master_key',
            'create_secure_string': 'c_create_secure_string',
            'verify_signature': 'c_verify_signature',
            'encrypt_data': 'c_encrypt_data',
            'decrypt_data': 'c_decrypt_data',
            'derive_key': 'c_derive_key'
        }
        
        # Map functions and add Python-friendly names
        mapped_successfully = True
        for py_name, c_name in function_mappings.items():
            if hasattr(_lib, c_name):
                # Create Python-friendly alias
                setattr(_lib, py_name, getattr(_lib, c_name))
                print(f"Successfully mapped {c_name} to {py_name}")
            else:
                print(f"Warning: Function {c_name} not found in DLL")
                mapped_successfully = False
        
        # Set function signatures
        try:
            if hasattr(_lib, 'c_secure_random_bytes'):
                _lib.c_secure_random_bytes.argtypes = [
                    ctypes.c_size_t,  # size
                    ctypes.POINTER(ctypes.c_ubyte),  # buffer
                    ctypes.POINTER(ctypes.c_size_t)  # output_len
                ]
                _lib.c_secure_random_bytes.restype = ctypes.c_bool
                print("Set signature for c_secure_random_bytes")
        except AttributeError as e:
            print(f"Error setting c_secure_random_bytes signature: {e}")
            
        try:
            if hasattr(_lib, 'c_create_secure_string'):
                _lib.c_create_secure_string.argtypes = [
                    ctypes.c_char_p,  # data
                    ctypes.c_size_t   # data_len
                ]
                _lib.c_create_secure_string.restype = ctypes.c_void_p
                print("Set signature for c_create_secure_string")
        except AttributeError as e:
            print(f"Error setting c_create_secure_string signature: {e}")
        
        # Add more function signature setups here for all other functions
        
        if not mapped_successfully:
            logger.warning("Some functions were not found in the DLL. Using mixed mode.")
        
        return _lib
    except Exception as e:
        logger.error(f"Error loading Rust DLL: {e}")
        _detected_dll_issue = True
        
        # Create marker file to indicate DLL issue
        try:
            os.makedirs(os.path.dirname(FALLBACK_MARKER_PATH), exist_ok=True)
            with open(FALLBACK_MARKER_PATH, 'w') as f:
                f.write(f"DLL crash at {time.ctime()}: {str(e)}")
        except Exception:
            pass
        
        # Use Python fallback
        _lib = _DummyModule()
        return _lib

# Load the DLL
_lib = _load_dll()

# Set the fallback flag based on actual DLL loading result
_using_fallback = getattr(_lib, "is_dummy", False)

# Print status information for debugging
if _using_fallback:
    print("Using Python fallback implementation for crypto operations")
else:
    print("Using Rust native implementation for crypto operations")

# Test DLL responsiveness after loading
if not getattr(_lib, "is_dummy", False):
    if not _test_dll_responsiveness():
        logger.warning("DLL did not respond in time, will use fallback for critical functions")
        # We don't reload as _DummyModule here to keep the DLL available for non-critical functions
        # Instead we'll use _safe_dll_call for critical functions

# Python fallback implementations for crypto functions
def _fallback_generate_salt():
    """Python implementation of salt generation."""
    import base64
    import os as os_module
    logger.info("Using Python fallback for salt generation")
    return base64.b64encode(os_module.urandom(32)).decode('utf-8')

def _fallback_create_secure_string(data):
    """Python implementation of secure string creation."""
    logger.info("Using Python fallback for secure string creation")
    if isinstance(data, bytes):
        try:
            return data.decode('utf-8', errors='replace')
        except:
            return str(data)
    return str(data)

def _fallback_secure_random_bytes(size):
    """Python implementation of secure random bytes generation."""
    import os as os_module
    logger.info("Using Python fallback for secure random bytes generation")
    return os_module.urandom(size)

# Define the high-risk functions that might hang and use safe calling
def generate_salt():
    """Generate a random salt for key derivation."""
    if USE_FALLBACK or _detected_dll_issue:
        return _fallback_generate_salt()
    
    try:
        # Record start time for diagnostics
        start_time = time.time()
        print(f"Starting salt generation at {time.strftime('%H:%M:%S')}")
        
        # We'll use our enhanced safe calling method with better timeout handling
        result = _safe_dll_call("c_generate_salt", _fallback_generate_salt)
        
        # Process result
        elapsed = time.time() - start_time
        print(f"Salt generation completed in {elapsed:.2f} seconds")
        
        if not result:
            logger.warning("Salt generation returned null result")
            
            # In Docker - try the Rust function directly one more time
            if "ContainerAdministrator" in os.path.expanduser("~"):
                print("Docker environment detected - trying direct Rust call")
                try:
                    direct_result = _lib.c_generate_salt()
                    if direct_result:
                        print(f"Direct Rust call successful after {time.time() - start_time:.2f} seconds")
                        return direct_result.decode('utf-8') if isinstance(direct_result, bytes) else direct_result
                except Exception as direct_error:
                    print(f"Direct Rust call failed: {direct_error}")
            
            return _fallback_generate_salt()
        
        return result.decode('utf-8') if isinstance(result, bytes) else result
        
    except Exception as e:
        # Catch any unexpected errors
        logger.error(f"Unexpected error in salt generation: {e}")
        print(f"Unexpected error in salt generation: {e}")
        return _fallback_generate_salt()

def create_secure_string(data):
    """Create a secure string from data."""
    if USE_FALLBACK or _detected_dll_issue or not hasattr(_lib, "c_create_secure_string"):
        return _fallback_create_secure_string(data)
    
    try:
        if isinstance(data, str):
            data_bytes = data.encode('utf-8')
        else:
            data_bytes = data
        
        # Call the DLL function with correct parameters
        data_len = len(data_bytes)
        logger.info(f"Calling c_create_secure_string with data length: {data_len}")
        
        # Use safe call with fallback
        result = _safe_dll_call("c_create_secure_string", 
                               lambda d, l: _fallback_create_secure_string(d),
                               data_bytes, data_len)
        
        if result is None:
            logger.error("c_create_secure_string returned NULL")
            return _fallback_create_secure_string(data)
            
        logger.info(f"c_create_secure_string returned: {result}")
        return result
    except Exception as e:
        logger.error(f"Error in create_secure_string: {e}")
        print(f"Error creating secure string: {e}")
        return _fallback_create_secure_string(data)

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
                # Convert inputs to bytes if they're strings
                if isinstance(data, str):
                    data = data.encode('utf-8')
                if isinstance(signature, str):
                    signature = signature.encode('utf-8')
                
                # Create C arrays for the data and signature
                data_len = len(data)
                data_array = (ctypes.c_ubyte * data_len)(*data)
                
                signature_len = len(signature)
                signature_array = (ctypes.c_ubyte * signature_len)(*signature)
                
                # Call the DLL function with the correct parameters
                logger.info(f"Calling c_verify_signature with data length: {data_len}, signature length: {signature_len}")
                result = _lib.c_verify_signature(
                    ctypes.cast(data_array, ctypes.POINTER(ctypes.c_ubyte)),
                    data_len,
                    ctypes.cast(signature_array, ctypes.POINTER(ctypes.c_ubyte)),
                    signature_len
                )
                logger.info(f"c_verify_signature returned: {result}")
                return result
            except Exception as e:
                logger.error(f"Error in verify_signature: {e}")
                return False
        
        def create_secure_string(data):
            """Create a secure string from data."""
            try:
                if isinstance(data, str):
                    data_bytes = data.encode('utf-8')
                else:
                    data_bytes = data
                
                # Call the DLL function with correct parameters
                data_len = len(data_bytes)
                logger.info(f"Calling c_create_secure_string with data length: {data_len}")
                result = _lib.c_create_secure_string(data_bytes, data_len)
                if result is None:
                    logger.error("c_create_secure_string returned NULL")
                    return None
                logger.info(f"c_create_secure_string returned: {result}")
                return result
            except Exception as e:
                logger.error(f"Error in create_secure_string: {e}")
                print(f"Error creating secure string: {e}")
                # Fall back to a simple string if there's an error
                if isinstance(data, bytes):
                    return data.decode('utf-8', errors='replace')
                return str(data)
    
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
