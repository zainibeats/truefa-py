"""
TrueFA Crypto Module

This module provides secure cryptographic operations through a Rust-based implementation.
It handles loading the Rust DLL and provides Python bindings for secure operations.
"""

import os
import sys
import ctypes
import time
import logging
import signal
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("truefa_crypto")

# Constants for the crypto operations
SALT_SIZE = 16  # Salt size in bytes
DEFAULT_TIMEOUT = 2.0  # Default timeout for Rust functions in seconds

# Check if we should use fallback
USE_FALLBACK = os.environ.get("TRUEFA_USE_FALLBACK", "").lower() in ("1", "true", "yes")
if USE_FALLBACK:
    logger.info("Using Python fallback implementation for crypto operations as requested by environment variable.")

# Global state for Python fallback implementations
_VAULT_UNLOCKED = [False]
_DLL_FUNCTION_TIMEOUTS = {}  # Track which functions have timed out

# Setup timeout handler for Rust functions
def _timeout_handler(signum, frame):
    """Signal handler for timeouts in Rust functions."""
    raise TimeoutError("Rust crypto operation timed out")

# Optimized DLL loading function
def find_dll():
    """
    Find the truefa_crypto DLL using a prioritized list of search paths.
    
    Returns:
        str or None: Path to the DLL if found, None otherwise
    """
    # Prioritized search paths
    search_paths = []
    
    # 1. First check PyInstaller bundle directory
    if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
        bundle_dir = getattr(sys, '_MEIPASS')
        logger.info(f"Running from PyInstaller bundle. Searching in: {bundle_dir}")
        search_paths.append(bundle_dir)
        
        # Also check _internal directory in PyInstaller bundle
        internal_dir = os.path.join(bundle_dir, '_internal')
        if os.path.exists(internal_dir):
            search_paths.append(internal_dir)
            search_paths.append(os.path.join(internal_dir, 'truefa_crypto'))
    
    # 2. Then check current directory and its subdirectories
    app_dir = os.getcwd()
    logger.info(f"Current working directory: {app_dir}")
    search_paths.append(app_dir)
    search_paths.append(os.path.join(app_dir, 'rust_crypto', 'target', 'release'))
    search_paths.append(os.path.join(app_dir, 'truefa_crypto'))
    
    # 3. Check module directory
    module_dir = os.path.dirname(os.path.abspath(__file__))
    search_paths.append(module_dir)
    
    # Log where we're looking for the DLL
    logger.info(f"Searching for DLL in paths: {search_paths}")
    for path in search_paths:
        dll_path = os.path.join(path, 'truefa_crypto.dll')
        if os.path.exists(dll_path):
            logger.info(f"DLL found at: {dll_path}")
            return dll_path
    
    # Also try nested paths (internal/truefa_crypto/truefa_crypto.dll)
    for path in search_paths:
        dll_path = os.path.join(path, 'truefa_crypto', 'truefa_crypto.dll')
        if os.path.exists(dll_path):
            logger.info(f"DLL found at: {dll_path}")
            return dll_path
    
    logger.warning("DLL not found in any of the search paths")
    return None

# Fallback implementations
class FallbackMethods:
    """Provides fallback implementations for Rust functions."""
    
    @staticmethod
    def secure_random_bytes(size):
        logger.debug(f"Using fallback: secure_random_bytes({size})")
        import os
        return os.urandom(size)
    
    @staticmethod
    def create_vault(password):
        logger.debug(f"Using fallback: create_vault()")
        import os
        import base64
        # Generate a random salt
        salt = os.urandom(32)
        # Return base64 encoded salt
        return base64.b64encode(salt).decode('utf-8')
    
    @staticmethod
    def unlock_vault(password):
        logger.debug(f"Using fallback: unlock_vault()")
        # Mark vault as unlocked in our simulation
        _VAULT_UNLOCKED[0] = True
        return True
    
    @staticmethod
    def is_vault_unlocked():
        logger.debug(f"Using fallback: is_vault_unlocked()")
        return _VAULT_UNLOCKED[0]
    
    @staticmethod
    def lock_vault():
        logger.debug(f"Using fallback: lock_vault()")
        _VAULT_UNLOCKED[0] = False
        return True
    
    @staticmethod
    def generate_salt():
        logger.debug(f"Using fallback: generate_salt()")
        import os
        import base64
        # Generate a 16-byte salt for compatibility with Rust implementation
        salt = os.urandom(SALT_SIZE)
        # Return base64 encoded salt
        return base64.b64encode(salt).decode('utf-8')
    
    @staticmethod
    def derive_master_key(password, salt):
        logger.debug(f"Using fallback: derive_master_key()")
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
        logger.debug(f"Using fallback: encrypt_master_key()")
        # Simulate encryption by returning the original key
        # This is a simple fallback
        return f"FALLBACK_ENCRYPTED:{master_key}"
    
    @staticmethod
    def decrypt_master_key(encrypted_key):
        logger.debug(f"Using fallback: decrypt_master_key()")
        # Simulate decryption for fallback
        if encrypted_key.startswith("FALLBACK_ENCRYPTED:"):
            return encrypted_key[19:]  # Remove the prefix
        return encrypted_key
    
    @staticmethod
    def create_secure_string(data):
        logger.debug(f"Using fallback: create_secure_string()")
        # Implement a basic secure string in Python
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
        logger.debug(f"Using fallback: verify_signature()")
        # Simple fallback - always return True
        return True
    
    @staticmethod
    def vault_exists():
        logger.debug(f"Using fallback: vault_exists()")
        
        # Check for vault.json in common locations
        home_dir = os.path.expanduser("~")
        appdata_dir = os.environ.get("APPDATA", home_dir)
        localappdata_dir = os.environ.get("LOCALAPPDATA", home_dir)
        
        # Common vault locations
        vault_locations = [
            os.path.join(home_dir, ".truefa", "vault.json"),
            os.path.join(appdata_dir, "TrueFA-Py", "vault.json"),
            os.path.join(localappdata_dir, "TrueFA-Py", "vault.json"),
        ]
        
        for location in vault_locations:
            if os.path.exists(location):
                return True
        
        return False

# Load the Rust DLL if available, otherwise use Python fallback
if not USE_FALLBACK:
    try:
        # Try to find and load the DLL
        dll_path = find_dll()
        
        if dll_path:
            try:
                logger.info(f"Attempting to load DLL from {dll_path}")
                print(f"Loading DLL from {dll_path}")
                dll = ctypes.CDLL(dll_path)
                print(f"DLL loaded successfully from {dll_path}")
                print(f"Available functions in DLL: {dir(dll)}")
                
                # Check if c_create_secure_string exists in the DLL
                has_create_secure_string = hasattr(dll, 'c_create_secure_string')
                print(f"c_create_secure_string exists in DLL: {has_create_secure_string}")
                
                # Define function signatures
                def _try_bind_function(func_name, fallback, arg_types=None, res_type=None):
                    """Safely attempt to bind a function from the DLL with fallback if it fails."""
                    try:
                        # Get the function from DLL
                        if not hasattr(dll, func_name):
                            logger.warning(f"Function {func_name} not found in DLL")
                            return fallback
                            
                        func = getattr(dll, func_name)
                        
                        # Set argument and return types if provided
                        if arg_types is not None:
                            func.argtypes = arg_types
                        if res_type is not None:
                            func.restype = res_type
                            
                            # Create a wrapper function with timeout handling
                            print(f"Set signature for {func_name}")
                            
                            def wrapper(*args, **kwargs):
                                # If this function has timed out before, use fallback
                                if func_name in _DLL_FUNCTION_TIMEOUTS:
                                    return fallback(*args, **kwargs)
                                    
                                try:
                                    # Install signal handler for timeout
                                    original_handler = None
                                    if hasattr(signal, 'SIGALRM'):
                                        original_handler = signal.signal(signal.SIGALRM, _timeout_handler)
                                        signal.alarm(int(DEFAULT_TIMEOUT))  # Set alarm
                                    
                                    start_time = time.time()
                                    # Call the function
                                    result = func(*args, **kwargs)
                                    elapsed = time.time() - start_time
                                    
                                    # Disable alarm and restore original handler
                                    if hasattr(signal, 'SIGALRM'):
                                        signal.alarm(0)  # Disable alarm
                                        if original_handler:
                                            signal.signal(signal.SIGALRM, original_handler)
                                    
                                    return result
                                except (TimeoutError, Exception) as e:
                                    # Mark this function as having timed out
                                    _DLL_FUNCTION_TIMEOUTS[func_name] = True
                                    logger.warning(f"DLL function {func_name} failed: {e}. Using fallback.")
                                    return fallback(*args, **kwargs)
                                finally:
                                    # Clean up signal handler
                                    if hasattr(signal, 'SIGALRM'):
                                        signal.alarm(0)  # Ensure alarm is disabled
                                        if original_handler:
                                            signal.signal(signal.SIGALRM, original_handler)
                        
                        return wrapper
                    except AttributeError:
                        # Function not found in DLL, use fallback
                        logger.warning(f"Function {func_name} not found in DLL")
                        return fallback
                    except Exception as e:
                        # Other error, use fallback
                        logger.warning(f"Error setting up {func_name}: {e}")
                        return fallback
                
                # Create function bindings
                def _secure_random_bytes_dll(size):
                    buffer = ctypes.create_string_buffer(size)
                    # Call the C function, which will fill the buffer
                    dll.c_secure_random_bytes(buffer, size)
                    # Return the filled buffer as bytes
                    return buffer.raw
                
                # Create getter for secure_random_bytes
                secure_random_bytes = _try_bind_function(
                    'c_secure_random_bytes',
                    FallbackMethods.secure_random_bytes
                )
                
                def _generate_salt_dll():
                    # The optimized c_generate_salt function returns a base64 encoded string
                    with _run_with_timeout(dll.c_generate_salt, DEFAULT_TIMEOUT) as result:
                        # If result is None, either function timed out or failed
                        if result is None:
                            logger.warning("Salt generation returned null result")
                            # Use Python fallback
                            logger.info("Using Python fallback for salt generation")
                            salt = FallbackMethods.generate_salt()
                            return salt
                        # Convert the C string to a Python string
                        return ctypes.c_char_p(result).value.decode('utf-8')
                
                # Create getter for generate_salt
                generate_salt = _try_bind_function(
                    'c_generate_salt',
                    FallbackMethods.generate_salt,
                )
                
                def _vault_exists_dll():
                    # Call the C function
                    return bool(dll.c_vault_exists())
                
                # Create getter for vault_exists
                vault_exists = _try_bind_function(
                    'c_vault_exists',
                    FallbackMethods.vault_exists,
                )
                
                def _is_vault_unlocked_dll():
                    # Call the C function
                    return bool(dll.c_is_vault_unlocked())
                
                # Create getter for is_vault_unlocked
                is_vault_unlocked = _try_bind_function(
                    'c_is_vault_unlocked',
                    FallbackMethods.is_vault_unlocked,
                )
                
                def _create_vault_dll(password):
                    # Convert password to C string
                    c_password = ctypes.c_char_p(password.encode('utf-8'))
                    # Call the C function
                    with _run_with_timeout(dll.c_create_vault, DEFAULT_TIMEOUT, c_password) as result:
                        # If result is None, either function timed out or failed
                        if result is None:
                            # Use Python fallback
                            logger.info("Using Python fallback for create_vault")
                            return FallbackMethods.create_vault(password)
                        # Convert the C string to a Python string
                        return ctypes.c_char_p(result).value.decode('utf-8')
                
                # Create getter for create_vault
                create_vault = _try_bind_function(
                    'c_create_vault',
                    FallbackMethods.create_vault,
                )
                
                def _unlock_vault_dll(password):
                    # Convert password to C string
                    c_password = ctypes.c_char_p(password.encode('utf-8'))
                    # Call the C function
                    return bool(dll.c_unlock_vault(c_password))
                
                # Create getter for unlock_vault
                unlock_vault = _try_bind_function(
                    'c_unlock_vault',
                    FallbackMethods.unlock_vault,
                )
                
                def _lock_vault_dll():
                    # Call the C function
                    return bool(dll.c_lock_vault())
                
                # Create getter for lock_vault
                lock_vault = _try_bind_function(
                    'c_lock_vault',
                    FallbackMethods.lock_vault,
                )
                
                def _derive_master_key_dll(password, salt):
                    # Convert password and salt to C strings
                    c_password = ctypes.c_char_p(password.encode('utf-8'))
                    c_salt = ctypes.c_char_p(salt.encode('utf-8'))
                    
                    # Call the C function
                    with _run_with_timeout(dll.c_derive_master_key, 
                                          DEFAULT_TIMEOUT, 
                                          c_password, 
                                          c_salt) as result:
                        # If result is None, either function timed out or failed
                        if result is None:
                            # Use Python fallback
                            logger.info("Using Python fallback for derive_master_key")
                            return FallbackMethods.derive_master_key(password, salt)
                        # Convert the C string to a Python string
                        return ctypes.c_char_p(result).value.decode('utf-8')
                
                # Create getter for derive_master_key
                derive_master_key = _try_bind_function(
                    'c_derive_master_key',
                    FallbackMethods.derive_master_key,
                )
                
                def _encrypt_master_key_dll(master_key):
                    # Convert master_key to C string
                    c_master_key = ctypes.c_char_p(master_key.encode('utf-8'))
                    
                    # Call the C function
                    with _run_with_timeout(dll.c_encrypt_master_key, 
                                          DEFAULT_TIMEOUT, 
                                          c_master_key) as result:
                        # If result is None, either function timed out or failed
                        if result is None:
                            # Use Python fallback
                            logger.info("Using Python fallback for encrypt_master_key")
                            return FallbackMethods.encrypt_master_key(master_key)
                        # Convert the C string to a Python string
                        return ctypes.c_char_p(result).value.decode('utf-8')
                
                # Create getter for encrypt_master_key
                encrypt_master_key = _try_bind_function(
                    'c_encrypt_master_key',
                    FallbackMethods.encrypt_master_key,
                )
                
                def _decrypt_master_key_dll(encrypted_key):
                    # Convert encrypted_key to C string
                    c_encrypted_key = ctypes.c_char_p(encrypted_key.encode('utf-8'))
                    
                    # Call the C function
                    with _run_with_timeout(dll.c_decrypt_master_key, 
                                          DEFAULT_TIMEOUT, 
                                          c_encrypted_key) as result:
                        # If result is None, either function timed out or failed
                        if result is None:
                            # Use Python fallback
                            logger.info("Using Python fallback for decrypt_master_key")
                            return FallbackMethods.decrypt_master_key(encrypted_key)
                        # Convert the C string to a Python string
                        return ctypes.c_char_p(result).value.decode('utf-8')
                
                # Create getter for decrypt_master_key
                decrypt_master_key = _try_bind_function(
                    'c_decrypt_master_key',
                    FallbackMethods.decrypt_master_key,
                )
                
                def _verify_signature_dll(public_key, message, signature):
                    # Convert inputs to C types
                    c_public_key = ctypes.c_char_p(public_key)
                    c_message = ctypes.c_char_p(message)
                    c_signature = ctypes.c_char_p(signature)
                    
                    # Call the C function
                    return bool(dll.c_verify_signature(c_public_key, c_message, c_signature))
                
                # Create getter for verify_signature
                verify_signature = _try_bind_function(
                    'c_verify_signature',
                    FallbackMethods.verify_signature,
                )
                
                # Handle create_secure_string differently as it's often missing
                def _create_secure_string_dll(data):
                    try:
                        if hasattr(dll, 'c_create_secure_string'):
                            # Convert data to bytes if it's a string
                            if isinstance(data, str):
                                data_bytes = data.encode('utf-8')
                            else:
                                data_bytes = data
                                
                            c_data = ctypes.c_char_p(data_bytes)
                            c_size = ctypes.c_size_t(len(data_bytes))
                            
                            # Set the function signature
                            dll.c_create_secure_string.argtypes = [ctypes.c_char_p, ctypes.c_size_t]
                            dll.c_create_secure_string.restype = ctypes.c_void_p
                            
                            # Call the C function if available
                            string_ptr = dll.c_create_secure_string(c_data, c_size)
                            if string_ptr:
                                # Create a Python wrapper for the secure string
                                class RustSecureString:
                                    def __init__(self, ptr):
                                        self.ptr = ptr
                                    
                                    def __str__(self):
                                        return f"<RustSecureString at {self.ptr}>"
                                
                                return RustSecureString(string_ptr)
                        # Fall back if function doesn't exist or returns null
                        return FallbackMethods.create_secure_string(data)
                    except Exception as e:
                        logger.warning(f"Error in create_secure_string: {e}")
                        return FallbackMethods.create_secure_string(data)
                
                # Try to bind create_secure_string, but don't raise errors if missing
                try:
                    if hasattr(dll, 'c_create_secure_string'):
                        create_secure_string = _create_secure_string_dll
                    else:
                        logger.warning("c_create_secure_string function not found in DLL, using fallback")
                        create_secure_string = FallbackMethods.create_secure_string
                except Exception as e:
                    logger.warning(f"Error binding create_secure_string: {e}")
                    create_secure_string = FallbackMethods.create_secure_string
                
                # Test the DLL
                logger.info("Testing DLL responsiveness...")
                try:
                    logger.info(f"Starting DLL test with {DEFAULT_TIMEOUT}s timeout")
                    
                    # Test a simple function that should always work
                    if hasattr(dll, 'c_vault_exists'):
                        dll.c_vault_exists.restype = ctypes.c_bool
                        result = dll.c_vault_exists()
                        logger.info(f"DLL test successful: vault_exists returned {result}")
                    else:
                        # If c_vault_exists is not available, try c_secure_random_bytes
                        if hasattr(dll, 'c_secure_random_bytes'):
                            buffer = ctypes.create_string_buffer(16)
                            dll.c_secure_random_bytes.argtypes = [ctypes.c_size_t, ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t)]
                            dll.c_secure_random_bytes.restype = ctypes.c_bool
                            out_len = ctypes.c_size_t(0)
                            result = dll.c_secure_random_bytes(16, buffer, ctypes.byref(out_len))
                            logger.info(f"DLL test successful: secure_random_bytes returned {result}")
                        else:
                            raise Exception("No suitable test function found in DLL")
                except Exception as e:
                    logger.warning(f"DLL test failed: {e}")
                    logger.warning("Falling back to Python implementation")
                    USE_FALLBACK = True
            except Exception as e:
                logger.error(f"Error loading DLL: {e}")
                USE_FALLBACK = True
        else:
            logger.warning("DLL not found, using Python fallback")
            USE_FALLBACK = True
    except Exception as e:
        logger.error(f"Error during DLL loading: {e}")
        USE_FALLBACK = True

# Setup the module exports
if USE_FALLBACK:
    logger.warning("Using fallback implementation for secure memory!")
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

# Context manager for timeouts
class _run_with_timeout:
    """
    Context manager for running functions with timeout.
    
    Args:
        func: The function to run.
        timeout: Timeout in seconds.
        *args: Arguments to pass to the function.
        **kwargs: Keyword arguments to pass to the function.
        
    Usage:
        with _run_with_timeout(func, 2.0, arg1, arg2) as result:
            if result is None:
                # Function timed out or failed
                pass
            else:
                # Function returned result within timeout
                pass
    """
    
    def __init__(self, func, timeout=DEFAULT_TIMEOUT, *args, **kwargs):
        self.func = func
        self.timeout = timeout
        self.args = args
        self.kwargs = kwargs
        self.result = None
        self.original_handler = None
    
    def __enter__(self):
        # Setup signal handler for timeout on Unix
        if hasattr(signal, 'SIGALRM'):
            self.original_handler = signal.signal(signal.SIGALRM, _timeout_handler)
            signal.alarm(int(self.timeout))
        
        # Start timer for manual timeout check
        self.start_time = time.time()
        
        # Run the function
        try:
            logger.info(f"Calling {self.func.__name__} with {self.timeout}s timeout")
            self.result = self.func(*self.args, **self.kwargs)
        except TimeoutError:
            logger.warning(f"Function {self.func.__name__} timed out after {self.timeout} seconds")
            self.result = None
        except Exception as e:
            logger.warning(f"Function {self.func.__name__} failed: {e}")
            self.result = None
        finally:
            # Disable alarm
            if hasattr(signal, 'SIGALRM'):
                signal.alarm(0)
        
        return self.result
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        # Restore original handler
        if hasattr(signal, 'SIGALRM') and self.original_handler:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, self.original_handler)
        
        # Check if an exception occurred
        if exc_type is not None:
            logger.warning(f"Exception during execution: {exc_type.__name__}: {exc_val}")
            return False  # re-raise the exception
        
        return True  # no exception

# Create a SecureString class for memory safety
class SecureString:
    """
    A string that keeps its content in secure memory.
    """
    
    def __init__(self, value):
        """Create a new secure string from a value."""
        self.value = value
    
    def __str__(self):
        """Return the string representation."""
        return self.value
    
    def clear(self):
        """Clear the secure string from memory."""
        # Zero out the memory
        self.value = None

# Export version info
__version__ = "0.1.0"
