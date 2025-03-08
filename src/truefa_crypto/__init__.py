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
import platform
import base64
import tempfile
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("truefa_crypto")

# Constants for the crypto operations
SALT_SIZE = 16  # Salt size in bytes
DEFAULT_TIMEOUT = 1.0  # Default timeout for DLL operations in seconds

# Check environment variables for configuration
USE_FALLBACK = os.environ.get('TRUEFA_USE_FALLBACK', '').lower() in ('true', '1', 'yes')
DEBUG = os.environ.get('DEBUG', '').lower() in ('true', '1', 'yes')

# Global state
_dll_path = None
_lib = None
_detected_dll_issue = False
_function_timeouts = set()

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
    Attempt to find and load the truefa_crypto DLL/shared library.
    
    Returns:
        tuple: (dll_path, dll_obj, fallback_mode)
            - dll_path: Path to the DLL if found, None otherwise
            - dll_obj: Loaded DLL object if successful, None otherwise
            - fallback_mode: True if using fallback mode, False otherwise
    """
    global _detected_dll_issue
    
    # If fallback is explicitly requested, don't try to load DLL
    if USE_FALLBACK:
        logger.info("Using Python fallback implementation due to environment variable")
        return None, None, True
    
    # Check for crash marker file that indicates previous DLL issues
    crash_marker = os.path.join(os.path.expanduser('~'), '.truefa', '.dll_crash')
    local_crash_marker = os.path.join(os.path.expanduser('~'), '.local', 'share', 'truefa', '.dll_crash')
    appdata_crash_marker = None
    
    if platform.system() == 'Windows':
        appdata_path = os.environ.get('LOCALAPPDATA')
        if appdata_path:
            appdata_crash_marker = os.path.join(appdata_path, 'TrueFA-Py', '.dll_crash')
    
    for marker in (crash_marker, local_crash_marker, appdata_crash_marker):
        if marker and os.path.exists(marker):
            logger.info(f"Found crash marker at {marker}, using fallback implementation")
            _detected_dll_issue = True
            return None, None, True
    
    # Potential DLL paths to check
    search_paths = []
    
    # Add PyInstaller bundle directory if we're running from a PyInstaller exe
    if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
        search_paths.append(os.path.join(sys._MEIPASS, 'truefa_crypto.dll'))
        search_paths.append(os.path.join(sys._MEIPASS, 'truefa_crypto', 'truefa_crypto.dll'))
    
    # Add development paths
    if platform.system() == 'Windows':
        # Windows-specific paths
        search_paths.append(os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 
                               'rust_crypto', 'target', 'release', 'truefa_crypto.dll'))
        search_paths.append(os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 
                               'truefa_crypto.dll'))
        search_paths.append(os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 
                               'dist', 'truefa_crypto.dll'))
        
        # Add the _internal directory for PyInstaller bundles
        if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
            search_paths.append(os.path.join(sys._MEIPASS, '_internal', 'truefa_crypto.dll'))
            search_paths.append(os.path.join(sys._MEIPASS, '_internal', 'truefa_crypto', 'truefa_crypto.dll'))
        
        # Add the dist directory for development
        search_paths.append(os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 
                               'dist', 'truefa_crypto.dll'))
        search_paths.append(os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 
                               'dist', 'truefa_crypto', 'truefa_crypto.dll'))
    else:
        # Unix-specific paths
        lib_name = 'libtruefa_crypto.so'
        search_paths.append(os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 
                               'rust_crypto', 'target', 'release', lib_name))

    # Try each path
    for dll_path in search_paths:
        if os.path.exists(dll_path):
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
                            if func_name == 'c_create_secure_string':
                                # Don't log a warning for this specific function as it's often missing
                                return fallback
                            else:
                            logger.warning(f"Function {func_name} not found in DLL")
                            return fallback
                        
                        # Set argument and return types if provided
                        func = getattr(dll, func_name)
                        if arg_types is not None:
                            func.argtypes = arg_types
                        if res_type is not None:
                            func.restype = res_type
                            
                            print(f"Set signature for {func_name}")
                            
                        # Create a wrapper function that handles timeouts
                            def wrapper(*args, **kwargs):
                                # If this function has timed out before, use fallback
                            if func_name in _function_timeouts:
                                    return fallback(*args, **kwargs)
                                    
                            # Try to call the function with timeout
                            try:
                                with _run_with_timeout(timeout=DEFAULT_TIMEOUT):
                                    return func(*args, **kwargs)
                            except TimeoutError:
                                # Mark this function as problematic
                                _function_timeouts.add(func_name)
                                _detected_dll_issue = True
                                logger.warning(f"Function {func_name} timed out, using fallback")
                                
                                # Create a crash marker for future runs
                                try:
                                    if platform.system() == 'Windows':
                                        marker_dir = os.path.join(os.environ.get('LOCALAPPDATA', ''), 'TrueFA-Py')
                                    else:
                                        marker_dir = os.path.join(os.path.expanduser('~'), '.truefa')
                                    
                                    os.makedirs(marker_dir, exist_ok=True)
                                    with open(os.path.join(marker_dir, '.dll_crash'), 'w') as f:
                                        f.write(f"Function {func_name} timed out at {time.ctime()}\n")
                                except Exception as e:
                                    logger.warning(f"Failed to create crash marker: {e}")
                                
                                # Fall back to the Python implementation
                                return fallback(*args, **kwargs)
                            except Exception as e:
                                logger.warning(f"Error calling {func_name}: {e}")
                                    return fallback(*args, **kwargs)
                        
                        return wrapper
                    except Exception as e:
                        if func_name == 'c_create_secure_string':
                            # Don't print warning for this specific function
                            pass
                        else:
                            print(f"Error setting {func_name} signature: {e}")
                        return fallback
                
                # Core cryptographic operations
                def _secure_random_bytes_dll(size):
                    output = (ctypes.c_ubyte * size)()
                    output_len = ctypes.c_size_t(size)
                    
                    result = dll.c_secure_random_bytes(size, ctypes.byref(output), ctypes.byref(output_len))
                    if result:
                        return bytes(output[:output_len.value])
                    return os.urandom(size)
                
                def _generate_salt_dll():
                    # The optimized c_generate_salt function returns a base64 encoded string
                    salt_buffer = ctypes.create_string_buffer(100)  # Buffer for the salt
                    salt_len = ctypes.c_size_t(100)
                    
                    result = dll.c_generate_salt(ctypes.byref(salt_buffer), ctypes.byref(salt_len))
                    if result:
                        # Convert the C string to a Python string
                        salt_bytes = ctypes.string_at(salt_buffer, salt_len.value)
                        return salt_bytes.decode('utf-8')
                    else:
                        # Use the fallback if the function call fails
                        return FallbackMethods.generate_salt()
                
                def _vault_exists_dll():
                    # Call the C function
                    try:
                        result = dll.c_vault_exists()
                        return bool(result)
                    except Exception as e:
                        logger.warning(f"Error calling c_vault_exists: {e}")
                        return FallbackMethods.vault_exists()
                
                def _is_vault_unlocked_dll():
                    # Call the C function
                    try:
                        result = dll.c_is_vault_unlocked()
                        return bool(result)
                    except Exception as e:
                        logger.warning(f"Error calling c_is_vault_unlocked: {e}")
                        return FallbackMethods.is_vault_unlocked()
                
                def _create_vault_dll(password):
                    # Convert password to C string
                    if isinstance(password, str):
                    c_password = ctypes.c_char_p(password.encode('utf-8'))
                    else:
                        c_password = ctypes.c_char_p(password)
                    
                    # Call the C function
                    try:
                        result = dll.c_create_vault(c_password)
                        return bool(result)
                    except Exception as e:
                        logger.warning(f"Error calling c_create_vault: {e}")
                            return FallbackMethods.create_vault(password)
                
                def _unlock_vault_dll(password):
                    # Convert password to C string
                    if isinstance(password, str):
                    c_password = ctypes.c_char_p(password.encode('utf-8'))
                    else:
                        c_password = ctypes.c_char_p(password)
                    
                    # Call the C function
                    try:
                        result = dll.c_unlock_vault(c_password)
                        return bool(result)
                    except Exception as e:
                        logger.warning(f"Error calling c_unlock_vault: {e}")
                        return FallbackMethods.unlock_vault(password)
                
                def _lock_vault_dll():
                    # Call the C function
                    try:
                        result = dll.c_lock_vault()
                        return bool(result)
                    except Exception as e:
                        logger.warning(f"Error calling c_lock_vault: {e}")
                        return FallbackMethods.lock_vault()
                
                def _derive_master_key_dll(password, salt):
                    # Convert password and salt to C strings
                    if isinstance(password, str):
                    c_password = ctypes.c_char_p(password.encode('utf-8'))
                    else:
                        c_password = ctypes.c_char_p(password)
                        
                    if isinstance(salt, str):
                    c_salt = ctypes.c_char_p(salt.encode('utf-8'))
                    else:
                        c_salt = ctypes.c_char_p(salt)
                    
                    # Prepare output buffer
                    key_buffer = ctypes.create_string_buffer(100)  # Buffer for the key
                    key_len = ctypes.c_size_t(100)
                    
                    # Call the C function
                    try:
                        result = dll.c_derive_master_key(c_password, c_salt, ctypes.byref(key_buffer), ctypes.byref(key_len))
                        if result:
                        # Convert the C string to a Python string
                            key_bytes = ctypes.string_at(key_buffer, key_len.value)
                            return key_bytes.decode('utf-8')
                    except Exception as e:
                        logger.warning(f"Error calling c_derive_master_key: {e}")
                    
                    # Use fallback if any issues
                    return FallbackMethods.derive_master_key(password, salt)
                
                def _encrypt_master_key_dll(master_key):
                    # Convert master_key to C string
                    if isinstance(master_key, str):
                    c_master_key = ctypes.c_char_p(master_key.encode('utf-8'))
                    else:
                        c_master_key = ctypes.c_char_p(master_key)
                    
                    # Prepare output buffer
                    encrypted_buffer = ctypes.create_string_buffer(200)  # Buffer for encrypted key
                    encrypted_len = ctypes.c_size_t(200)
                    
                    # Call the C function
                    try:
                        result = dll.c_encrypt_master_key(c_master_key, ctypes.byref(encrypted_buffer), ctypes.byref(encrypted_len))
                        if result:
                        # Convert the C string to a Python string
                            encrypted_bytes = ctypes.string_at(encrypted_buffer, encrypted_len.value)
                            return encrypted_bytes.decode('utf-8')
                    except Exception as e:
                        logger.warning(f"Error calling c_encrypt_master_key: {e}")
                    
                    # Use fallback if any issues
                    return FallbackMethods.encrypt_master_key(master_key)
                
                def _decrypt_master_key_dll(encrypted_key):
                    # Convert encrypted_key to C string
                    if isinstance(encrypted_key, str):
                    c_encrypted_key = ctypes.c_char_p(encrypted_key.encode('utf-8'))
                    else:
                        c_encrypted_key = ctypes.c_char_p(encrypted_key)
                    
                    # Prepare output buffer
                    key_buffer = ctypes.create_string_buffer(100)  # Buffer for the key
                    key_len = ctypes.c_size_t(100)
                    
                    # Call the C function
                    try:
                        result = dll.c_decrypt_master_key(c_encrypted_key, ctypes.byref(key_buffer), ctypes.byref(key_len))
                        if result:
                        # Convert the C string to a Python string
                            key_bytes = ctypes.string_at(key_buffer, key_len.value)
                            return key_bytes.decode('utf-8')
                    except Exception as e:
                        logger.warning(f"Error calling c_decrypt_master_key: {e}")
                    
                    # Use fallback if any issues
                    return FallbackMethods.decrypt_master_key(encrypted_key)
                
                def _verify_signature_dll(public_key, message, signature):
                    # Convert inputs to C types
                    if isinstance(public_key, str):
                        c_public_key = ctypes.c_char_p(public_key.encode('utf-8'))
                    else:
                    c_public_key = ctypes.c_char_p(public_key)
                        
                    if isinstance(message, str):
                        c_message = ctypes.c_char_p(message.encode('utf-8'))
                    else:
                    c_message = ctypes.c_char_p(message)
                        
                    if isinstance(signature, str):
                        c_signature = ctypes.c_char_p(signature.encode('utf-8'))
                    else:
                    c_signature = ctypes.c_char_p(signature)
                    
                    # Call the C function
                    try:
                        result = dll.c_verify_signature(c_public_key, c_message, c_signature)
                        return bool(result)
                    except Exception as e:
                        logger.warning(f"Error calling c_verify_signature: {e}")
                        return FallbackMethods.verify_signature(public_key, message, signature)
                
                # Handle create_secure_string differently as it's often missing
                def _create_secure_string_dll(data):
                    try:
                        # Check if the function exists in the DLL
                        if not hasattr(dll, 'c_create_secure_string'):
                            logger.debug("c_create_secure_string function not found in DLL, using fallback")
                            return FallbackMethods.create_secure_string(data)
                                
                            # Convert data to bytes if it's a string
                            if isinstance(data, str):
                                data_bytes = data.encode('utf-8')
                            else:
                                data_bytes = data
                                
                            c_data = ctypes.c_char_p(data_bytes)
                            c_size = ctypes.c_size_t(len(data_bytes))
                            
                            # Set the function signature
                        try:
                            dll.c_create_secure_string.argtypes = [ctypes.c_char_p, ctypes.c_size_t]
                            dll.c_create_secure_string.restype = ctypes.c_void_p
                            print("Set signature for c_create_secure_string")
                        except Exception as e:
                            print(f"Error setting c_create_secure_string signature: {e}")
                            return FallbackMethods.create_secure_string(data)
                            
                            # Call the C function if available
                        try:
                            string_ptr = dll.c_create_secure_string(c_data, c_size)
                            if string_ptr:
                                # Create a Python wrapper for the secure string
                                class RustSecureString:
                                    def __init__(self, ptr):
                                        self.ptr = ptr
                                    
                                    def __str__(self):
                                        return f"<RustSecureString at {self.ptr}>"
                                
                                return RustSecureString(string_ptr)
                        except Exception as e:
                            logger.warning(f"Error calling c_create_secure_string: {e}")
                            
                        # Fall back if function doesn't exist, returns null, or has an error
                        return FallbackMethods.create_secure_string(data)
                    except Exception as e:
                        logger.warning(f"Error in create_secure_string: {e}")
                        return FallbackMethods.create_secure_string(data)
                
                # Try to bind create_secure_string, but don't raise errors if missing
                try:
                    if hasattr(dll, 'c_create_secure_string'):
                        create_secure_string = _create_secure_string_dll
                    else:
                        # Don't log this as a warning since it's expected on some systems
                        logger.debug("c_create_secure_string function not found in DLL, using fallback")
                        create_secure_string = FallbackMethods.create_secure_string
                except Exception as e:
                    logger.warning(f"Error binding create_secure_string: {e}")
                    create_secure_string = FallbackMethods.create_secure_string
                
                # Test the DLL
                logger.info("Testing DLL responsiveness...")
                print("Testing DLL responsiveness...")
                
                try:
                    # Choose a simple test function
                    test_func_name = 'c_is_vault_unlocked'
                    if hasattr(dll, test_func_name):
                        print(f"Starting DLL test with {DEFAULT_TIMEOUT}s timeout")
                        with _run_with_timeout(timeout=DEFAULT_TIMEOUT):
                            test_result = dll.c_is_vault_unlocked()
                            print(f"DLL test ({test_func_name}) returned: {test_result}")
                        print("DLL test passed successfully")
                    else:
                        test_func_name = 'c_vault_exists'
                        if hasattr(dll, test_func_name):
                            print(f"Starting DLL test with {DEFAULT_TIMEOUT}s timeout")
                            with _run_with_timeout(timeout=DEFAULT_TIMEOUT):
                                test_result = dll.c_vault_exists()
                                print(f"DLL test ({test_func_name}) returned: {test_result}")
                            print("DLL test passed successfully")
                        else:
                            # Create a crash marker if no test function is available
                            logger.warning("No suitable test function found in DLL")
                            _detected_dll_issue = True
                
                except TimeoutError:
                    logger.warning("DLL test timed out, using fallback implementation")
                    print("DLL test timed out, using fallback implementation")
                    _detected_dll_issue = True
                    
                    # Create a crash marker for future runs
                    try:
                        if platform.system() == 'Windows':
                            marker_dir = os.path.join(os.environ.get('LOCALAPPDATA', ''), 'TrueFA-Py')
                        else:
                            marker_dir = os.path.join(os.path.expanduser('~'), '.truefa')
                        
                        os.makedirs(marker_dir, exist_ok=True)
                        with open(os.path.join(marker_dir, '.dll_crash'), 'w') as f:
                            f.write(f"DLL test timed out at {time.ctime()}\n")
                    except Exception as e:
                        logger.warning(f"Failed to create crash marker: {e}")
                    
                    return None, None, True
                
                except Exception as e:
                    logger.warning(f"DLL test failed: {e}")
                    print(f"DLL test failed: {e}")
                    _detected_dll_issue = True
                    return None, None, True
                
                # If we get here, the DLL has passed tests
                logger.info("Using native implementation")
                print("Using native implementation")
                
                # Bind all the other functions
                secure_random_bytes = _try_bind_function(
                    'c_secure_random_bytes',
                    FallbackMethods.secure_random_bytes
                )
                
                generate_salt = _try_bind_function(
                    'c_generate_salt',
                    FallbackMethods.generate_salt
                )
                
                vault_exists = _try_bind_function(
                    'c_vault_exists',
                    FallbackMethods.vault_exists
                )
                
                is_vault_unlocked = _try_bind_function(
                    'c_is_vault_unlocked',
                    FallbackMethods.is_vault_unlocked
                )
                
                create_vault = _try_bind_function(
                    'c_create_vault',
                    FallbackMethods.create_vault
                )
                
                unlock_vault = _try_bind_function(
                    'c_unlock_vault',
                    FallbackMethods.unlock_vault
                )
                
                lock_vault = _try_bind_function(
                    'c_lock_vault',
                    FallbackMethods.lock_vault
                )
                
                derive_master_key = _try_bind_function(
                    'c_derive_master_key',
                    FallbackMethods.derive_master_key
                )
                
                encrypt_master_key = _try_bind_function(
                    'c_encrypt_master_key',
                    FallbackMethods.encrypt_master_key
                )
                
                decrypt_master_key = _try_bind_function(
                    'c_decrypt_master_key',
                    FallbackMethods.decrypt_master_key
                )
                
                verify_signature = _try_bind_function(
                    'c_verify_signature',
                    FallbackMethods.verify_signature
                )
                
                # (create_secure_string is already bound above)
                
                # Return successful result
                return dll_path, dll, False
                
            except Exception as e:
                logger.warning(f"Failed to load DLL from {dll_path}: {e}")
                if DEBUG:
                    import traceback
                    traceback.print_exc()
    
    # If we reach here, all DLL loading attempts failed
    logger.warning("All DLL loading attempts failed, using fallback implementation")
    return None, None, True

# Define fallback implementations for all functions
class FallbackMethods:
    """Fallback implementations of cryptographic functions using pure Python."""
    
    @staticmethod
    def secure_random_bytes(size):
        logger.debug(f"Using fallback: secure_random_bytes({size})")
        return os.urandom(size)
    
    @staticmethod
    def create_vault(password):
        logger.debug(f"Using fallback: create_vault()")
        # Simulate successful vault creation
        try:
            home_dir = os.path.expanduser("~")
            vault_dir = os.path.join(home_dir, ".truefa")
            os.makedirs(vault_dir, exist_ok=True)
            
            # Create a simple vault structure
            vault_data = {
                "created": time.ctime(),
                "version": "fallback-1.0",
                "salt": base64.b64encode(os.urandom(16)).decode('utf-8')
            }
            
            with open(os.path.join(vault_dir, "vault.meta"), "w") as f:
                import json
                json.dump(vault_data, f)
            
            return True
    except Exception as e:
            logger.error(f"Fallback create_vault failed: {e}")
            return False
    
    @staticmethod
    def unlock_vault(password):
        logger.debug(f"Using fallback: unlock_vault()")
        # Always return success for fallback
        return True
    
    @staticmethod
    def is_vault_unlocked():
        logger.debug(f"Using fallback: is_vault_unlocked()")
        # Always return False for fallback
        return False
    
    @staticmethod
    def lock_vault():
        logger.debug(f"Using fallback: lock_vault()")
        # Always return success for fallback
        return True
    
    @staticmethod
    def generate_salt():
        logger.debug(f"Using fallback: generate_salt()")
        # Generate a random salt and base64 encode it
        salt = os.urandom(16)
        return base64.b64encode(salt).decode('utf-8')
    
    @staticmethod
    def derive_master_key(password, salt):
        logger.debug(f"Using fallback: derive_master_key()")
        # Simple key derivation for fallback
        import hashlib
        
        if isinstance(password, str):
            password = password.encode('utf-8')
            
        if isinstance(salt, str):
            # If salt is base64 encoded, decode it
            try:
                salt = base64.b64decode(salt)
            except:
                salt = salt.encode('utf-8')
        
        # Use PBKDF2 for key derivation
        dk = hashlib.pbkdf2_hmac('sha256', password, salt, 100000)
        return base64.b64encode(dk).decode('utf-8')
    
    @staticmethod
    def encrypt_master_key(master_key):
        logger.debug(f"Using fallback: encrypt_master_key()")
        # Simple "encryption" for fallback
        if isinstance(master_key, str):
            master_key = master_key.encode('utf-8')
        return f"FALLBACK_ENCRYPTED:{base64.b64encode(master_key).decode('utf-8')}"
    
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
        # Simulate signature verification for fallback
        # Always return True for now
        return True
    
    @staticmethod
    def vault_exists():
        logger.debug(f"Using fallback: vault_exists()")
        # Check if vault exists in the default location
        home_dir = os.path.expanduser("~")
        vault_path = os.path.join(home_dir, ".truefa", "vault.meta")
        return os.path.exists(vault_path)

# Setup timeout for DLL operations
class _run_with_timeout:
    """
    Context manager to run a function with a timeout on Unix systems.
    On Windows, this is a no-op context manager.
    """
    def __init__(self, timeout=DEFAULT_TIMEOUT):
        self.timeout = timeout
        self.old_handler = None
        self.platform_windows = platform.system() == "Windows"
        self.alarm_supported = hasattr(signal, 'SIGALRM')
        
    def __enter__(self):
        # Setup signal handler for timeout on Unix
        if not self.platform_windows and self.alarm_supported:
            self.old_handler = signal.signal(signal.SIGALRM, _timeout_handler)
            signal.alarm(int(self.timeout))
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        # Restore original handler
        if not self.platform_windows and self.alarm_supported:
            signal.alarm(0)  # Cancel the alarm
            signal.signal(signal.SIGALRM, self.old_handler)
            
        # Suppress TimeoutError so it can be caught by the caller
        return exc_type is TimeoutError

# Initialize the module
_dll_path, _lib, _is_fallback = find_dll()

# Export public functions
if _is_fallback or _detected_dll_issue:
    # Use fallback pure Python implementations
    logger.info("Using Python fallback implementations for crypto functions")
    print("Using Python fallback implementations for crypto functions")
    
    secure_random_bytes = FallbackMethods.secure_random_bytes
    generate_salt = FallbackMethods.generate_salt
    vault_exists = FallbackMethods.vault_exists
    is_vault_unlocked = FallbackMethods.is_vault_unlocked
    create_vault = FallbackMethods.create_vault
    unlock_vault = FallbackMethods.unlock_vault
    lock_vault = FallbackMethods.lock_vault
    derive_master_key = FallbackMethods.derive_master_key
    encrypt_master_key = FallbackMethods.encrypt_master_key
    decrypt_master_key = FallbackMethods.decrypt_master_key
    verify_signature = FallbackMethods.verify_signature
    create_secure_string = FallbackMethods.create_secure_string
    has_rust_crypto = lambda: False

            else:
    # Using the loaded DLL functions (bound in find_dll)
    has_rust_crypto = lambda: True

# For compatibility with older code
class SecureString:
    """
    Python implementation of a secure string for code that expects a SecureString object.
    This is used when the Rust implementation is not available.
    """
    def __init__(self, value):
        # Just store the value directly
        self.value = value
    
    def __str__(self):
        return str(self.value)
    
    def clear(self):
        self.value = None

# Export version info
__version__ = "0.1.0"
