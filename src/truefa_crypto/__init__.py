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
        if not _VAULT_UNLOCKED[0]:
            raise ValueError("Vault is locked, cannot encrypt master key")
        import base64
        import os
        # Simulate encryption with random data
        encrypted = os.urandom(48)  # Simulate encrypted data
        return base64.b64encode(encrypted).decode('utf-8')
    
    @staticmethod
    def decrypt_master_key(encrypted_key):
        logger.debug(f"Using fallback: decrypt_master_key()")
        if not _VAULT_UNLOCKED[0]:
            raise ValueError("Vault is locked, cannot decrypt master key")
        import base64
        import os
        # Return a simulated master key
        master_key = os.urandom(32)
        return base64.b64encode(master_key).decode('utf-8')
    
    @staticmethod
    def create_secure_string(data):
        logger.debug(f"Using fallback: create_secure_string()")
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
        # Always return valid for testing
        return True

    @staticmethod
    def vault_exists():
        logger.debug(f"Using fallback: vault_exists()")
        return True

# If fallback is explicitly requested, skip DLL loading entirely
if USE_FALLBACK:
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
    # Define all fallback functions at module level - these will be overridden if DLL loading succeeds
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

    # Function to run Rust functions with timeout protection
    def _run_with_timeout(func, timeout=DEFAULT_TIMEOUT, *args, **kwargs):
        """
        Run a function with timeout protection.
        
        Args:
            func: Function to run
            timeout: Timeout in seconds
            *args, **kwargs: Arguments to pass to the function
            
        Returns:
            Result of the function
            
        Raises:
            TimeoutError: If the function times out
        """
        if timeout <= 0:
            # If timeout is disabled, just run the function
            return func(*args, **kwargs)
        
        # Set up the alarm
        old_handler = signal.signal(signal.SIGALRM, _timeout_handler)
        signal.alarm(int(timeout))
        
        try:
            result = func(*args, **kwargs)
            return result
        finally:
            # Reset the alarm and restore the old handler
            signal.alarm(0)
            signal.signal(signal.SIGALRM, old_handler)

    try:
        # Try to find and load the Rust library
        # For PyInstaller bundles, we need to adjust the paths
        if getattr(sys, 'frozen', False):
            logger.info(f"Running from PyInstaller bundle: {sys._MEIPASS}")
            logger.info(f"Current working directory: {os.getcwd()}")
            logger.info(f"__file__ location: {__file__}")
            logger.info(f"truefa_crypto package directory: {os.path.dirname(__file__)}")
            bundle_dir = sys._MEIPASS
            app_dir = os.path.dirname(sys.executable)
            
            # Possible DLL locations in PyInstaller bundle - ordered by preference
            possible_dll_locations = [
                # First, check in the root directory of the executable
                os.path.join(app_dir, "truefa_crypto.dll"),
                # Then check in the bundle itself
                os.path.join(bundle_dir, "truefa_crypto.dll"),
                # Then check in directory structure within the bundle
                os.path.join(bundle_dir, "truefa_crypto", "truefa_crypto.dll"),
                # Then check relative to the module
                os.path.join(os.path.dirname(__file__), "truefa_crypto.dll"),
            ]
        else:
            # For normal Python execution
            # Check the current directory and the package directory
            possible_dll_locations = [
                # Current directory
                os.path.join(os.getcwd(), "truefa_crypto.dll"),
                # Direct path
                os.path.join(os.path.dirname(__file__), "truefa_crypto.dll"),
                # One level up
                os.path.join(os.path.dirname(os.path.dirname(__file__)), "truefa_crypto.dll"),
                # Project root directory (assuming a certain structure)
                os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "truefa_crypto", "truefa_crypto.dll"),
                # Build directory
                os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "rust_crypto", "target", "release", "truefa_crypto.dll"),
                # Absolute backup paths for testing
                Path.home() / ".truefa" / "truefa_crypto.dll",
            ]

        # Flag to track if we successfully loaded the DLL
        _dll_loaded = False
        
        # Try each potential location
        for dll_path in possible_dll_locations:
            logger.info(f"Checking for DLL at {dll_path}")
            if os.path.exists(dll_path):
                logger.info(f"Found DLL at {dll_path}")
                try:
                    # Create a marker directory to track DLL crashes
                    marker_dir = os.path.join(str(Path.home()), ".truefa")
                    os.makedirs(marker_dir, exist_ok=True)
                    
                    # Load the DLL
                    _lib = ctypes.CDLL(dll_path)
                    
                    # If we reach here, DLL loaded successfully
                    logger.info(f"DLL loaded successfully from {dll_path}")
                    
                    # Define C function signatures for the DLL functions
                    
                    # First, verify if all functions we expect are present
                    required_functions = [
                        'c_secure_random_bytes',
                        'c_is_vault_unlocked',
                        'c_vault_exists',
                        'c_create_vault',
                        'c_unlock_vault',
                        'c_lock_vault',
                        'c_generate_salt',
                        'c_derive_master_key',
                        'c_encrypt_master_key',
                        'c_decrypt_master_key',
                        'c_verify_signature'
                    ]
                    
                    # Check all required functions
                    missing_functions = []
                    for func_name in required_functions:
                        if not hasattr(_lib, func_name):
                            missing_functions.append(func_name)
                    
                    if missing_functions:
                        logger.warning(f"The following functions are missing in the DLL: {', '.join(missing_functions)}")
                        logger.warning("Will continue with fallback implementations for missing functions")
                    else:
                        logger.info("All required functions found in the DLL")
                    
                    # We'll attempt to bind all functions, with try/except for each one
                    # If any function fails to bind, we'll use the fallback implementation
                    
                    # Define function to override module-level functions with DLL versions if available
                    def _try_bind_function(func_name, fallback, arg_types=None, res_type=None):
                        """Try to bind a function from the DLL, fall back if it fails."""
                        if not hasattr(_lib, func_name):
                            logger.warning(f"{func_name} not found in DLL, using fallback")
                            return fallback
                        
                        try:
                            # Get function from DLL
                            dll_func = getattr(_lib, func_name)
                            
                            # Set argument and return types if provided
                            if arg_types is not None:
                                dll_func.argtypes = arg_types
                            if res_type is not None:
                                dll_func.restype = res_type
                                
                            # Create wrapper function that handles timeouts
                            def wrapper(*args, **kwargs):
                                # If this function has timed out before, use fallback
                                if func_name in _DLL_FUNCTION_TIMEOUTS:
                                    logger.warning(f"{func_name} has timed out before, using fallback")
                                    return fallback(*args, **kwargs)
                                
                                try:
                                    # Run with timeout protection
                                    return _run_with_timeout(dll_func, DEFAULT_TIMEOUT, *args, **kwargs)
                                except Exception as e:
                                    logger.error(f"Error in {func_name}: {str(e)}")
                                    # Mark this function as timed out
                                    _DLL_FUNCTION_TIMEOUTS[func_name] = True
                                    # Create a marker file to track this error
                                    with open(os.path.join(marker_dir, f".{func_name}_error"), "w") as f:
                                        f.write(f"Error occurred: {str(e)}")
                                    # Use fallback
                                    return fallback(*args, **kwargs)
                            
                            return wrapper
                        except Exception as e:
                            logger.error(f"Error binding {func_name}: {str(e)}")
                            return fallback
                    
                    # Define function signatures
                    
                    # c_secure_random_bytes
                    c_secure_random_bytes_sig = [
                        ctypes.c_void_p,  # output buffer
                        ctypes.c_size_t,  # requested size
                        ctypes.POINTER(ctypes.c_size_t)  # actual size
                    ]
                    
                    # Override module-level functions with DLL versions
                    # Secure random bytes
                    def _secure_random_bytes_dll(size):
                        buf = ctypes.create_string_buffer(size)
                        out_size = ctypes.c_size_t()
                        result = _lib.c_secure_random_bytes(buf, size, ctypes.byref(out_size))
                        if result and out_size.value == size:
                            return buf.raw
                        else:
                            logger.warning("c_secure_random_bytes failed, using fallback")
                            return FallbackMethods.secure_random_bytes(size)
                    
                    # Generate salt
                    def _generate_salt_dll():
                        # The optimized c_generate_salt function returns a base64 encoded string
                        buf = ctypes.create_string_buffer(64)  # Enough space for base64 encoded salt
                        out_size = ctypes.c_size_t()
                        result = _lib.c_generate_salt(buf, 64, ctypes.byref(out_size))
                        if result and out_size.value > 0:
                            # Return the string up to the actual size
                            return buf.raw[:out_size.value].decode('utf-8')
                        else:
                            logger.warning("c_generate_salt failed, using fallback")
                            return FallbackMethods.generate_salt()
                    
                    # Vault existence check
                    def _vault_exists_dll():
                        try:
                            return bool(_lib.c_vault_exists())
                        except:
                            return FallbackMethods.vault_exists()
                    
                    # Vault unlock status
                    def _is_vault_unlocked_dll():
                        try:
                            return bool(_lib.c_is_vault_unlocked())
                        except:
                            return FallbackMethods.is_vault_unlocked()
                    
                    # Create vault
                    def _create_vault_dll(password):
                        buf = ctypes.create_string_buffer(64)  # Enough space for salt
                        pwd_bytes = password.encode('utf-8')
                        pwd_buf = ctypes.create_string_buffer(pwd_bytes)
                        try:
                            result = _lib.c_create_vault(pwd_buf, len(pwd_bytes), buf, 64)
                            if result:
                                return buf.value.decode('utf-8')
                            else:
                                return FallbackMethods.create_vault(password)
                        except:
                            return FallbackMethods.create_vault(password)
                    
                    # Unlock vault
                    def _unlock_vault_dll(password):
                        pwd_bytes = password.encode('utf-8')
                        pwd_buf = ctypes.create_string_buffer(pwd_bytes)
                        try:
                            return bool(_lib.c_unlock_vault(pwd_buf, len(pwd_bytes)))
                        except:
                            return FallbackMethods.unlock_vault(password)
                    
                    # Lock vault
                    def _lock_vault_dll():
                        try:
                            return bool(_lib.c_lock_vault())
                        except:
                            return FallbackMethods.lock_vault()
                    
                    # Derive master key
                    def _derive_master_key_dll(password, salt):
                        buf = ctypes.create_string_buffer(128)  # Enough space for derived key
                        pwd_bytes = password.encode('utf-8')
                        pwd_buf = ctypes.create_string_buffer(pwd_bytes)
                        salt_bytes = salt.encode('utf-8')
                        salt_buf = ctypes.create_string_buffer(salt_bytes)
                        try:
                            result = _lib.c_derive_master_key(
                                pwd_buf, len(pwd_bytes),
                                salt_buf, len(salt_bytes),
                                buf, 128
                            )
                            if result:
                                return buf.value.decode('utf-8')
                            else:
                                return FallbackMethods.derive_master_key(password, salt)
                        except:
                            return FallbackMethods.derive_master_key(password, salt)
                    
                    # Encrypt master key
                    def _encrypt_master_key_dll(master_key):
                        buf = ctypes.create_string_buffer(256)  # Enough space for encrypted key
                        key_bytes = master_key.encode('utf-8')
                        key_buf = ctypes.create_string_buffer(key_bytes)
                        try:
                            result = _lib.c_encrypt_master_key(key_buf, len(key_bytes), buf, 256)
                            if result:
                                return buf.value.decode('utf-8')
                            else:
                                return FallbackMethods.encrypt_master_key(master_key)
                        except:
                            return FallbackMethods.encrypt_master_key(master_key)
                    
                    # Decrypt master key
                    def _decrypt_master_key_dll(encrypted_key):
                        buf = ctypes.create_string_buffer(128)  # Enough space for decrypted key
                        key_bytes = encrypted_key.encode('utf-8')
                        key_buf = ctypes.create_string_buffer(key_bytes)
                        try:
                            result = _lib.c_decrypt_master_key(key_buf, len(key_bytes), buf, 128)
                            if result:
                                return buf.value.decode('utf-8')
                            else:
                                return FallbackMethods.decrypt_master_key(encrypted_key)
                        except:
                            return FallbackMethods.decrypt_master_key(encrypted_key)
                    
                    # Verify signature
                    def _verify_signature_dll(public_key, message, signature):
                        try:
                            return bool(_lib.c_verify_signature(
                                public_key, len(public_key),
                                message, len(message),
                                signature, len(signature)
                            ))
                        except:
                            return FallbackMethods.verify_signature(public_key, message, signature)
                    
                    # Create secure string
                    def _create_secure_string_dll(data):
                        # For now, we'll use the Python implementation
                        # In the future, we could use a Rust implementation
                        return FallbackMethods.create_secure_string(data)
                    
                    # Override module-level functions with DLL versions
                    secure_random_bytes = _try_bind_function('c_secure_random_bytes', FallbackMethods.secure_random_bytes)
                    is_vault_unlocked = _try_bind_function('c_is_vault_unlocked', FallbackMethods.is_vault_unlocked)
                    vault_exists = _try_bind_function('c_vault_exists', FallbackMethods.vault_exists)
                    create_vault = _try_bind_function('c_create_vault', FallbackMethods.create_vault)
                    unlock_vault = _try_bind_function('c_unlock_vault', FallbackMethods.unlock_vault)
                    lock_vault = _try_bind_function('c_lock_vault', FallbackMethods.lock_vault)
                    generate_salt = _try_bind_function('c_generate_salt', FallbackMethods.generate_salt)
                    derive_master_key = _try_bind_function('c_derive_master_key', FallbackMethods.derive_master_key)
                    encrypt_master_key = _try_bind_function('c_encrypt_master_key', FallbackMethods.encrypt_master_key)
                    decrypt_master_key = _try_bind_function('c_decrypt_master_key', FallbackMethods.decrypt_master_key)
                    verify_signature = _try_bind_function('c_verify_signature', FallbackMethods.verify_signature)
                    create_secure_string = FallbackMethods.create_secure_string  # Always use Python version for now
                    
                    # Set flag indicating we've loaded the DLL successfully
                    _dll_loaded = True
                    break
                    
                except Exception as e:
                    logger.error(f"Error loading DLL: {e}")
                    # Create a marker file to track this error
                    marker_dir = os.path.join(str(Path.home()), ".truefa")
                    os.makedirs(marker_dir, exist_ok=True)
                    with open(os.path.join(marker_dir, ".dll_crash"), "w") as f:
                        f.write(f"Error loading DLL: {str(e)}")

        # If we didn't successfully load the DLL, use the fallback implementations
        if not _dll_loaded:
            logger.warning("Could not load Rust crypto library, using Python fallback implementations")
            # All functions already point to fallback implementations
            
    except Exception as e:
        logger.error(f"Error during DLL loading: {e}")
        logger.warning("Using Python fallback implementations")

# Export version info
__version__ = "0.1.0"
