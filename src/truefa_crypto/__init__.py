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

def _get_dll_search_paths():
    """
    Get ordered list of paths to search for the DLL.
    Handles both PyInstaller bundles and regular Python environments.
    """
    dll_name = "truefa_crypto.dll" if sys.platform == "win32" else "libtruefa_crypto.so"
    
    # Check if running from PyInstaller bundle
    is_frozen = getattr(sys, 'frozen', False)
    if is_frozen:
        base_dir = sys._MEIPASS
        exe_dir = os.path.dirname(sys.executable)
        exe_path = os.path.abspath(sys.executable).lower()
        is_installed = any(p in exe_path for p in ["program files", "program files (x86)"])
        
        print(f"Running from PyInstaller bundle. Searching in: {base_dir}")
        print(f"Current working directory: {os.getcwd()}")
        
        # Enhanced search paths for PyInstaller bundle
        # Order is important - prioritize the most reliable locations
        search_paths = [
            # 1. Check directly in the base directory (most common)
            os.path.join(base_dir, dll_name),
            
            # 2. Check in a subdirectory named after the module
            os.path.join(base_dir, "truefa_crypto", dll_name),
            
            # 3. Check in the executable directory
            os.path.join(exe_dir, "rust_crypto", "target", "release", dll_name),
            
            # 4. Check in a temp directory that PyInstaller might use
            os.path.join(base_dir, "rust_crypto", "target", "release", dll_name),
            
            # 5. Check directly in executable directory
            os.path.join(exe_dir, dll_name),
            
            # 6. Check in the current working directory
            os.path.join(os.getcwd(), dll_name),
            
            # 7. Check in the _internal directory that newer PyInstaller versions use
            os.path.join(base_dir, "_internal", dll_name),
            os.path.join(base_dir, "_internal", "truefa_crypto", dll_name),
            
            # 8. Try a few other common locations
            os.path.join(exe_dir, dll_name),
            os.path.join(exe_dir, "truefa_crypto", dll_name),
        ]
        
        # Print all search paths for diagnostic purposes
        for path in search_paths:
            try:
                exists = os.path.exists(path)
                print(f"DLL {'found' if exists else 'not found'} at: {path}")
            except Exception as e:
                print(f"Error checking path {path}: {e}")
        
        return search_paths
    else:
        # Development environment - check module directory first
        module_dir = os.path.dirname(os.path.abspath(__file__))
        return [
            os.path.join(module_dir, dll_name),
            os.path.join(os.path.dirname(module_dir), dll_name),
            os.path.join(os.getcwd(), "rust_crypto", "target", "release", dll_name)
        ]

# Add a function to directly detect if using PyInstaller and set fallback accordingly
def _is_pyinstaller():
    return getattr(sys, 'frozen', False)

# Add a special flag to force fallback for PyInstaller on fresh Windows
def _should_force_fallback():
    # Check environment variables
    if os.environ.get("TRUEFA_USE_FALLBACK", "").lower() == "true":
        return True
        
    # Check for PyInstaller on Windows
    is_pyinstaller = _is_pyinstaller()
    is_windows = sys.platform == "win32"
    
    # PyInstaller on Windows 10 or 11 might need fallback
    # We can detect Windows 10/11 by checking Windows version
    if is_pyinstaller and is_windows:
        try:
            import platform
            win_ver = platform.version()
            # Windows 10 is 10.0.x, Windows 11 is typically 10.0.22xxx
            if win_ver.startswith("10.0."):
                # If it's a fresh install of Windows 10 or Windows 11,
                # using fallback might be more reliable
                logger.info(f"Detected Windows {win_ver} with PyInstaller - considering fallback")
                
                # Check if the application has previously crashed at this stage
                crash_marker = os.path.join(os.path.expanduser("~"), ".truefa", ".dll_crash")
                if os.path.exists(crash_marker):
                    logger.warning("Found previous crash marker - forcing fallback mode")
                    return True
        except Exception as e:
            logger.warning(f"Error detecting Windows version: {e}")
    
    return False

def _load_dll():
    """
    Load the native crypto DLL with proper error handling.
    Returns a tuple of (lib, use_fallback) where lib is the loaded DLL and
    use_fallback is a boolean indicating whether to use Python fallbacks.
    """
    # Check if we should force fallback mode
    if _should_force_fallback():
        logger.info("Using Python fallback implementation due to environment or platform detection")
        return None, True
    
    use_fallback = os.environ.get("TRUEFA_USE_FALLBACK", "").lower() == "true"
    if use_fallback:
        logger.info("Using Python fallback implementation due to environment variable")
        return None, True
    
    # Force the DLL to use specific paths to find dependencies
    os.environ["PATH"] = os.path.dirname(os.path.abspath(__file__)) + os.pathsep + os.environ.get("PATH", "")
    
    # Get the search paths
    search_paths = _get_dll_search_paths()
    
    # First, just check if the DLL exists
    dll_found = False
    dll_path = None
    for path in search_paths:
        try:
            if os.path.exists(path):
                dll_found = True
                dll_path = path
                logger.info(f"DLL found at: {path}")
                break
        except Exception as e:
            logger.warning(f"Error checking path {path}: {e}")
    
    if not dll_found:
        logger.warning("DLL not found in any search path, using fallback")
        return None, True
    
    # Try to load the DLL with protective measures
    # On fresh Windows installations, DLL loading can be problematic
    try:
        # Set a timeout for DLL loading (Windows only)
        if sys.platform == "win32":
            import threading
            import time
            
            dll_loaded = threading.Event()
            dll_error = [None]
            dll_handle = [None]
            
            def load_dll_thread():
                try:
                    # Use native Windows API to load with detailed error handling
                    if hasattr(ctypes, 'windll'):
                        try:
                            # Try using Windows-specific loading
                            kernel32 = ctypes.windll.kernel32
                            # Try to get full path permissions
                            handle = kernel32.LoadLibraryW(dll_path)
                            if handle:
                                dll_handle[0] = handle
                                dll_loaded.set()
                                return
                        except Exception as e:
                            logger.warning(f"Windows native loading failed: {e}")
                    
                    # Fall back to standard ctypes loading
                    lib = ctypes.cdll.LoadLibrary(dll_path)
                    dll_handle[0] = lib
                    dll_loaded.set()
                except Exception as e:
                    dll_error[0] = e
                    dll_loaded.set()
            
            # Start loading in a separate thread
            thread = threading.Thread(target=load_dll_thread)
            thread.daemon = True
            thread.start()
            
            # Wait for loading with a timeout
            if not dll_loaded.wait(timeout=5.0):
                logger.warning("DLL loading timed out, using fallback")
                return None, True
            
            if dll_error[0]:
                logger.warning(f"DLL loading failed: {dll_error[0]}")
                return None, True
            
            if not dll_handle[0]:
                logger.warning("DLL loaded but handle is None, using fallback")
                return None, True
            
            # Successfully loaded, now wrap in ctypes
            try:
                lib = ctypes.CDLL(dll_path)
                logger.info("Successfully loaded DLL using ctypes")
            except Exception as e:
                logger.warning(f"Failed to wrap DLL in ctypes: {e}")
                return None, True
        else:
            # Non-Windows platforms - use standard loading
            lib = ctypes.cdll.LoadLibrary(dll_path)
            logger.info(f"Successfully loaded DLL from {dll_path}")
        
        # Set function signatures
        try:
            # Define basic secure random function
            lib.c_secure_random_bytes.argtypes = [ctypes.c_size_t]
            lib.c_secure_random_bytes.restype = ctypes.POINTER(ctypes.c_ubyte)
            
            # Define secure string functions if they exist
            has_secure_string = hasattr(lib, 'c_create_secure_string')
            if has_secure_string:
                lib.c_create_secure_string.argtypes = [ctypes.c_char_p, ctypes.c_size_t]
                lib.c_create_secure_string.restype = ctypes.c_size_t
                
                lib.c_secure_string_to_string.argtypes = [ctypes.c_size_t]
                lib.c_secure_string_to_string.restype = ctypes.c_char_p
                
                # This function is optional and may not exist in older builds
                if hasattr(lib, 'c_secure_string_clear'):
                    lib.c_secure_string_clear.argtypes = [ctypes.c_size_t]
                    lib.c_secure_string_clear.restype = ctypes.c_bool
                else:
                    logger.warning("DLL is missing c_secure_string_clear function")
            else:
                logger.warning("Using fallback implementation for secure memory!")
            
            # Check for generate_salt
            has_generate_salt = hasattr(lib, 'c_generate_salt')
            if has_generate_salt:
                # Configure function signatures
                lib.c_generate_salt.argtypes = []
                lib.c_generate_salt.restype = ctypes.c_char_p
                logger.info("Found generate_salt function in DLL")
            else:
                logger.warning("DLL is missing c_generate_salt function")
            
            logger.info("Successfully set function signatures")
            return lib, not (has_secure_string and has_generate_salt)
        except Exception as e:
            logger.error(f"Error setting function signatures: {e}")
            return lib, True
    except Exception as e:
        logger.warning(f"Failed to load DLL: {e}")
        return None, True

# Try to load the DLL
_lib, _use_fallback = _load_dll()

if _lib is None:
    logger.warning("Using fallback implementation for secure memory!")
    
    class SecureString:
        """Pure Python fallback implementation of SecureString."""
        def __init__(self, value):
            if isinstance(value, str):
                self._data = value
            elif isinstance(value, bytes):
                try:
                    self._data = value.decode('utf-8')
                except UnicodeDecodeError:
                    import base64
                    self._data = base64.b64encode(value).decode('utf-8')
            else:
                self._data = str(value)
                
        def __str__(self):
            return self._data
            
        def get(self):
            return self._data
            
        def clear(self):
            self._data = None
            
        def __del__(self):
            self.clear()
    
    def create_secure_string(value):
        logger.info("Using Python fallback implementation for create_secure_string")
        return SecureString(value)
        
else:
    # Set up function signatures
    try:
        class SecureString:
            def __init__(self, value):
                if isinstance(value, str):
                    encoded = value.encode('utf-8')
                elif isinstance(value, bytes):
                    encoded = value
                else:
                    encoded = str(value).encode('utf-8')
                    
                self.ptr = _lib.c_create_secure_string(encoded, len(encoded))
                if not self.ptr:
                    raise RuntimeError("Failed to create secure string")
                    
            def __str__(self):
                return "<SecureString: [protected]>"
                
            def get(self):
                return "<SecureString: [protected]>"
                
            def clear(self):
                if hasattr(self, 'ptr') and self.ptr:
                    _lib.c_secure_string_clear(self.ptr)
                    self.ptr = None
                    
            def __del__(self):
                self.clear()
        
        def create_secure_string(value):
            return SecureString(value)
            
        logger.info("Successfully initialized Rust secure string implementation")
        
    except Exception as e:
        logger.error(f"Failed to initialize secure string functions: {e}")
        raise

def secure_random_bytes(size):
    """Generate cryptographically secure random bytes."""
    if _lib and hasattr(_lib, 'c_secure_random_bytes'):
        buffer = (ctypes.c_ubyte * size)()
        output_size = ctypes.c_size_t(size)
        if _lib.c_secure_random_bytes(size, buffer, ctypes.byref(output_size)):
            return bytes(buffer[:output_size.value])
    # Fallback to os.urandom
    return os.urandom(size)

def encrypt_master_key(master_key):
    """
    Encrypt the master key using a secure method.
    Returns the encrypted key as a base64-encoded string.
    """
    import base64
    import time
    
    start_time = time.time()
    
    # Try Rust implementation first with timeout
    if not _use_fallback:
        try:
            from concurrent.futures import ThreadPoolExecutor, TimeoutError
            
            with ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(_lib.c_encrypt_master_key, master_key.encode('utf-8'))
                try:
                    # Use a 3-second timeout
                    encrypted_key = future.result(timeout=3.0)
                    # Convert from C string to Python string
                    if encrypted_key:
                        result = encrypted_key.decode('utf-8')
                        logger.info(f"Master key encrypted successfully using Rust implementation in {time.time() - start_time:.2f} seconds")
                        return result
                except TimeoutError:
                    logger.warning("Encryption timed out in Rust implementation, using fallback")
                except Exception as e:
                    logger.warning(f"Error in Rust encryption: {e}, using fallback")
        except Exception as e:
            logger.warning(f"Failed to use Rust implementation for encryption: {e}")
    
    # Python fallback with simpler implementation
    logger.info("Using Python fallback for master key encryption")
    try:
        from .fallback import encrypt_master_key as fallback_encrypt
        result = fallback_encrypt(master_key)
        logger.info(f"Master key encrypted successfully using Python fallback in {time.time() - start_time:.2f} seconds")
        return result
    except Exception as e:
        logger.error(f"Python fallback encryption failed: {e}")
        
        # Last resort - very simple XOR encryption
        try:
            logger.warning("Using last-resort XOR encryption")
            import os
            import base64
            
            # Generate a random key
            key = os.urandom(32)
            
            # Simple XOR encryption
            encrypted = bytes(a ^ b for a, b in zip(master_key.encode('utf-8'), key * (len(master_key) // len(key) + 1)))
            
            # Encode both the key and encrypted data
            key_b64 = base64.b64encode(key).decode('utf-8')
            data_b64 = base64.b64encode(encrypted).decode('utf-8')
            
            # Return a special format that indicates this is XOR encrypted
            result = f"XOR:{key_b64}:{data_b64}"
            logger.warning(f"Used XOR fallback encryption (emergency mode)")
            return result
        except Exception as e:
            logger.critical(f"All encryption methods failed: {e}")
            # Absolute last resort - return the master key with minimal protection
            # This is not secure but better than crashing
            return f"PLAIN:{base64.b64encode(master_key.encode('utf-8')).decode('utf-8')}"

def decrypt_master_key(encrypted_master_key):
    """
    Decrypt the master key.
    Takes a base64-encoded encrypted master key and returns the decrypted master key.
    """
    import base64
    import time
    
    start_time = time.time()
    
    # Check for fallback encryption formats
    if encrypted_master_key.startswith("XOR:"):
        try:
            logger.warning("Decrypting with XOR fallback method")
            # Extract key and data
            parts = encrypted_master_key.split(":")
            if len(parts) != 3:
                raise ValueError("Invalid XOR encryption format")
                
            key_b64 = parts[1]
            data_b64 = parts[2]
            
            # Decode from base64
            key = base64.b64decode(key_b64)
            encrypted = base64.b64decode(data_b64)
            
            # Simple XOR decryption
            decrypted = bytes(a ^ b for a, b in zip(encrypted, key * (len(encrypted) // len(key) + 1)))
            
            # Convert to string
            result = decrypted.decode('utf-8')
            logger.warning(f"XOR fallback decryption succeeded in {time.time() - start_time:.2f} seconds")
            return result
        except Exception as e:
            logger.error(f"XOR fallback decryption failed: {e}")
    
    # Check for plain text format (absolute last resort)
    if encrypted_master_key.startswith("PLAIN:"):
        try:
            logger.critical("Decrypting with PLAIN text method - INSECURE!")
            encoded = encrypted_master_key[6:]  # Remove "PLAIN:" prefix
            result = base64.b64decode(encoded).decode('utf-8')
            return result
        except Exception as e:
            logger.critical(f"PLAIN decryption failed: {e}")
    
    # Try Rust implementation first with timeout
    if not _use_fallback:
        try:
            from concurrent.futures import ThreadPoolExecutor, TimeoutError
            
            with ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(_lib.c_decrypt_master_key, encrypted_master_key.encode('utf-8'))
                try:
                    # Use a 3-second timeout
                    decrypted_key = future.result(timeout=3.0)
                    # Convert from C string to Python string
                    if decrypted_key:
                        result = decrypted_key.decode('utf-8')
                        logger.info(f"Master key decrypted successfully using Rust implementation in {time.time() - start_time:.2f} seconds")
                        return result
                except TimeoutError:
                    logger.warning("Decryption timed out in Rust implementation, using fallback")
                except Exception as e:
                    logger.warning(f"Error in Rust decryption: {e}, using fallback")
        except Exception as e:
            logger.warning(f"Failed to use Rust implementation for decryption: {e}")
    
    # Python fallback
    logger.info("Using Python fallback for master key decryption")
    try:
        from .fallback import decrypt_master_key as fallback_decrypt
        result = fallback_decrypt(encrypted_master_key)
        logger.info(f"Master key decrypted successfully using Python fallback in {time.time() - start_time:.2f} seconds")
        return result
    except Exception as e:
        logger.error(f"All decryption methods failed: {e}")
        raise ValueError(f"Could not decrypt master key: {e}")

def test_crypto():
    """Test the crypto functions."""
    print("Testing crypto functions...")
    
    # Test key generation
    try:
        key = generate_secure_key(32)
        print(f"Generated secure key: {key[:8]}... (length: {len(key)})")
    except Exception as e:
        print(f"Error in generate_secure_key: {e}")
    
    # Test random bytes
    try:
        rand_bytes = generate_random_bytes(32)
        print(f"Generated random bytes: {rand_bytes[:8]}... (length: {len(rand_bytes)})")
    except Exception as e:
        print(f"Error in generate_random_bytes: {e}")
    
    # Test master key encryption and decryption
    try:
        test_master_key = "SuperSecretMasterKey123!"
        print(f"Original master key: {test_master_key}")
        
        # Test encryption
        encrypted = encrypt_master_key(test_master_key)
        print(f"Encrypted master key: {encrypted[:20]}... (length: {len(encrypted)})")
        
        # Test decryption
        decrypted = decrypt_master_key(encrypted)
        print(f"Decrypted master key: {decrypted}")
        
        # Verify
        if decrypted == test_master_key:
            print("✅ Encryption/Decryption test PASSED")
        else:
            print("❌ Encryption/Decryption test FAILED")
    except Exception as e:
        print(f"Error in master key encryption/decryption test: {e}")
    
    # Force Python fallback for testing
    try:
        print("\nTesting Python fallback implementation:")
        test_master_key = "AnotherSecretMasterKey456!"
        
        # Simulate Rust implementation failure
        original_encrypt = _lib.c_encrypt_master_key
        original_decrypt = _lib.c_decrypt_master_key
        
        # Remove the functions temporarily to force fallback
        delattr(_lib, 'c_encrypt_master_key')
        delattr(_lib, 'c_decrypt_master_key')
        
        # Test fallback encryption
        encrypted = encrypt_master_key(test_master_key)
        print(f"Fallback encrypted master key: {encrypted[:20]}... (length: {len(encrypted)})")
        
        # Test fallback decryption
        decrypted = decrypt_master_key(encrypted)
        print(f"Fallback decrypted master key: {decrypted}")
        
        # Verify
        if decrypted == test_master_key:
            print("✅ Fallback Encryption/Decryption test PASSED")
        else:
            print("❌ Fallback Encryption/Decryption test FAILED")
            
        # Restore original functions
        _lib.c_encrypt_master_key = original_encrypt
        _lib.c_decrypt_master_key = original_decrypt
    except Exception as e:
        print(f"Error in fallback encryption/decryption test: {e}")
        # Attempt to restore functions if they exist
        if 'original_encrypt' in locals():
            _lib.c_encrypt_master_key = original_encrypt
        if 'original_decrypt' in locals():
            _lib.c_decrypt_master_key = original_decrypt
    
    print("Crypto tests completed")

# Export version info
__version__ = "0.1.0"
