"""
TrueFA Crypto DLL Loader

Handles dynamic loading of the Rust cryptographic library with intelligent fallback.
Implements a robust multi-location search strategy and function-level monitoring
to ensure cryptographic operations work reliably across different environments.
"""

import os
import sys
import time
import ctypes
import logging
import platform
from pathlib import Path
from ..config import CRYPTO_LIB_PATH
from ..utils.debug import debug_print

# Configure logging
logger = logging.getLogger("truefa_crypto.loader")

# Constants
DEFAULT_TIMEOUT = 1.0  # Default timeout for DLL operations in seconds

# Global state
_dll_path = None
_lib = None
_detected_dll_issue = False
_function_timeouts = set()
_is_using_fallback = False
_attempted_rebuild = False

# Check environment variables for configuration
_use_fallback_env = os.environ.get('TRUEFA_USE_FALLBACK', '').lower() in ('true', '1', 'yes')
_debug_mode = os.environ.get('DEBUG', '').lower() in ('true', '1', 'yes')

def _find_dll_path():
    """
    Search for the truefa_crypto DLL across multiple potential locations.
    
    Implements a prioritized search strategy checking PyInstaller bundles,
    development environments, installed locations, and Docker containers.
    
    Returns:
        str or None: Path to the DLL if found, None otherwise
    """
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
            if _debug_mode:
                debug_print(f"DLL found at: {location}")
            return location
    
    if _debug_mode:
        debug_print("DLL not found in any standard location")
        for location in possible_locations:
            debug_print(f"DLL not found at: {location}")
    
    return None

def _enhance_dll_search_paths():
    """
    Augment system PATH to help locate the DLL and its dependencies.
    
    Adds the DLL directory, relative paths, and working directory to the
    system PATH to maximize the chances of successful loading.
    """
    try:
        # Get all potential directories that might contain our DLL or its dependencies
        search_paths = []
        
        # Add the directory containing our DLL
        if _dll_path:
            dll_dir = os.path.dirname(_dll_path)
            if dll_dir:
                search_paths.append(dll_dir)
        
        # Add directory with just the filename (for relative imports)
        if _dll_path:
            filename = os.path.basename(_dll_path)
            dir_name = os.path.dirname(filename)
            if dir_name:
                search_paths.append(dir_name)
        
        # Add current working directory
        cwd = os.getcwd()
        search_paths.append(cwd)
        
        # Get existing PATH
        existing_path = os.environ.get('PATH', '')
        paths = existing_path.split(os.pathsep)
        
        # Add all new paths that aren't already in PATH
        for path in search_paths:
            if path not in paths:
                paths.insert(0, path)  # Add to beginning for priority
        
        # Set the new PATH
        new_path = os.pathsep.join(paths)
        os.environ['PATH'] = new_path
        
        if _debug_mode:
            debug_print(f"Enhanced DLL search paths: {new_path}")
            
    except Exception as e:
        logger.warning(f"Error enhancing DLL search paths: {e}")

def _try_rebuild_rust_dll():
    """
    Attempt to rebuild the Rust DLL if not found or if loading fails.
    
    Returns:
        bool: True if rebuild was successful, False otherwise
    """
    global _attempted_rebuild
    
    # Only try to rebuild once
    if _attempted_rebuild:
        return False
    
    _attempted_rebuild = True
    
    logger.info("Attempting to rebuild Rust DLL...")
    
    # Define possible locations of the build_rust.py script
    build_script_paths = [
        os.path.join(os.getcwd(), "dev-tools", "build_rust.py"),
        os.path.join(os.getcwd(), "build_rust.py"),
        os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "dev-tools", "build_rust.py")
    ]
    
    # Try each possible build script location
    for script_path in build_script_paths:
        if os.path.exists(script_path):
            try:
                logger.info(f"Found build script at {script_path}, attempting to run...")
                
                # Try to import and run the build script
                import importlib.util
                spec = importlib.util.spec_from_file_location("build_rust", script_path)
                build_module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(build_module)
                
                # If the module has a main function, run it
                if hasattr(build_module, "main"):
                    build_module.main()
                    logger.info("Rust DLL rebuild completed")
                    return True
                else:
                    logger.warning("Build script does not have a main function")
            except Exception as e:
                logger.error(f"Error running build script: {e}")
    
    logger.error("Could not find or run the Rust build script")
    return False

def find_dll():
    """
    Find and load the native Rust crypto library with fallback capability.
    
    Implements a robust search and loading strategy with detailed error reporting.
    Automatically configures Python ctypes for function calls and sets up
    fallback to pure Python implementation if necessary.
    
    Returns:
        tuple: (dll_path, lib_module, is_using_fallback)
            - dll_path: Path to the loaded DLL or None if using fallback
            - lib_module: Library module (either native or fallback)
            - is_using_fallback: True if using Python fallback
    """
    global _dll_path, _lib, _is_using_fallback, _detected_dll_issue

    # If we already detected an issue, use the fallback right away
    if _detected_dll_issue and _use_fallback_env:
        logger.info("Using fallback implementation due to previous DLL issue or environment setting")
        from . import fallback
        return None, fallback, True

    # Try to find the DLL if we haven't already
    if _dll_path is None:
        _dll_path = _find_dll_path()
        if _dll_path is None:
            # Try to rebuild the DLL if it's not found
            if _try_rebuild_rust_dll():
                # Try to find the DLL again
                _dll_path = _find_dll_path()
            
            if _dll_path is None:
                logger.warning("Native crypto library not found, using fallback implementation")
                from . import fallback
                _is_using_fallback = True
                return None, fallback, True

    # Try to load the DLL if we haven't already
    if _lib is None:
        try:
            logger.info(f"Attempting to load native crypto library from {_dll_path}")
            
            # Enhance DLL search paths to help Windows find dependencies
            _enhance_dll_search_paths()
            
            # Load the library
            lib = ctypes.CDLL(_dll_path)
            
            # Set up the function signatures
            _setup_function_signatures(lib)
            
            # Test a simple function to validate the library works
            try:
                # Call a simple function to test the library
                if hasattr(lib, 'c_vault_exists'):
                    _ = lib.c_vault_exists()
                    logger.info("Successfully validated Rust crypto library")
                else:
                    logger.warning("c_vault_exists function not found in DLL")
                    raise AttributeError("c_vault_exists function not available")
            except Exception as e:
                logger.error(f"Error testing native library: {e}")
                
                # Try to rebuild the DLL and load it again
                if _try_rebuild_rust_dll():
                    # Try to find and load the DLL again
                    _dll_path = _find_dll_path()
                    if _dll_path:
                        try:
                            lib = ctypes.CDLL(_dll_path)
                            _setup_function_signatures(lib)
                            if hasattr(lib, 'c_vault_exists'):
                                _ = lib.c_vault_exists()
                                logger.info("Successfully validated rebuilt Rust crypto library")
                                _lib = lib
                                _is_using_fallback = False
                                return _dll_path, _lib, False
                        except Exception as rebuild_e:
                            logger.error(f"Error loading rebuilt library: {rebuild_e}")
                
                _detected_dll_issue = True
                from . import fallback
                _is_using_fallback = True
                return None, fallback, True
                
            # If we get here, the library is loaded and validated
            _lib = lib
            _is_using_fallback = False
            logger.info("Successfully loaded native crypto library")
            return _dll_path, _lib, False
            
        except Exception as e:
            # Log detailed error information
            error_msg = f"Error loading native crypto library: {e}"
            logger.error(error_msg)
            if _debug_mode:
                debug_print(error_msg)
            
            # Try to rebuild the DLL and load it again
            if _try_rebuild_rust_dll():
                # Try to find and load the DLL again
                _dll_path = _find_dll_path()
                if _dll_path:
                    try:
                        lib = ctypes.CDLL(_dll_path)
                        _setup_function_signatures(lib)
                        _lib = lib
                        _is_using_fallback = False
                        logger.info("Successfully loaded rebuilt Rust crypto library")
                        return _dll_path, _lib, False
                    except Exception as rebuild_e:
                        logger.error(f"Error loading rebuilt library: {rebuild_e}")
                
            # Mark that we've detected an issue
            _detected_dll_issue = True
            
            # Fall back to Python implementation
            from . import fallback
            _is_using_fallback = True
            return None, fallback, True
    
    # Return the cached values
    return _dll_path, _lib, _is_using_fallback

def _setup_function_signatures(lib):
    """
    Configure function signatures for the loaded native library.
    
    Defines argument types and return types for the C functions
    exposed by the Rust DLL to ensure proper type conversion.
    
    Args:
        lib: Loaded native library handle
    """
    try:
        # Define the function signatures for the C API
        # Secure random bytes
        lib.c_secure_random_bytes.argtypes = [ctypes.c_size_t, ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_size_t)]
        lib.c_secure_random_bytes.restype = ctypes.c_bool
        
        # Vault operations
        lib.c_create_vault.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t, ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_size_t)]
        lib.c_create_vault.restype = ctypes.c_bool
        
        lib.c_is_vault_unlocked.argtypes = []
        lib.c_is_vault_unlocked.restype = ctypes.c_bool
        
        lib.c_vault_exists.argtypes = []
        lib.c_vault_exists.restype = ctypes.c_bool
        
        lib.c_unlock_vault.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t]
        lib.c_unlock_vault.restype = ctypes.c_bool
        
        lib.c_lock_vault.argtypes = []
        lib.c_lock_vault.restype = ctypes.c_bool
        
        # Salt and key operations
        lib.c_generate_salt.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_size_t)]
        lib.c_generate_salt.restype = ctypes.c_bool
        
        lib.c_derive_master_key.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t, ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_size_t)]
        lib.c_derive_master_key.restype = ctypes.c_bool
        
        lib.c_encrypt_master_key.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t, ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_size_t)]
        lib.c_encrypt_master_key.restype = ctypes.c_bool
        
        lib.c_decrypt_master_key.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t, ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_size_t)]
        lib.c_decrypt_master_key.restype = ctypes.c_bool
        
        # SecureString operations
        lib.c_create_secure_string.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t]
        lib.c_create_secure_string.restype = ctypes.c_void_p
        
        # Ensure all required functions are available
        _check_required_functions(lib)
        
        logger.info("Successfully configured function signatures for native library")
    except Exception as e:
        logger.error(f"Error setting function signatures: {e}")
        if _debug_mode:
            debug_print(f"Error setting function signatures: {e}")

def _check_required_functions(lib):
    """
    Verify that all required functions are available in the loaded library.
    
    Args:
        lib: Loaded native library handle
        
    Raises:
        AttributeError: If a required function is missing
    """
    required_functions = [
        'c_secure_random_bytes',
        'c_create_vault',
        'c_is_vault_unlocked',
        'c_vault_exists',
        'c_unlock_vault',
        'c_lock_vault',
        'c_generate_salt',
        'c_derive_master_key',
        'c_encrypt_master_key',
        'c_decrypt_master_key',
        'c_create_secure_string'
    ]
    
    missing = []
    for func in required_functions:
        if not hasattr(lib, func):
            missing.append(func)
    
    if missing:
        raise AttributeError(f"Missing required functions in DLL: {', '.join(missing)}")

def get_lib():
    """
    Get the crypto library handle, loading it if necessary.
    
    Returns the appropriate library implementation (native or fallback)
    for use by the crypto functions.
    
    Returns:
        object: Library module for cryptographic operations
    """
    global _lib
    
    if _lib is None:
        _, _lib, _ = find_dll()
    
    return _lib

def is_using_fallback():
    """
    Check whether the Python fallback implementation is active.
    
    Returns:
        bool: True if using Python fallback, False if using native library
    """
    global _is_using_fallback
    
    if _lib is None:
        _, _, _is_using_fallback = find_dll()
    
    return _is_using_fallback 

def _reset_dll_cache():
    """Reset the cached DLL state to force a fresh attempt to load the DLL."""
    global _dll_path, _lib, _is_using_fallback, _detected_dll_issue, _attempted_rebuild
    
    logger.info("Resetting DLL cache")
    _dll_path = None
    _lib = None
    _is_using_fallback = False
    _detected_dll_issue = False
    _attempted_rebuild = False 

def _setup_dll_search_paths():
    """
    Configure the DLL search paths to help Windows find the crypto DLL.
    """
    try:
        import os
        
        # Get the directory of the current script or executable
        if getattr(sys, 'frozen', False):
            # PyInstaller creates a temp folder and stores path in _MEIPASS
            base_dir = getattr(sys, '_MEIPASS', os.path.dirname(sys.executable))
        else:
            base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        
        # Get the directory containing the DLL
        dll_dir = os.path.dirname(_dll_path) if _dll_path else base_dir
        
        # Set environment variable for DLL paths
        if 'PATH' in os.environ:
            # Add our paths to the beginning of PATH
            new_path = f"{dll_dir}{os.pathsep}{os.environ['PATH']}"
            os.environ['PATH'] = new_path
            debug_print(f"Enhanced DLL search paths: {new_path}")
    except Exception:
        pass

def _initialize_ffi():
    """Initialize the FFI interface."""
    global _dll, _is_initialized
    
    try:
        # Make sure we have the DLL path
        if not _dll_path:
            error_msg = "Crypto library not found. Please install the TrueFA Rust crypto component."
            debug_print(error_msg)
            raise ImportError(error_msg)
        
        # Set up search paths on Windows
        if platform.system() == "Windows":
            _setup_dll_search_paths()
        
        # Load the shared library/DLL
        try:
            _dll = ctypes.CDLL(_dll_path)
        except Exception as e:
            error_msg = f"Failed to load crypto library {_dll_path}: {e}"
            debug_print(error_msg)
            raise ImportError(error_msg)

        # Setup function signatures
        try:
            _setup_function_signatures()
        except Exception as e:
            debug_print(f"Error setting function signatures: {e}")
            raise

        _is_initialized = True
        
    except Exception as e:
        _is_initialized = False
        raise e 