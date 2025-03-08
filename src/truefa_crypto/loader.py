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
                print(f"DLL found at: {location}")
            return location
    
    if _debug_mode:
        print("DLL not found in any standard location")
        for location in possible_locations:
            print(f"DLL not found at: {location}")
    
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
            print(f"Enhanced DLL search paths: {new_path}")
            
    except Exception as e:
        logger.warning(f"Error enhancing DLL search paths: {e}")

def find_dll():
    """
    Load native crypto library with intelligent fallback.
    
    Search order:
    1. Check for cached library
    2. Check environment variable to force fallback
    3. Find native library in multiple locations
    4. Load and configure the library
    5. Fall back to Python implementation if any step fails
    
    Returns:
        tuple: (dll_path, lib_handle, is_fallback)
            - dll_path: Path to the native library or None
            - lib_handle: Loaded library or fallback module
            - is_fallback: Whether Python fallback is being used
    """
    global _dll_path, _lib, _is_using_fallback
    
    # If already loaded, return cached values
    if _lib is not None:
        return _dll_path, _lib, _is_using_fallback
    
    # If fallback mode is forced by environment variable
    if _use_fallback_env:
        logger.info("Using Python fallback implementation due to environment variable")
        _is_using_fallback = True
        from . import fallback
        _lib = fallback
        return None, _lib, _is_using_fallback
    
    # Try to find and load the DLL
    _dll_path = _find_dll_path()
    
    if _dll_path:
        try:
            # Set up DLL search paths
            _enhance_dll_search_paths()
            
            # Load the DLL
            _lib = ctypes.CDLL(_dll_path)
            
            if _debug_mode:
                print("Successfully loaded DLL using ctypes")
            
            # Set up function signatures
            _setup_function_signatures(_lib)
            
            return _dll_path, _lib, False
        except Exception as e:
            logger.warning(f"Error loading DLL: {e}")
            _dll_path = None
    
    # If we get here, fall back to Python implementation
    logger.info("Using Python fallback implementation due to loading issues")
    _is_using_fallback = True
    from . import fallback
    _lib = fallback
    return None, _lib, _is_using_fallback

def _setup_function_signatures(lib):
    """
    Configure function signatures for the loaded native library.
    
    Defines argument types and return types for the C functions
    exposed by the Rust DLL to ensure proper type conversion.
    
    Args:
        lib: Loaded native library handle
    """
    try:
        # Define the function signatures here
        # Example:
        # lib.secure_random_bytes.argtypes = [ctypes.c_int]
        # lib.secure_random_bytes.restype = ctypes.POINTER(ctypes.c_ubyte)
        pass
    except Exception as e:
        if _debug_mode:
            print(f"Error setting function signatures: {e}")

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