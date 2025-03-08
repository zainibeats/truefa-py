"""
DLL Loader for TrueFA Crypto

This module handles finding and loading the Rust-based DLL for cryptographic operations.
If the DLL cannot be found or loaded, it provides mechanisms for using fallback implementations.
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
    """Find the path to the truefa_crypto DLL."""
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
    """Add additional paths to system PATH to help find dependencies."""
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
    Attempt to find and load the truefa_crypto DLL/shared library.
    
    Returns:
        tuple: (dll_path, lib_handle, is_fallback)
            where dll_path is the path to the DLL,
            lib_handle is the loaded library or None,
            is_fallback indicates whether fallback mode is being used
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
    """Set up the function signatures for the loaded DLL."""
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
    Get the library handle for crypto operations.
    
    This will load the DLL if it hasn't been loaded yet.
    
    Returns:
        object: The library module (either DLL or fallback)
    """
    global _lib
    
    if _lib is None:
        _, _lib, _ = find_dll()
    
    return _lib

def is_using_fallback():
    """
    Check if the fallback implementation is being used.
    
    Returns:
        bool: True if fallback is being used, False if DLL is being used
    """
    global _is_using_fallback
    
    if _lib is None:
        _, _, _is_using_fallback = find_dll()
    
    return _is_using_fallback 