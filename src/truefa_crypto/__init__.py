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
        
        logger.info(f"Running from {'installed' if is_installed else 'portable'} PyInstaller bundle")
        logger.info(f"Base dir: {base_dir}")
        logger.info(f"Exe dir: {exe_dir}")
        
        if is_installed:
            # Installed mode - check bundle first, then program files
            return [
                os.path.join(base_dir, dll_name),
                os.path.join(exe_dir, dll_name)
            ]
        else:
            # Portable mode - check exe directory first, then bundle
            return [
                os.path.join(exe_dir, dll_name),
                os.path.join(base_dir, dll_name)
            ]
    else:
        # Development environment - check module directory first
        module_dir = os.path.dirname(os.path.abspath(__file__))
        return [
            os.path.join(module_dir, dll_name),
            os.path.join(os.path.dirname(module_dir), dll_name),
            os.path.join(os.getcwd(), "rust_crypto", "target", "release", dll_name)
        ]

def _load_dll():
    """
    Load the native crypto DLL with proper error handling.
    Returns (dll, path) tuple or (None, None) if loading fails.
    """
    for dll_path in _get_dll_search_paths():
        if os.path.exists(dll_path):
            logger.info(f"Found DLL at: {dll_path}")
            try:
                dll = ctypes.CDLL(dll_path)
                
                # Define required functions and their signatures
                function_signatures = {
                    'c_secure_random_bytes': {
                        'argtypes': [ctypes.c_size_t, ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_size_t)],
                        'restype': ctypes.c_bool
                    },
                    'c_create_secure_string': {
                        'argtypes': [ctypes.c_char_p, ctypes.c_size_t],
                        'restype': ctypes.c_void_p
                    },
                    'c_secure_string_clear': {
                        'argtypes': [ctypes.c_void_p],
                        'restype': None
                    }
                }
                
                # Verify and set up function signatures
                for func_name, sig in function_signatures.items():
                    if not hasattr(dll, func_name):
                        logger.warning(f"DLL missing required function: {func_name}")
                        break
                    
                    try:
                        func = getattr(dll, func_name)
                        func.argtypes = sig['argtypes']
                        func.restype = sig['restype']
                        logger.info(f"Successfully configured function: {func_name}")
                    except Exception as e:
                        logger.error(f"Error setting up {func_name}: {e}")
                        break
                else:
                    # All functions were found and configured
                    logger.info("Successfully loaded and configured DLL")
                    return dll, dll_path
                
            except Exception as e:
                logger.warning(f"Failed to load DLL from {dll_path}: {e}")
        else:
            logger.debug(f"DLL not found at: {dll_path}")
            
    return None, None

# Try to load the DLL
_lib, _dll_path = _load_dll()

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

# Export version info
__version__ = "0.1.0"
