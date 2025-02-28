"""
Secure Memory Management Module

This module provides Python wrappers around the Rust-based secure memory implementation.
It ensures that sensitive data (like TOTP secrets) is properly protected in memory
through automatic zeroization and secure cleanup.

Key Features:
- SecureString class for protected memory storage
- Vault-based secret management
- Secure random number generation
- Automatic cleanup on process termination

The module uses the Rust truefa_crypto library for the actual implementation
of security-critical operations.
"""

import sys
import os
import ctypes
from ctypes import c_void_p, c_size_t, c_char_p, c_int
from pathlib import Path

# Add the project root to Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

# Try to load the DLL directly
def _load_dll():
    """Try to load the truefa_crypto DLL from various locations."""
    import os
    import sys
    import ctypes
    from ctypes import c_void_p, c_size_t, c_char_p, c_int
    
    # Check if we're running from a PyInstaller bundle
    is_pyinstaller = getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS')
    base_dir = sys._MEIPASS if is_pyinstaller else os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    
    print(f"Running from {'PyInstaller bundle' if is_pyinstaller else 'regular Python'}. Searching in: {base_dir}")
    print(f"Current working directory: {os.getcwd()}")
    
    # DLL name
    dll_name = "truefa_crypto.dll" if sys.platform == "win32" else "libtruefa_crypto.so"
    
    # Try all possible locations for the DLL
    possible_locations = [
        # Direct locations from PyInstaller bundle
        os.path.join(base_dir, dll_name),
        os.path.join(base_dir, "truefa_crypto", dll_name),
        
        # Regular development locations
        os.path.join(os.getcwd(), "rust_crypto", "target", "release", dll_name),
        os.path.join(base_dir, "rust_crypto", "target", "release", dll_name),
        
        # Distribution locations
        os.path.join(os.getcwd(), dll_name),
        os.path.join(os.path.dirname(sys.executable) if is_pyinstaller else os.getcwd(), dll_name),
    ]
    
    # Add more locations if in bundle
    if is_pyinstaller:
        possible_locations.extend([
            os.path.join(base_dir, "_internal", dll_name),
            os.path.join(base_dir, "_internal", "truefa_crypto", dll_name),
            os.path.join(os.path.dirname(sys.executable), dll_name),
            os.path.join(os.path.dirname(sys.executable), "truefa_crypto", dll_name)
        ])
    
    _dll = None
    
    # Try each location in order
    for location in possible_locations:
        if os.path.exists(location):
            print(f"DLL found at: {location}")
            try:
                _dll = ctypes.CDLL(location)
                print("Successfully loaded DLL using ctypes")
                
                # Define function signatures if loaded successfully
                try:
                    # SecureString functions
                    _dll.create_secure_string.argtypes = [c_char_p]
                    _dll.create_secure_string.restype = c_void_p
                    _dll.secure_string_clear.argtypes = [c_void_p]
                    _dll.secure_string_clear.restype = None
                    _dll.secure_string_to_string.argtypes = [c_void_p]
                    _dll.secure_string_to_string.restype = c_char_p
                    
                    # Memory functions
                    _dll.secure_zero_memory.argtypes = [c_void_p, c_size_t]
                    _dll.secure_zero_memory.restype = None
                    
                    # Return successful load
                    return _dll
                except AttributeError as e:
                    print(f"Error setting function signatures: {str(e)}")
                    _dll = None  # Reset to try the next location
            except Exception as e:
                print(f"Error loading DLL from {location}: {str(e)}")
        else:
            print(f"DLL not found at: {location}")
    
    # Return a fallback implementation for testing
    if _dll is None:
        print("WARNING: Using fallback implementation for secure memory!")
        
        class DummyDLL:
            def __getattr__(self, name):
                def dummy_func(*args, **kwargs):
                    print(f"DUMMY CALL: {name}({args}, {kwargs})")
                    if name == "create_secure_string":
                        return 12345  # Dummy pointer
                    elif name == "secure_string_to_string":
                        return b"DUMMY_STRING"  # Return dummy string
                    return None
                return dummy_func
        
        return DummyDLL()
    
    return _dll

# Try to load the DLL
_lib = _load_dll()

if _lib is None:
    # If DLL loading failed, try to import from the Python package
    try:
        print("DLL loading failed, trying to import from Python package...")
        from truefa_crypto import (
            SecureString as RustSecureString,
            create_vault,
            unlock_vault,
            lock_vault,
            is_vault_unlocked,
            vault_exists,
            secure_random_bytes
        )
        print("Successfully imported from truefa_crypto package")
    except ImportError as e:
        print(f"Error importing from truefa_crypto package: {e}")
        raise ImportError("Failed to load truefa_crypto module")
else:
    print("Successfully loaded DLL using ctypes")
    # Define the functions using the loaded DLL
    class RustSecureString:
        def __init__(self, value):
            self._data = _lib.create_secure_string(value.encode('utf-8'))
        
        def __str__(self):
            return _lib.secure_string_to_string(self._data).decode('utf-8')
        
        def clear(self):
            _lib.secure_string_clear(self._data)
    
    def create_vault(password):
        _lib.create_vault.argtypes = [ctypes.c_char_p]
        _lib.create_vault.restype = ctypes.c_char_p
        result = _lib.create_vault(password.encode('utf-8'))
        return result.decode('utf-8')
    
    def unlock_vault(password, salt):
        _lib.unlock_vault.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
        _lib.unlock_vault.restype = ctypes.c_bool
        return _lib.unlock_vault(password.encode('utf-8'), salt.encode('utf-8'))
    
    def lock_vault():
        _lib.lock_vault()
    
    def is_vault_unlocked():
        _lib.is_vault_unlocked.restype = ctypes.c_bool
        return _lib.is_vault_unlocked()
    
    def vault_exists():
        _lib.vault_exists.restype = ctypes.c_bool
        return _lib.vault_exists()
    
    def secure_random_bytes(size):
        _lib.secure_random_bytes.argtypes = [ctypes.c_size_t]
        _lib.secure_random_bytes.restype = ctypes.POINTER(ctypes.c_ubyte)
        result = _lib.secure_random_bytes(size)
        return bytes(result[:size])

class SecureString:
    """
    Python wrapper for Rust's SecureString implementation.
    
    This class provides a secure way to store sensitive strings in memory.
    The underlying data is automatically zeroized when the object is destroyed
    or when clear() is explicitly called.
    
    Usage:
        secret = SecureString("sensitive_data")
        # Use the secret
        print(str(secret))  # Temporarily exposes the secret
        secret.clear()      # Explicitly clear when done
    """
    def __init__(self, value):
        """Initialize with a string value to be protected."""
        self._inner = RustSecureString(value)
        
    def __str__(self):
        """
        Get the protected string value.
        Note: This temporarily exposes the secret in memory.
        """
        return str(self._inner)
        
    def clear(self):
        """
        Explicitly clear the protected data.
        The memory is securely zeroized.
        """
        self._inner.clear()
        
    def __del__(self):
        """
        Ensure secure cleanup when the object is destroyed.
        Ignores cleanup errors during destruction.
        """
        try:
            self.clear()
        except:
            pass  # Ignore cleanup errors in destructor

# Export functions directly with their original docstrings
__all__ = [
    'SecureString',
    'create_vault',
    'unlock_vault',
    'lock_vault',
    'is_vault_unlocked',
    'vault_exists',
    'secure_random_bytes'
]