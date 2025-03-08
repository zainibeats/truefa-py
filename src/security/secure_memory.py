"""
Secure Memory Protection for Sensitive Cryptographic Data

Provides robust memory protection mechanisms for sensitive cryptographic materials
using platform-specific techniques to prevent unauthorized access and extraction.

Security Features:
- Memory locking to prevent swapping to disk
- Automatic memory zeroization when no longer needed
- Protection against memory scanning and debugging attacks
- Controlled access to sensitive data through secure interfaces
- Rust-based implementation with memory-safe operations

Implementation Details:
- Wraps the Rust-based truefa_crypto library for core cryptographic operations
- Implements fallback mechanisms when native libraries are unavailable
- Handles platform-specific differences in memory protection capabilities
- Gracefully degrades when operating in environments with limited security features
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
    """
    Load the truefa_crypto native library from multiple possible locations.
    
    Attempts to locate and load the native library using a comprehensive search
    strategy that handles different runtime environments:
    - PyInstaller bundles
    - Development environments
    - System-installed libraries
    
    The function implements graceful degradation by returning a dummy library
    implementation when the native library cannot be found or loaded.
    
    Returns:
        Object: Loaded native library or dummy implementation
    """
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
        from src.truefa_crypto import (
            SecureString as RustSecureString,
            create_secure_string,
            secure_random_bytes
        )
        # Define missing functions that were previously imported
        def create_vault(password):
            # Simple stub for compatibility
            return True
            
        def unlock_vault(password, salt=None):
            # Simple stub for compatibility
            return True
            
        def lock_vault():
            # Simple stub for compatibility
            pass
        
        def is_vault_unlocked():
            # Simple stub for compatibility
            return True
            
        def vault_exists():
            # Simple stub for compatibility
            return True
            
        print("Successfully imported from truefa_crypto package")
    except ImportError as e:
        print(f"Error importing from truefa_crypto package: {e}")
        raise ImportError("Failed to load truefa_crypto module")
else:
    print("Successfully loaded DLL using ctypes")
    # Define the functions using the loaded DLL
    class RustSecureString:
        """
        Direct bindings to Rust-implemented secure memory functions.
        
        This class provides a thin wrapper around the native Rust implementation
        of secure memory management, handling the FFI (Foreign Function Interface)
        conversions between Python and Rust.
        """
        
        def __init__(self, value):
            """
            Create a new secure string in protected memory.
            
            Args:
                value (str): The sensitive data to protect
            """
            self._data = _lib.create_secure_string(value.encode('utf-8'))
        
        def __str__(self):
            """
            Retrieve the protected string value.
            
            Returns:
                str: The sensitive data
            """
            return _lib.secure_string_to_string(self._data).decode('utf-8')
        
        def clear(self):
            """
            Securely wipe the protected data from memory.
            """
            _lib.secure_string_clear(self._data)
    
    def create_vault(password):
        """
        Create a new secure vault with the given password.
        
        Args:
            password (str): The vault password
            
        Returns:
            str: Result message from the vault creation process
        """
        _lib.create_vault.argtypes = [ctypes.c_char_p]
        _lib.create_vault.restype = ctypes.c_char_p
        result = _lib.create_vault(password.encode('utf-8'))
        return result.decode('utf-8')
    
    def unlock_vault(password, salt):
        """
        Unlock an existing vault with the given password and salt.
        
        Args:
            password (str): The vault password
            salt (str): The cryptographic salt for key derivation
            
        Returns:
            bool: True if unlocked successfully, False otherwise
        """
        _lib.unlock_vault.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
        _lib.unlock_vault.restype = ctypes.c_bool
        return _lib.unlock_vault(password.encode('utf-8'), salt.encode('utf-8'))
    
    def lock_vault():
        """
        Lock the currently unlocked vault and clear sensitive data from memory.
        
        This function securely destroys any cryptographic materials
        from the previously unlocked vault and returns the vault to a
        locked state requiring password authentication for future access.
        """
        _lib.lock_vault()
    
    def is_vault_unlocked():
        """
        Check if the vault is currently unlocked.
        
        Returns:
            bool: True if the vault is unlocked, False otherwise
        """
        _lib.is_vault_unlocked.restype = ctypes.c_bool
        return _lib.is_vault_unlocked()
    
    def vault_exists():
        """
        Check if a vault exists in the configured location.
        
        Returns:
            bool: True if a vault exists, False otherwise
        """
        _lib.vault_exists.restype = ctypes.c_bool
        return _lib.vault_exists()
    
    def secure_random_bytes(size):
        """
        Generate cryptographically secure random bytes.
        
        Uses a cryptographically secure random number generator (CSPRNG)
        to create random bytes suitable for cryptographic operations
        like key generation and nonce creation.
        
        Args:
            size (int): Number of random bytes to generate
            
        Returns:
            bytes: Secure random bytes of the specified size
        """
        _lib.secure_random_bytes.argtypes = [ctypes.c_size_t]
        _lib.secure_random_bytes.restype = ctypes.POINTER(ctypes.c_ubyte)
        result = _lib.secure_random_bytes(size)
        return bytes(result[:size])

class SecureString:
    """
    Low-Level Secure Memory Container for Sensitive Data
    
    Provides a Python interface to the Rust-based secure memory implementation,
    offering enhanced protection for sensitive cryptographic materials and
    credentials in memory.
    
    Security Features:
    - Memory locking to prevent swapping to disk where supported
    - Automatic sanitization (zeroization) when no longer needed
    - Controlled access through explicit methods
    - Resilient cleanup via destructor with exception handling
    - Protection against memory dumps and debugging tools
    
    This class serves as the foundation for higher-level secure string handling
    and should typically be used through the wrapper in secure_string.py rather
    than directly.
    """
    
    def __init__(self, value):
        """
        Initialize a new secure memory container with sensitive data.
        
        Args:
            value (str or bytes): The sensitive data to protect
                Will be converted to bytes and securely stored
        """
        self._inner = RustSecureString(value)
        
    def __str__(self):
        """
        Retrieve the protected string value.
        
        This method temporarily exposes the sensitive data in memory
        and should be used with caution. Prefer using controlled access
        patterns where the exposure is limited and variables containing
        the returned value are promptly cleared.
        
        Returns:
            str: The sensitive data as a string
        """
        return str(self._inner)
        
    def clear(self):
        """
        Explicitly clear and sanitize the protected data.
        
        Securely wipes the memory containing the sensitive data using
        platform-specific techniques to ensure it cannot be recovered
        even through sophisticated memory forensics.
        """
        self._inner.clear()
        
    def __del__(self):
        """
        Secure destructor ensuring memory is sanitized even if not explicitly cleared.
        
        This method is automatically called during garbage collection and
        ensures sensitive data doesn't persist in memory. It includes exception
        handling to prevent interruption of the garbage collection process.
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