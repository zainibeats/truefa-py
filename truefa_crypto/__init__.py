import os
import sys
import ctypes
from pathlib import Path
import warnings

# Define the functions we expect from the Rust library
EXPECTED_FUNCTIONS = [
    'secure_random_bytes',
    'create_vault',
    'unlock_vault',
    'is_vault_unlocked',
    'lock_vault',
    'generate_salt',
    'derive_master_key',
    'encrypt_master_key',
    'decrypt_master_key',
    'create_secure_string',
    'verify_signature'
]

def _find_dll():
    """Attempt to find the truefa_crypto DLL in various locations"""
    search_paths = [
        # Current directory
        os.path.dirname(os.path.abspath(__file__)),
        # Executable directory if frozen
        os.path.dirname(sys.executable) if getattr(sys, 'frozen', False) else None,
        # PyInstaller bundle directory if frozen
        getattr(sys, '_MEIPASS', None),
        # Parent directory
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        # Native extension directory for standard Python
        os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "rust_crypto", "target", "release"),
    ]
    
    dll_names = ["truefa_crypto.dll"] if os.name == 'nt' else ["libtruefa_crypto.so"]
    
    for path in search_paths:
        if not path:
            continue
        
        for dll_name in dll_names:
            dll_path = os.path.join(path, dll_name)
            print(f"Checking for DLL at: {dll_path}")
            
            if os.path.exists(dll_path):
                print(f"DLL found at: {dll_path}")
                return dll_path
                
    return None

def _load_crypto_module():
    """Load the truefa_crypto DLL and set up function signatures"""
    dll_path = _find_dll()
    
    if not dll_path:
        print("WARNING: Could not find truefa_crypto DLL")
        return None
    
    try:
        # Load the DLL
        lib = ctypes.CDLL(dll_path)
        print("Successfully loaded DLL using ctypes")
        
        # Set up function signatures
        try:
            # Check if required functions exist
            missing_funcs = []
            for func_name in EXPECTED_FUNCTIONS:
                if not hasattr(lib, func_name):
                    missing_funcs.append(func_name)
            
            if missing_funcs:
                print(f"Error setting function signatures: function{'s' if len(missing_funcs) > 1 else ''} {', '.join(missing_funcs)} not found")
                return None
                
            # Set up secure_random_bytes function signature
            lib.secure_random_bytes.argtypes = [ctypes.c_int]
            lib.secure_random_bytes.restype = ctypes.POINTER(ctypes.c_uint8)
            
            return lib
            
        except Exception as e:
            print(f"Error setting function signatures: {e}")
            return None
            
    except Exception as e:
        print(f"Error loading DLL: {e}")
        return None

# Try to load the Rust module
_lib = _load_crypto_module()

# If we couldn't load the Rust module, use the fallback implementation
if _lib is None:
    print("WARNING: Using fallback implementation for secure memory!")
    try:
        from .fallback import *
        print("Initialized fallback truefa_crypto module")
    except ImportError:
        print("ERROR: Could not load fallback implementation")
        # Define minimal fallback functions
        def secure_random_bytes(size):
            import os
            return os.urandom(size)
else:
    # Export functions from the Rust module
    def secure_random_bytes(size):
        """Generate cryptographically secure random bytes."""
        return bytes(_lib.secure_random_bytes(size)[:size])
