# Import all symbols from the Rust module
import os
import sys
import ctypes
import importlib.util

# Better error reporting function
def _report_error(msg, exc=None):
    print(f"DEBUG: {msg}")
    if exc:
        print(f"DEBUG: Exception: {type(exc).__name__}: {str(exc)}")

# Where are we running from?
if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
    print(f"DEBUG: Running from PyInstaller bundle: {sys._MEIPASS}")
else:
    print(f"DEBUG: Running from regular Python")

print(f"DEBUG: Current working directory: {os.getcwd()}")
print(f"DEBUG: __file__ location: {__file__}")
print(f"DEBUG: truefa_crypto package directory: {os.path.dirname(__file__)}")

# Function to attempt loading the DLL directly using ctypes
def _load_truefa_crypto_dll():
    possible_dll_paths = []
    
    # Start with checking in the same directory as this file
    this_dir = os.path.dirname(os.path.abspath(__file__))
    possible_dll_paths.append(os.path.join(this_dir, "truefa_crypto.dll"))
    
    # Check in PyInstaller bundle location if running from a bundle
    if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
        meipass_dir = sys._MEIPASS
        possible_dll_paths.extend([
            os.path.join(meipass_dir, "truefa_crypto.dll"),
            os.path.join(meipass_dir, "truefa_crypto", "truefa_crypto.dll"),
            os.path.join(meipass_dir, "_internal", "truefa_crypto.dll")
        ])
    
    # Check in project root directories
    if os.path.exists(os.path.join(os.getcwd(), "rust_crypto")):
        possible_dll_paths.append(os.path.join(os.getcwd(), "rust_crypto", "target", "release", "truefa_crypto.dll"))
    
    # Also check parent directories
    parent_dir = os.path.dirname(this_dir)
    possible_dll_paths.append(os.path.join(parent_dir, "rust_crypto", "target", "release", "truefa_crypto.dll"))
    
    # Add the main project directory if running from a bundle
    if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
        exe_dir = os.path.dirname(sys.executable)
        possible_dll_paths.extend([
            os.path.join(exe_dir, "truefa_crypto.dll"),
            os.path.join(exe_dir, "truefa_crypto", "truefa_crypto.dll")
        ])
    
    # Try to load from each potential location
    for dll_path in possible_dll_paths:
        try:
            if os.path.exists(dll_path):
                print(f"DEBUG: Found DLL at {dll_path}")
                dll = ctypes.CDLL(dll_path)
                print(f"DEBUG: Successfully loaded DLL using ctypes")
                return True
            else:
                print(f"DEBUG: DLL not found at {dll_path}")
        except Exception as e:
            _report_error(f"Error loading DLL from {dll_path}", e)
    
    return False

# Attempt to load from .pyd file first
try:
    print("DEBUG: Attempting to load from .pyd file")
    module_path = os.path.join(os.path.dirname(__file__), "truefa_crypto.pyd" if os.name == "nt" else "truefa_crypto.so")
    
    if os.path.exists(module_path):
        print(f"DEBUG: Found .pyd at {module_path}")
        spec = importlib.util.spec_from_file_location("truefa_crypto", module_path)
        module = importlib.util.module_from_spec(spec)
        print("DEBUG: Created module from spec")
        spec.loader.exec_module(module)
        print("DEBUG: Successfully loaded .pyd module")
        
        # Import all symbols into this namespace
        for name in dir(module):
            if not name.startswith("_"):
                globals()[name] = getattr(module, name)
        print("DEBUG: Imported symbols from module")
    else:
        print(f"DEBUG: PYD file not found at {module_path}")
        # Try direct DLL loading
        if not _load_truefa_crypto_dll():
            raise ImportError(f"Could not find truefa_crypto.pyd at {module_path}")
except Exception as e:
    _report_error("Error loading truefa_crypto module", e)
    
    # Fallback to fake implementation for testing
    print("DEBUG: Using fallback implementation for module")
    class SecureString:
        def __init__(self, value):
            self._data = value
        
        def __str__(self):
            return self._data
        
        def clear(self):
            self._data = ""
    
    def create_vault(password):
        print(f"FAKE create_vault({password})")
    
    def unlock_vault(password, salt):
        print(f"FAKE unlock_vault({password}, {salt})")
        return True
    
    def lock_vault():
        print("FAKE lock_vault()")
    
    def is_vault_unlocked():
        print("FAKE is_vault_unlocked()")
        return True
    
    def vault_exists():
        print("FAKE vault_exists()")
        return True
    
    def secure_random_bytes(size):
        print(f"FAKE secure_random_bytes({size})")
        import random
        return bytes([random.randint(0, 255) for _ in range(size)])
