"""
Test script to diagnose DLL loading issues
"""
import ctypes
import os
import sys

def test_dll_loading():
    """Test loading the Rust DLL and accessing its functions"""
    dll_path = os.path.join(os.path.dirname(__file__), 'rust_crypto', 'target', 'release', 'truefa_crypto.dll')
    
    print(f"Checking DLL at: {dll_path}")
    print(f"File exists: {os.path.exists(dll_path)}")
    
    if not os.path.exists(dll_path):
        print("DLL file not found!")
        return
    
    try:
        # Load the DLL
        lib = ctypes.CDLL(dll_path)
        print("Successfully loaded DLL!")
        
        # List available functions
        print("\nAvailable functions:")
        for name in dir(lib):
            if not name.startswith('_'):
                print(f"  - {name}")
        
        # Check for specific functions
        functions_to_check = [
            'c_create_secure_string',
            'c_secure_random_bytes',
            'c_create_vault',
            'c_unlock_vault'
        ]
        
        print("\nChecking for specific functions:")
        for func_name in functions_to_check:
            has_func = hasattr(lib, func_name)
            print(f"  - {func_name}: {'Found' if has_func else 'Not found'}")
        
    except Exception as e:
        print(f"Error loading DLL: {e}")

if __name__ == "__main__":
    test_dll_loading()
