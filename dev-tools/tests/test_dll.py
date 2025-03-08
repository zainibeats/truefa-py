#!/usr/bin/env python3
"""
Test script to debug the Rust DLL loading
"""

import os
import sys
import ctypes
import traceback

def main():
    """Test DLL loading and function availability"""
    print("Starting Rust DLL loading test...")
    print(f"Current working directory: {os.getcwd()}")
    
    # Check for the DLL in various locations
    possible_locations = [
        os.path.join(os.getcwd(), "truefa_crypto.dll"),
        os.path.join(os.getcwd(), "truefa_crypto", "truefa_crypto.dll"),
        os.path.join(os.getcwd(), "rust_crypto", "target", "release", "truefa_crypto.dll"),
    ]
    
    dll_path = None
    for location in possible_locations:
        if os.path.exists(location):
            print(f"DLL found at: {location}")
            dll_path = location
            break
    
    if not dll_path:
        print("ERROR: DLL not found!")
        return
    
    # Try to load the DLL
    try:
        lib = ctypes.CDLL(dll_path)
        print(f"Successfully loaded DLL from {dll_path}")
        
        # Print all available functions
        print("\nAvailable functions in DLL:")
        for func_name in dir(lib):
            if not func_name.startswith("_"):
                print(f"  - {func_name}")
        
        # Try to call a few functions
        print("\nTesting specific functions:")
        functions_to_test = [
            'c_secure_random_bytes',
            'c_create_secure_string',
            'c_vault_exists',
            'c_generate_salt',
            'c_encrypt_data',
            'c_decrypt_data'
        ]
        
        for func_name in functions_to_test:
            if hasattr(lib, func_name):
                print(f"  ✓ Function {func_name} exists")
                
                # Set up signatures for testing
                if func_name == 'c_secure_random_bytes':
                    try:
                        lib.c_secure_random_bytes.argtypes = [
                            ctypes.c_size_t,
                            ctypes.POINTER(ctypes.c_ubyte),
                            ctypes.POINTER(ctypes.c_size_t)
                        ]
                        lib.c_secure_random_bytes.restype = ctypes.c_bool
                        print(f"    - Signature set for {func_name}")
                    except Exception as e:
                        print(f"    - Error setting signature: {e}")
                
                if func_name == 'c_generate_salt':
                    try:
                        lib.c_generate_salt.argtypes = [
                            ctypes.POINTER(ctypes.c_ubyte),
                            ctypes.POINTER(ctypes.c_size_t)
                        ]
                        lib.c_generate_salt.restype = ctypes.c_bool
                        print(f"    - Signature set for {func_name}")
                    except Exception as e:
                        print(f"    - Error setting signature: {e}")
            else:
                print(f"  ✗ Function {func_name} NOT found")
        
        # Try to import truefa_crypto to see how it would work
        print("\nTrying to import truefa_crypto module:")
        try:
            sys.path.insert(0, os.getcwd())
            import truefa_crypto
            print("Successfully imported truefa_crypto module")
            
            # Check what functions are available
            print("\nAvailable functions in truefa_crypto module:")
            for func_name in dir(truefa_crypto):
                if not func_name.startswith("_") and callable(getattr(truefa_crypto, func_name)):
                    print(f"  - {func_name}")
            
            # Check if using fallback
            fallback = getattr(truefa_crypto, 'is_using_fallback', lambda: True)()
            print(f"\nUsing fallback: {fallback}")
            
        except Exception as e:
            print(f"ERROR importing truefa_crypto: {e}")
            traceback.print_exc()
    
    except Exception as e:
        print(f"ERROR loading DLL: {e}")
        traceback.print_exc()

if __name__ == "__main__":
    main() 