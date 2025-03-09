#!/usr/bin/env python
"""
TrueFA Crypto DLL Export Verification Script

This script thoroughly verifies that all required FFI functions are exported properly from the 
Rust-built truefa_crypto.dll. It tests both the availability of functions and their basic functionality.
"""

import os
import sys
import time
import ctypes
from ctypes import c_bool, c_void_p, c_int, c_size_t, POINTER, c_char_p, c_ubyte
from pathlib import Path

# Add the project root to the Python path
script_dir = Path(__file__).parent.parent.parent
sys.path.insert(0, str(script_dir))

print("===== TrueFA Crypto DLL Export Verification =====")
print(f"Python version: {sys.version}")
print(f"Working directory: {os.getcwd()}")

# Check possible DLL locations
dll_locations = [
    os.path.join(script_dir, "truefa_crypto", "truefa_crypto.dll"),
    os.path.join(script_dir, "rust_crypto", "target", "release", "truefa_crypto.dll"),
    os.path.join(os.getcwd(), "truefa_crypto", "truefa_crypto.dll"),
    os.path.join(os.getcwd(), "rust_crypto", "target", "release", "truefa_crypto.dll")
]

# Find and load the DLL
print("\nSearching for DLL:")
dll = None
dll_path = None

for location in dll_locations:
    print(f"Checking: {location}")
    if os.path.exists(location):
        dll_path = location
        print(f"✓ DLL found at: {location}")
        try:
            dll = ctypes.CDLL(location)
            print(f"✓ Successfully loaded DLL using ctypes")
            break
        except Exception as e:
            print(f"× Failed to load DLL: {e}")
    else:
        print(f"× DLL not found at this location")

if dll is None:
    print("\n× Failed to load DLL from any location. Exiting.")
    sys.exit(1)

# Check for required exported functions
print("\nVerifying exported C functions:")
required_functions = [
    'c_create_secure_string',
    'c_is_vault_unlocked',
    'c_vault_exists',
    'c_lock_vault',
    'c_secure_random_bytes',
    'c_generate_salt',
    'c_create_vault',
    'c_unlock_vault',
    'c_derive_master_key',
    'c_encrypt_master_key',
    'c_decrypt_master_key'
]

missing_functions = []
for func_name in required_functions:
    try:
        func = getattr(dll, func_name)
        print(f"✓ {func_name}")
    except AttributeError:
        print(f"× {func_name} - NOT FOUND")
        missing_functions.append(func_name)

if missing_functions:
    print(f"\n× Some required functions are missing: {', '.join(missing_functions)}")
else:
    print("\n✓ All required functions are present")

# Set up function signatures for testing
print("\nSetting up function signatures for testing:")
try:
    if hasattr(dll, 'c_vault_exists'):
        dll.c_vault_exists.restype = c_bool
        dll.c_vault_exists.argtypes = []
        print("✓ Set signature for c_vault_exists")
    
    if hasattr(dll, 'c_is_vault_unlocked'):
        dll.c_is_vault_unlocked.restype = c_bool
        dll.c_is_vault_unlocked.argtypes = []
        print("✓ Set signature for c_is_vault_unlocked")
    
    if hasattr(dll, 'c_lock_vault'):
        dll.c_lock_vault.restype = c_bool
        dll.c_lock_vault.argtypes = []
        print("✓ Set signature for c_lock_vault")
    
    if hasattr(dll, 'c_create_secure_string'):
        dll.c_create_secure_string.restype = c_void_p
        dll.c_create_secure_string.argtypes = [c_void_p, c_size_t]
        print("✓ Set signature for c_create_secure_string")
    
    if hasattr(dll, 'c_secure_random_bytes'):
        dll.c_secure_random_bytes.restype = c_bool
        dll.c_secure_random_bytes.argtypes = [c_size_t, POINTER(c_ubyte), POINTER(c_size_t)]
        print("✓ Set signature for c_secure_random_bytes")
except Exception as e:
    print(f"× Error setting function signatures: {e}")

# Perform basic function calls
print("\nTesting basic function calls:")
try:
    # Test c_vault_exists
    if hasattr(dll, 'c_vault_exists'):
        result = dll.c_vault_exists()
        print(f"✓ c_vault_exists() returned: {result}")
    
    # Test c_is_vault_unlocked
    if hasattr(dll, 'c_is_vault_unlocked'):
        result = dll.c_is_vault_unlocked()
        print(f"✓ c_is_vault_unlocked() returned: {result}")
    
    # Test c_create_secure_string
    if hasattr(dll, 'c_create_secure_string'):
        test_string = b"TestSecureString"
        test_buffer = ctypes.create_string_buffer(test_string)
        result = dll.c_create_secure_string(ctypes.cast(test_buffer, c_void_p), len(test_string))
        if result:
            print(f"✓ c_create_secure_string() returned valid pointer: {result}")
        else:
            print(f"× c_create_secure_string() returned NULL pointer")
    
    # Test c_secure_random_bytes
    if hasattr(dll, 'c_secure_random_bytes'):
        buffer_size = 32
        buffer = (c_ubyte * buffer_size)()
        output_size = c_size_t(buffer_size)
        result = dll.c_secure_random_bytes(buffer_size, buffer, ctypes.byref(output_size))
        if result:
            random_bytes = bytes(buffer)
            print(f"✓ c_secure_random_bytes() returned: {random_bytes.hex()[:16]}...")
        else:
            print(f"× c_secure_random_bytes() failed")
    
except Exception as e:
    print(f"× Error during function testing: {e}")

# Try importing the Python module to see if it can use the DLL
print("\nTesting Python module import:")
try:
    sys.path.insert(0, os.getcwd())
    from src.truefa_crypto import find_dll, is_using_fallback
    
    dll_info = find_dll()
    print(f"Module found DLL at: {dll_info[0]}")
    print(f"Using fallback: {is_using_fallback()}")
    
    if not is_using_fallback():
        print("✓ Python module is using native Rust implementation")
    else:
        print("× Python module is using fallback implementation")
    
except Exception as e:
    print(f"× Error importing Python module: {e}")

# Print final summary
if missing_functions:
    print("\n❌ Verification FAILED: Missing required functions")
    for func in missing_functions:
        print(f"  - {func}")
    print("\nThe DLL is not properly exporting all required functions.")
    print("Please rebuild the Rust library and ensure all functions have the #[no_mangle] attribute.")
    sys.exit(1)
else:
    print("\n✅ Verification SUCCESSFUL: All required functions present")
    print("\nThe DLL is correctly exporting all required functions.")
    sys.exit(0) 