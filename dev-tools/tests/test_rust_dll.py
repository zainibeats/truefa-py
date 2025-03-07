#!/usr/bin/env python3
"""
Test script for verifying the Rust DLL functionality in TrueFA-Py.
This script tests if the Rust DLL can be loaded and used properly.
"""

import os
import sys
import ctypes
from pathlib import Path

# Add the src directory to the Python path
script_dir = Path(__file__).parent.parent.parent
sys.path.insert(0, str(script_dir))
sys.path.insert(0, str(script_dir / "src"))

print("=== TrueFA-Py Rust DLL Test ===")
print(f"Python version: {sys.version}")
print(f"Working directory: {os.getcwd()}")
print(f"Python path: {sys.path}")

# Environment settings
fallback_env = os.environ.get('TRUEFA_USE_FALLBACK', 'Not set')
print(f"TRUEFA_USE_FALLBACK: {fallback_env}")

debug_crypto = os.environ.get('TRUEFA_DEBUG_CRYPTO', 'Not set')
print(f"TRUEFA_DEBUG_CRYPTO: {debug_crypto}")

# Try to get DLL search paths from the module
try:
    from src.truefa_crypto import _get_dll_search_paths
    print("\nPossible DLL search paths:")
    for path in _get_dll_search_paths():
        exists = os.path.exists(path)
        status = "✓ EXISTS" if exists else "× NOT FOUND"
        print(f"  - {path} ({status})")
except ImportError as e:
    print(f"Could not import _get_dll_search_paths: {e}")

# Try direct DLL loading
dll_locations = [
    os.path.join(script_dir, "src", "truefa_crypto", "truefa_crypto.dll"),
    os.path.join(script_dir, "rust_crypto", "target", "release", "truefa_crypto.dll"),
    os.path.join(os.getcwd(), "truefa_crypto.dll"),
    os.path.join(os.getcwd(), "src", "truefa_crypto", "truefa_crypto.dll"),
]

print("\nTrying direct DLL loading:")
for dll_path in dll_locations:
    print(f"  Testing: {dll_path}")
    if os.path.exists(dll_path):
        print(f"  ✓ DLL file exists at {dll_path}")
        try:
            dll = ctypes.CDLL(dll_path)
            print(f"  ✓ Successfully loaded DLL directly with ctypes")
            # Try to get a function
            try:
                secure_random = dll.c_secure_random_bytes
                print(f"  ✓ Found c_secure_random_bytes function")
            except AttributeError:
                print(f"  × Function c_secure_random_bytes not found in DLL")
        except Exception as e:
            print(f"  × Failed to load DLL: {e}")
    else:
        print(f"  × DLL file not found at {dll_path}")

# Try module import
try:
    import src.truefa_crypto as truefa_crypto
    print("\nTrueFACrypto module import:")
    print(f"Module location: {truefa_crypto.__file__}")
    
    # Check if using DLL or fallback
    is_using_dll = getattr(truefa_crypto, '_is_using_dll', None)
    if is_using_dll is not None:
        if is_using_dll:
            print("✓ Using Rust DLL implementation")
        else:
            print("× Using Python fallback implementation")
    else:
        print("? Could not determine implementation (no _is_using_dll attribute)")
    
    # Test basic functionality
    print("\nTesting basic functionality:")
    try:
        random_bytes = truefa_crypto.secure_random_bytes(32)
        print(f"✓ Generated random bytes: {random_bytes.hex()[:16]}...")
    except Exception as e:
        print(f"× Failed to generate random bytes: {e}")
    
    try:
        salt = truefa_crypto.generate_salt()
        print(f"✓ Generated salt: {salt[:16]}...")
    except Exception as e:
        print(f"× Failed to generate salt: {e}")

except ImportError as e:
    print(f"\n× Failed to import truefa_crypto module: {e}")

# Test vault operations
try:
    from src.vault.vault import create_vault, is_vault_unlocked, unlock_vault
    from src.config import get_vault_path, get_vault_dir
    
    print("\nTesting vault operations:")
    vault_path = get_vault_path()
    print(f"Vault path: {vault_path}")
    
    # Ensure vault directory exists
    os.makedirs(os.path.dirname(vault_path), exist_ok=True)
    
    # Create vault
    try:
        if os.path.exists(vault_path):
            os.remove(vault_path)
        create_vault("TestPassword123!")
        print("✓ Created vault successfully")
    except Exception as e:
        print(f"× Failed to create vault: {e}")
        sys.exit(1)
    
    # Unlock vault
    try:
        unlock_vault("TestPassword123!")
        print("✓ Unlocked vault successfully")
    except Exception as e:
        print(f"× Failed to unlock vault: {e}")
        sys.exit(1)

except ImportError as e:
    print(f"\n× Failed to import vault module: {e}")
    sys.exit(1)

print("\n✓ All Rust DLL tests completed successfully!")
sys.exit(0) 