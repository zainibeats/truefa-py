#!/usr/bin/env python
"""
Rust Cryptography Verification Script

This script tests all Rust cryptography functions to verify they are working properly.
It includes detailed diagnostic information to help identify any remaining issues.
"""

import os
import sys
import logging
import binascii

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("crypto_verification")

# Add the src directory to the path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

# Import TrueFA crypto module
from src.truefa_crypto import (
    SecureString,
    create_secure_string,
    secure_random_bytes,
    find_dll,
    get_lib,
    is_using_fallback,
    encrypt_data,
    decrypt_data,
    derive_key,
    hash_password,
    verify_password,
    create_hmac
)

def test_dll_loading():
    """Test if the Rust DLL loads correctly."""
    print("\n=== DLL Loading Test ===")
    dll_path, lib, fallback = find_dll()
    
    if fallback:
        print("❌ Using Python fallback implementation")
        print(f"DLL path: {dll_path}")
    else:
        print("✅ Successfully loaded native Rust DLL")
        print(f"DLL path: {dll_path}")
    
    return not fallback

def test_secure_string():
    """Test SecureString creation and handling."""
    print("\n=== SecureString Test ===")
    
    # Create a secure string
    test_str = "This is a test secure string"
    secure = create_secure_string(test_str)
    
    if secure is None:
        print("❌ Failed to create secure string")
        return False
    
    # Check type
    print(f"SecureString type: {type(secure)}")
    
    # Test string representation (should be masked)
    print(f"String representation: {str(secure)}")
    
    # Test getting the actual value
    try:
        value = secure.get() if hasattr(secure, "get") else str(secure)
        if value == test_str:
            print("✅ Correctly retrieved secure string value")
            return True
        else:
            print(f"❌ Value mismatch: expected '{test_str}', got '{value}'")
            return False
    except Exception as e:
        print(f"❌ Error accessing secure string: {e}")
        return False

def test_random_bytes():
    """Test secure random bytes generation."""
    print("\n=== Secure Random Bytes Test ===")
    
    try:
        # Generate random bytes
        random_bytes = secure_random_bytes(32)
        hex_bytes = binascii.hexlify(random_bytes).decode('utf-8')
        
        print(f"Generated 32 random bytes: {hex_bytes}")
        print(f"Length: {len(random_bytes)} bytes")
        
        if len(random_bytes) == 32:
            print("✅ Successfully generated random bytes")
            return True
        else:
            print(f"❌ Incorrect length: expected 32, got {len(random_bytes)}")
            return False
    except Exception as e:
        print(f"❌ Error generating random bytes: {e}")
        return False

def test_encryption():
    """Test encryption and decryption."""
    print("\n=== Encryption/Decryption Test ===")
    
    try:
        # Generate a test key and data
        key = secure_random_bytes(32)
        data = b"This is test data for encryption and decryption"
        
        # Encrypt the data
        encrypted = encrypt_data(data, key)
        print(f"Encrypted data length: {len(encrypted)} bytes")
        
        # Decrypt the data
        decrypted = decrypt_data(encrypted, key)
        
        if decrypted == data:
            print("✅ Successfully encrypted and decrypted data")
            return True
        else:
            print(f"❌ Decryption mismatch: expected {data}, got {decrypted}")
            return False
    except Exception as e:
        print(f"❌ Error testing encryption: {e}")
        return False

def test_key_derivation():
    """Test key derivation."""
    print("\n=== Key Derivation Test ===")
    
    try:
        # Derive a key from a password
        password = "test_password"
        salt = secure_random_bytes(16)  # Use bytes directly instead of hex string
        
        key = derive_key(password, salt)
        print(f"Derived key length: {len(key)} bytes")
        
        if len(key) > 0:
            print("✅ Successfully derived key from password")
            return True
        else:
            print("❌ Failed to derive key (empty result)")
            return False
    except Exception as e:
        print(f"❌ Error testing key derivation: {e}")
        return False

def main():
    """Run all verification tests."""
    print("TrueFA Rust Cryptography Verification\n")
    
    print(f"Using fallback: {is_using_fallback()}")
    
    # Run tests
    tests = [
        ("DLL Loading", test_dll_loading),
        ("SecureString", test_secure_string),
        ("Random Bytes", test_random_bytes),
        ("Encryption/Decryption", test_encryption),
        ("Key Derivation", test_key_derivation)
    ]
    
    results = []
    
    for name, test_func in tests:
        try:
            result = test_func()
            results.append((name, result))
        except Exception as e:
            print(f"❌ Unexpected error in {name} test: {e}")
            results.append((name, False))
    
    # Print summary
    print("\n=== Test Summary ===")
    
    all_passed = True
    for name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        all_passed = all_passed and result
        print(f"{status}: {name}")
    
    print(f"\nOverall result: {'✅ ALL TESTS PASSED' if all_passed else '❌ SOME TESTS FAILED'}")
    
    return 0 if all_passed else 1

if __name__ == "__main__":
    sys.exit(main()) 