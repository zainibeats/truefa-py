#!/usr/bin/env python
"""
Simple Rust Crypto Integration Test

This script performs basic tests of the Rust crypto integration.
It's a simpler version of the comprehensive verify_rust_crypto.py tool.
"""

import os
import sys
import logging

# Set up logging
logging.basicConfig(level=logging.DEBUG, 
                   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("rust_crypto_test")

# Add the src directory to the path - adjust for the new location
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

# Import the crypto module
import src.truefa_crypto as crypto

def main():
    """Test Rust crypto functionality."""
    print("\n===== Testing Rust Crypto Integration =====\n")
    
    # Check if we're using the Rust implementation or the fallback
    print(f"Using fallback implementation: {crypto.is_using_fallback()}")
    
    # Try to create a secure string
    print("\nTesting SecureString creation...")
    test_str = "This is a test secure string"
    secure = crypto.create_secure_string(test_str)
    print(f"SecureString type: {type(secure)}")
    print(f"SecureString representation: {str(secure)}")
    
    # Try to generate random bytes
    print("\nTesting secure random bytes generation...")
    random_bytes = crypto.secure_random_bytes(32)
    print(f"Generated {len(random_bytes)} bytes of random data")
    
    # Try encryption and decryption
    print("\nTesting encryption and decryption...")
    key = crypto.secure_random_bytes(32)
    data = b"Test data for encryption"
    encrypted = crypto.encrypt_data(data, key)
    print(f"Encrypted {len(data)} bytes into {len(encrypted)} bytes")
    
    decrypted = crypto.decrypt_data(encrypted, key)
    print(f"Decrypted back to {len(decrypted)} bytes")
    print(f"Original data: {data}")
    print(f"Decrypted data: {decrypted}")
    print(f"Match: {data == decrypted}")
    
    print("\nTest completed.")
    
if __name__ == "__main__":
    main() 