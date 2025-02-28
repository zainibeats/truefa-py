"""
Test script for the TrueFA secure vault functionality
"""

import os
import sys
import base64
import json
from src.security.secure_storage import SecureStorage
from src.security.vault import SecureVault

def main():
    print("=== TrueFA Vault Test ===")
    
    # Create SecureStorage instance with explicit path
    test_storage_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_vault")
    print(f"Using test storage path: {test_storage_path}")
    
    # Create storage directory
    try:
        os.makedirs(test_storage_path, exist_ok=True)
    except OSError as e:
        print(f"Error creating storage directory: {e}")
        sys.exit(1)
    
    # Create vault directory
    vault_dir = os.path.join(test_storage_path, ".vault")
    os.makedirs(vault_dir, exist_ok=True)
    
    # Manually set up vault metadata for testing
    vault_salt = base64.b64encode(os.urandom(32)).decode("utf-8")
    with open(os.path.join(vault_dir, "vault.meta"), "w") as f:
        f.write(json.dumps({
            "salt": vault_salt,
            "version": "1.0",
            "created": "2023-01-01T00:00:00"
        }))
    
    # Create SecureStorage instance
    storage = SecureStorage(storage_path=test_storage_path)
    
    # Test vault creation (since we manually created the metadata, this is a test that our API works)
    print("\nSimulating vault creation...")
    vault_password = "vault-password123"
    master_password = "master-password456"
    
    # Test vault unlock
    print("\nUnlocking vault...")
    unlocked = storage.unlock(vault_password)
    print(f"Vault unlock result: {unlocked}")
    
    # Test encryption/decryption with storage
    print("\nTesting encryption/decryption...")
    original_secret = "SECRETCODE123456"
    
    # Create temp directory for test
    test_dir = os.path.join(test_storage_path, "test")
    try:
        os.makedirs(test_dir, exist_ok=True)
    except OSError as e:
        print(f"Error creating test directory: {e}")
        sys.exit(1)
    
    # Save a secret
    print(f"Saving secret: {original_secret}")
    test_path = os.path.join(test_dir, "test_secret.enc")
    
    try:
        storage.save_encrypted(original_secret, test_path)
        print(f"Secret saved to {test_path}")
    except Exception as e:
        print(f"Error saving secret: {e}")
        sys.exit(1)
    
    # Load the secret
    try:
        loaded_secret = storage.load_encrypted(test_path)
        print(f"Loaded secret: {loaded_secret}")
    except Exception as e:
        print(f"Error loading secret: {e}")
        sys.exit(1)
    
    # Verify match
    if original_secret == loaded_secret:
        print("SUCCESS: Original and loaded secrets match!")
    else:
        print("ERROR: Secrets do not match!")
    
    print("\nTest complete!")

if __name__ == "__main__":
    main()
