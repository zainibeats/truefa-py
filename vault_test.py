#!/usr/bin/env python3
"""
Vault Test Script for TrueFA

This script tests the vault functionality of TrueFA to ensure that
the vault is being properly created, unlocked, and that secrets can be saved
and loaded.
"""

import os
import sys
import shutil
from src.security.vault import SecureVault
from src.security.secure_storage import SecureStorage
import truefa_crypto

def test_vault():
    """Test vault creation, unlocking, and key operations."""
    # Create a test directory
    test_dir = os.path.join(os.path.expanduser('~'), '.truefa_test')
    if os.path.exists(test_dir):
        shutil.rmtree(test_dir)
    os.makedirs(test_dir, mode=0o700, exist_ok=True)
    
    # Create a vault instance
    vault = SecureVault(storage_path=test_dir)
    
    # Verify vault status
    print(f"Initial vault status: initialized={vault.is_initialized()}, unlocked={vault.is_unlocked()}")
    
    # Create the vault
    vault_password = "test_password"
    master_password = "test_master"
    print("\nCreating vault...")
    result = vault.create_vault(vault_password, master_password)
    print(f"Vault creation result: {result}")
    print(f"After creation: initialized={vault.is_initialized()}, unlocked={vault.is_unlocked()}")
    
    # Lock the vault
    print("\nLocking vault...")
    vault.lock_vault()
    print(f"After locking: initialized={vault.is_initialized()}, unlocked={vault.is_unlocked()}")
    
    # Unlock the vault
    print("\nUnlocking vault...")
    result = vault.unlock_vault(vault_password)
    print(f"Unlock result: {result}")
    print(f"After unlocking: initialized={vault.is_initialized()}, unlocked={vault.is_unlocked()}")
    
    # Get the master key
    print("\nGetting master key...")
    master_key = vault.get_master_key()
    if master_key:
        print(f"Master key available: {bool(master_key.get())}")
        master_key.clear()
    else:
        print("Failed to get master key")
    
    # Clean up
    shutil.rmtree(test_dir)

def test_secure_storage():
    """Test saving and loading encrypted secrets."""
    # Create a test directory
    test_dir = os.path.join(os.path.expanduser('~'), '.truefa_test')
    if os.path.exists(test_dir):
        shutil.rmtree(test_dir)
    os.makedirs(test_dir, mode=0o700, exist_ok=True)
    
    # Initialize secure storage
    storage = SecureStorage()
    storage.storage_path = test_dir
    
    # Set up vault
    print("\nSetting up vault for secure storage...")
    vault_password = "test_password"
    master_password = "test_master"
    
    # Create and unlock the vault
    print("Creating vault...")
    storage.vault.create_vault(vault_password, master_password)
    print("Unlocking vault...")
    storage.vault.unlock_vault(vault_password)
    storage._unlock()
    
    # Set the master key from the vault
    master_key = storage.vault.get_master_key()
    if master_key and master_key.get():
        try:
            import base64
            # Handle potential padding issues
            key_str = master_key.get()
            # Add padding if needed
            padding = 4 - (len(key_str) % 4) if len(key_str) % 4 else 0
            key_str = key_str + ('=' * padding)
            storage.key = base64.b64decode(key_str.encode())
            master_key.clear()
            print("Master key set from vault")
        except Exception as e:
            print(f"Error decoding master key: {e}")
            storage.key = os.urandom(32)  # Use a random key for testing
            print("Using random key for testing")
    else:
        print("Failed to get master key from vault")
        return
    
    # Save a test secret
    print("\nSaving test secret...")
    secret_name = "test_secret"
    secret_value = "ABCDEFGHIJKLMNOP"
    result = storage.save_secret(secret_name, secret_value)
    print(f"Save result: {result}")
    
    # Load the secret
    print("\nLoading test secret...")
    encrypted_secret = storage.load_secret(secret_name)
    if encrypted_secret:
        print(f"Loaded encrypted secret: {encrypted_secret is not None}")
        try:
            decrypted_secret = storage.decrypt_secret(encrypted_secret, secret_name)
            print(f"Decryption successful: {decrypted_secret == secret_value}")
        except Exception as e:
            print(f"Error decrypting secret: {e}")
    else:
        print("Failed to load secret")
    
    # Clean up
    shutil.rmtree(test_dir)

if __name__ == "__main__":
    print("=== Testing TrueFA Vault Functionality ===")
    print("\n--- Vault Test ---")
    test_vault()
    print("\n--- Secure Storage Test ---")
    test_secure_storage()
    print("\n=== Tests Complete ===")
