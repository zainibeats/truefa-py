#!/usr/bin/env python
"""
Test script to test unlocking the vault and decrypting the master key.
This will help diagnose issues with the vault decryption process.
"""

import os
import sys
import json
import base64
import hashlib

# Add the src directory to the path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

def main():
    # Import vault modules
    from src.security import vault_crypto
    
    # Define test values
    password = "testpassword"
    vault_dir = os.path.join(os.environ['APPDATA'], 'TrueFA-Py', 'vault')
    vault_path = os.path.join(vault_dir, "vault.json")
    
    print(f"Using vault path: {vault_path}")
    
    # Check if vault exists
    if not os.path.exists(vault_path):
        print(f"Vault not found at {vault_path}")
        return
    
    print("Vault exists, loading metadata...")
    
    # Load vault metadata
    try:
        with open(vault_path, 'r') as f:
            metadata = json.load(f)
    except Exception as e:
        print(f"Error loading vault metadata: {e}")
        return
    
    print(f"Vault metadata keys: {list(metadata.keys())}")
    
    # Set the vault path in the module
    vault_crypto.set_vault_path(vault_path)
    
    # Unlock the vault
    print(f"Unlocking vault with password: {password}")
    result = vault_crypto.unlock_vault(password)
    
    if result:
        print("Vault unlocked successfully!")
        
        # Get the master key
        master_key = metadata.get('master_key')
        if not master_key:
            print("Master key not found in metadata!")
            return
        
        print(f"Encrypted master key: {master_key[:20]}...")
        
        # Try to decrypt the master key
        decrypted = vault_crypto.decrypt_master_key(master_key)
        
        if decrypted:
            print(f"Successfully decrypted master key: {type(decrypted)}, length: {len(decrypted)}")
        else:
            print("Failed to decrypt master key")
    else:
        print("Failed to unlock vault")

if __name__ == "__main__":
    main() 