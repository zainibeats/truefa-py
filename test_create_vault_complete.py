#!/usr/bin/env python
"""
Comprehensive test script to create a complete vault with all required files.
This will help us diagnose issues with vault creation and authentication.
"""

import os
import sys
import json
import datetime
import shutil
import hashlib
import base64
import secrets

def main():
    # Get the vault directory
    vault_dir = os.path.join(os.environ['APPDATA'], 'TrueFA-Py', 'vault')
    vault_path = os.path.join(vault_dir, "vault.json")
    master_path = os.path.join(vault_dir, "master.json")
    master_meta_path = os.path.join(vault_dir, "master.meta")
    state_path = os.path.join(vault_dir, "state.json")
    
    print(f"Using vault directory: {vault_dir}")
    print(f"Vault path: {vault_path}")
    
    # Ensure the vault directory exists
    try:
        os.makedirs(vault_dir, exist_ok=True)
        print(f"Created vault directory: {vault_dir}")
        
        # Verify the directory was created
        if os.path.exists(vault_dir):
            print(f"Confirmed vault directory exists at: {vault_dir}")
        else:
            print(f"ERROR: Failed to create vault directory at: {vault_dir}")
            return
    except Exception as e:
        print(f"Error creating vault directory: {e}")
        return
    
    # Create password hash
    password = "testpassword"
    password_bytes = password.encode('utf-8')
    
    # Generate a salt
    salt_bytes = secrets.token_bytes(16) 
    salt_str = base64.b64encode(salt_bytes).decode('utf-8')
    
    # Hash the password - IMPORTANT: Store as base64 string, not hex!
    password_hash_bytes = hashlib.pbkdf2_hmac(
        'sha256', 
        password_bytes, 
        salt_bytes, 
        100000, 
        dklen=32
    )
    # Convert the hash to base64 to match what verify_password expects
    password_hash_str = base64.b64encode(password_hash_bytes).decode('utf-8')
    
    print(f"Generated salt: {salt_str}")
    print(f"Generated password hash: {password_hash_str}")
    
    # Create a master key - this will be encrypted
    master_key_bytes = secrets.token_bytes(32)  # 32 bytes = 256 bits
    
    # For our simple test, we're using base64 encoding as the "encryption" method
    # This simulates encrypting the master key with the vault key
    master_key_str = base64.b64encode(master_key_bytes).decode('utf-8')
    
    # Create the vault.json file
    vault_data = {
        "version": "1.0",
        "created": datetime.datetime.now().isoformat(),
        "password_hash": password_hash_str,
        "vault_salt": salt_str,
        "salt": salt_str,
        "master_key": master_key_str,  # This is the encrypted master key
        "encrypted_master_key": master_key_str  # Add this field for compatibility
    }
    
    # Save the vault.json file
    try:
        with open(vault_path, 'w') as f:
            json.dump(vault_data, f, indent=2)
        print(f"Created vault.json file at: {vault_path}")
        # Display the vault data for debugging
        print("Vault data:")
        for key, value in vault_data.items():
            print(f"  {key}: {value[:20]}..." if isinstance(value, str) and len(value) > 20 else f"  {key}: {value}")
    except Exception as e:
        print(f"Error creating vault.json: {e}")
    
    # Create the master.json file
    master_data = {
        "salt": salt_str,
        "encrypted_key": master_key_str,
        "version": "1.0"
    }
    
    # Save the master.json file
    try:
        with open(master_path, 'w') as f:
            json.dump(master_data, f, indent=2)
        print(f"Created master.json file at: {master_path}")
    except Exception as e:
        print(f"Error creating master.json: {e}")
    
    # Create the master.meta file
    master_meta_data = {
        "salt": salt_str,
        "encrypted_key": master_key_str,
        "version": "1.0"
    }
    
    # Save the master.meta file
    try:
        with open(master_meta_path, 'w') as f:
            json.dump(master_meta_data, f, indent=2)
        print(f"Created master.meta file at: {master_meta_path}")
    except Exception as e:
        print(f"Error creating master.meta: {e}")
    
    # Create the state.json file
    now = datetime.datetime.now().isoformat()
    state_data = {
        "last_access": now,
        "access_count": 1,
        "created": now,
        "error_states": {
            "bad_password_attempts": 0,
            "tamper_attempts": 0,
            "file_access_errors": 0,
            "integrity_violations": 0,
            "last_error_time": None
        }
    }
    
    # Save the state.json file
    try:
        with open(state_path, 'w') as f:
            json.dump(state_data, f, indent=2)
        print(f"Created state.json file at: {state_path}")
    except Exception as e:
        print(f"Error creating state.json: {e}")
    
    # List all files in the vault directory
    try:
        print(f"Files in vault directory:")
        for file in os.listdir(vault_dir):
            print(f"  - {file}")
    except Exception as e:
        print(f"Error listing files in vault directory: {e}")
        
    # Create a sample secret
    secret_path = os.path.join(vault_dir, "test-secret.enc")
    try:
        with open(secret_path, 'w') as f:
            f.write("This is a test secret")
        print(f"Created test secret at: {secret_path}")
    except Exception as e:
        print(f"Error creating test secret: {e}")

if __name__ == "__main__":
    main() 