#!/usr/bin/env python
"""
Test script to create a vault directly using the vault_crypto module.
This will help us diagnose issues with vault creation.
"""

import os
import sys
import json
import datetime
import shutil

# Add the src directory to the path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

def main():
    # Get the vault directory
    vault_dir = os.path.join(os.environ['APPDATA'], 'TrueFA-Py', 'vault')
    vault_path = os.path.join(vault_dir, "vault.json")
    
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
    
    import hashlib
    import base64
    import secrets
    
    # Generate a salt
    salt_bytes = secrets.token_bytes(16) 
    salt_str = base64.b64encode(salt_bytes).decode('utf-8')
    
    # Hash the password
    password_hash_bytes = hashlib.pbkdf2_hmac(
        'sha256', 
        password_bytes, 
        salt_bytes, 
        100000, 
        dklen=32
    )
    password_hash_str = password_hash_bytes.hex()
    
    # Create a master key
    master_key_bytes = secrets.token_bytes(32)  # 32 bytes = 256 bits
    master_key_str = base64.b64encode(master_key_bytes).decode('utf-8')
    
    # Create the vault.json file
    vault_data = {
        "version": "1.0",
        "created": datetime.datetime.now().isoformat(),
        "password_hash": password_hash_str,
        "vault_salt": salt_str,
        "salt": salt_str,
        "master_key": master_key_str
    }
    
    # Save the vault.json file
    try:
        with open(vault_path, 'w') as f:
            json.dump(vault_data, f, indent=2)
        print(f"Created vault.json file at: {vault_path}")
    except Exception as e:
        print(f"Error creating vault.json: {e}")
    
    # Create the master.json file
    master_path = os.path.join(vault_dir, "master.json")
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
    master_meta_path = os.path.join(vault_dir, "master.meta")
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
    state_path = os.path.join(vault_dir, "state.json")
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