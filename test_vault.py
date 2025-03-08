"""
Test script for vault creation and unlocking.

This script:
1. Cleans up existing vault files
2. Creates a new vault
3. Tests unlocking the vault
"""

import os
import sys
import shutil
import traceback
import json
from src.security.vault_interfaces import SecureVault

def clean_vault_files():
    """Remove all vault-related files and directories"""
    print("Step 1: Cleaning up existing vault files...")
    
    # Paths to clean up
    paths_to_clean = [
        os.path.join(os.path.expanduser("~"), "AppData", "Roaming", "TrueFA-Py"),
        os.path.join(os.path.expanduser("~"), "AppData", "Local", "TrueFA-Py"),
        os.path.join(os.path.expanduser("~"), ".truefa"),
        os.path.join(os.path.expanduser("~"), ".truefa_secure"),
        os.path.join("C:\\", "test_vault")
    ]
    
    # Remove each path
    for path in paths_to_clean:
        try:
            if os.path.exists(path):
                if os.path.isdir(path):
                    print(f"Removing directory: {path}")
                    shutil.rmtree(path)
                else:
                    print(f"Removing file: {path}")
                    os.remove(path)
                print(f"Successfully removed: {path}")
            else:
                print(f"Path does not exist: {path}")
        except Exception as e:
            print(f"Error removing {path}: {e}")
            
    print("Cleanup completed.")

def test_vault():
    """Test vault creation and unlocking"""
    print("\nStep 2: Creating and testing vault...")
    
    try:
        # Create a vault
        vault = SecureVault()
        vault_path = os.path.join(vault.vault_dir, "vault.json")
        print(f"Vault path: {vault_path}")
        
        # Create the vault with a test password
        password = "testpassword"
        print(f"Creating vault with password: {password}")
        
        if vault.create_vault(password):
            print("Vault created successfully!")
            
            # Check if the vault file exists
            if os.path.exists(vault_path):
                print(f"Vault file exists at: {vault_path}")
                
                # Read the vault file to check metadata
                try:
                    with open(vault_path, 'r') as f:
                        metadata = json.load(f)
                        print(f"Vault metadata keys: {list(metadata.keys())}")
                except Exception as e:
                    print(f"Error reading vault metadata: {e}")
                    
            else:
                print(f"ERROR: Vault file not found at {vault_path}")
                
            # Test unlocking the vault
            print("\nTesting vault unlock...")
            
            # Create a new vault instance to ensure we're testing from scratch
            new_vault = SecureVault()
            
            # Check if the vault is initialized
            if new_vault.is_initialized:
                print("Vault is initialized correctly")
                
                # Try to unlock with the correct password
                if new_vault.unlock(password):
                    print("Successfully unlocked vault with correct password!")
                else:
                    print("ERROR: Failed to unlock vault with correct password")
                    
                # Try with incorrect password
                if not new_vault.unlock("wrongpassword"):
                    print("Correctly rejected incorrect password")
                else:
                    print("ERROR: Unlocked vault with incorrect password!")
            else:
                print(f"ERROR: New vault instance not initialized")
        else:
            print("ERROR: Failed to create vault")
    except Exception as e:
        print(f"ERROR: Exception in test_vault: {e}")
        traceback.print_exc()

def main():
    """Main function"""
    try:
        # Clean up vault files
        clean_vault_files()
        
        # Test vault creation and unlocking
        test_vault()
        
        return 0
    except Exception as e:
        print(f"Error: {e}")
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main()) 