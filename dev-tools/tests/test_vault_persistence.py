#!/usr/bin/env python3
"""
Test script for verifying vault creation and persistence in TrueFA-Py.
This script tests both initial vault creation and subsequent access.
"""

import os
import sys
import time
import json
from pathlib import Path

# Add the src directory to the Python path
script_dir = Path(__file__).parent.parent.parent
sys.path.insert(0, str(script_dir))
sys.path.insert(0, str(script_dir / "src"))

# Display Python paths for debugging
print(f"Python path: {sys.path}")
print(f"Working directory: {os.getcwd()}")

try:
    from src.truefa_crypto import secure_random_bytes, generate_salt
    from src.vault.vault import create_vault, is_vault_unlocked, unlock_vault, list_accounts, add_account
    from src.config import get_vault_path, get_vault_dir
except ImportError as e:
    print(f"Import error: {e}")
    # Try alternative import path
    try:
        print("Trying alternative import path...")
        from truefa_crypto import secure_random_bytes, generate_salt
        from vault.vault import create_vault, is_vault_unlocked, unlock_vault, list_accounts, add_account
        from config import get_vault_path, get_vault_dir
        print("Alternative import path successful")
    except ImportError as e2:
        print(f"Alternative import also failed: {e2}")
        # List available modules to help diagnose
        print("\nAvailable modules in directory:")
        for root, dirs, files in os.walk("src"):
            for file in files:
                if file.endswith(".py"):
                    print(f"  {os.path.join(root, file)}")
        sys.exit(1)

def setup_environment():
    """Set up the environment for testing."""
    print(f"Python version: {sys.version}")
    print(f"Using Python fallback: {os.environ.get('TRUEFA_USE_FALLBACK', 'Not set')}")
    print(f"Data directory: {os.environ.get('TRUEFA_DATA_DIR', 'Not set')}")
    
    # Get vault information
    vault_path = get_vault_path()
    vault_dir = get_vault_dir()
    print(f"Vault path: {vault_path}")
    print(f"Vault directory: {vault_dir}")
    
    # Ensure the vault directory exists
    os.makedirs(vault_dir, exist_ok=True)
    
    # Check if the vault already exists
    if os.path.exists(vault_path):
        print(f"Removing existing vault for clean test...")
        os.remove(vault_path)

def test_vault_creation():
    """Test creating a new vault and verifying it exists."""
    print("\nTesting vault creation...")
    
    # Generate a test password
    test_password = "TestPassword123!"
    
    # Get the vault path
    vault_path = get_vault_path()
    
    # Create the vault
    try:
        print("Creating new vault...")
        create_vault(test_password)
        print("✓ Vault created successfully")
    except Exception as e:
        print(f"✗ Failed to create vault: {e}")
        return False
    
    # Verify the vault file exists
    if not os.path.exists(vault_path):
        print(f"✗ Vault file does not exist after creation at {vault_path}")
        return False
    print(f"✓ Vault file exists at {vault_path}")
    
    # Try to unlock the vault
    try:
        print("Testing vault unlock...")
        if not unlock_vault(test_password):
            print("✗ Failed to unlock vault")
            return False
        print("✓ Vault unlocked successfully")
    except Exception as e:
        print(f"✗ Failed to unlock vault: {e}")
        return False
    
    # Verify vault is unlocked
    if not is_vault_unlocked():
        print("✗ Vault is not showing as unlocked")
        return False
    print("✓ Vault shows as unlocked")
    
    # Add a test account
    try:
        print("Adding test account...")
        add_account("Test Service", "JBSWY3DPEHPK3PXP", "test@example.com")
        print("✓ Test account added successfully")
    except Exception as e:
        print(f"✗ Failed to add test account: {e}")
        return False
    
    return True

def test_vault_persistence():
    """Test that the vault remains accessible after creation."""
    print("\nTesting vault persistence...")
    
    # Get the vault path
    vault_path = get_vault_path()
    
    # Verify the vault file still exists
    if not os.path.exists(vault_path):
        print(f"✗ Vault file does not exist during persistence check at {vault_path}")
        print(f"Directory contents: {os.listdir(os.path.dirname(vault_path))}")
        return False
    print("✓ Vault file exists")
    
    # Password used in creation
    test_password = "TestPassword123!"
    
    # Try to unlock the vault again
    try:
        print("Testing vault unlock with same password...")
        if not unlock_vault(test_password):
            print("✗ Failed to unlock existing vault")
            return False
        print("✓ Existing vault unlocked successfully")
    except Exception as e:
        print(f"✗ Failed to unlock existing vault: {e}")
        return False
    
    # Verify the account we added is still there
    try:
        print("Checking for previously added account...")
        accounts = list_accounts()
        
        if not any(a.get('service') == 'Test Service' for a in accounts):
            print("✗ Previously added account not found")
            print(f"Accounts found: {json.dumps(accounts, indent=2)}")
            return False
        print("✓ Previously added account found")
    except Exception as e:
        print(f"✗ Failed to list accounts: {e}")
        return False
    
    return True

def main():
    """Main test function."""
    print("=== TrueFA-Py Vault Creation and Persistence Test ===")
    
    # Set up test environment
    setup_environment()
    
    # Test initial vault creation
    if not test_vault_creation():
        print("\n✗ Vault creation test failed")
        sys.exit(1)
    
    # Wait a moment to simulate program restart
    print("\nWaiting 2 seconds to simulate program restart...")
    time.sleep(2)
    
    # Test vault persistence
    if not test_vault_persistence():
        print("\n✗ Vault persistence test failed")
        sys.exit(1)
    
    print("\n✓ All vault tests passed successfully!")
    sys.exit(0)

if __name__ == "__main__":
    main() 