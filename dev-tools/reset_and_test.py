#!/usr/bin/env python
"""
Reset Vault Files and Test Environment

This script:
1. Cleans up existing vault files
2. Creates test instructions
3. Prepares the environment for testing with a clean state
"""

import os
import sys
import shutil
import traceback

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

def create_test_instructions():
    """Create a text file with testing instructions"""
    print("\nStep 2: Creating test instructions...")
    
    instructions = """
TrueFA-Py Testing Instructions
=============================

1. Load QR Code:
   - Select option 1
   - Enter: qrtest.png
   - When prompted, type 'y' to proceed with QR code scanning
   - Press Ctrl+C to stop the code generation

2. Save Secret:
   - Select option 3
   - Accept the default name or enter your own
   - When prompted to create a vault:
     - Enter password: testpassword
     - Confirm password: testpassword
   - The secret should be saved successfully

3. View Saved Secrets:
   - Select option 4
   - You should see the saved secret in the list
   - Select it to view the generated codes
   - Press Ctrl+C to stop and return to the menu

4. Exit:
   - Select option 7 to exit the application

Notes:
- The master password is: testpassword
- If you encounter any issues, note them down
"""
    
    # Write the instructions to a file
    try:
        with open("test_instructions.txt", "w") as f:
            f.write(instructions)
        print("Test instructions created: test_instructions.txt")
    except Exception as e:
        print(f"Error creating test instructions: {e}")

def main():
    """Main function"""
    try:
        # Clean up vault files
        clean_vault_files()
        
        # Create test instructions
        create_test_instructions()
        
        # Inform the user about next steps
        print("\nStep 3: Run the application with a shared storage instance")
        print("Please run: python -m main")
        print("Follow the steps in test_instructions.txt")
        print("The password to use is: testpassword")
        
        return 0
    except Exception as e:
        print(f"Error: {e}")
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main()) 