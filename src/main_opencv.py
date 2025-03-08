"""
TrueFA-Py: Two-Factor Authentication Utility

A secure, offline TOTP authenticator implementing RFC 6238 with robust
security features and privacy-focused design:

- QR code processing via OpenCV for reliable code extraction
- Vault-based secret storage with strong encryption
- Hybrid cryptographic implementation (Rust & Python fallback)
- Zero network connectivity for enhanced privacy
- Memory protection for sensitive information
- Command-line interface with intuitive navigation

Architecture:
- Two-layer security with master key and vault password
- Automatic memory sanitization for sensitive data
- Platform-specific secure storage locations
- Cross-platform compatibility via intelligent fallback mechanism
"""

import sys
import time
import os
from pathlib import Path
import urllib.parse
import traceback
import getpass  # Add getpass module for secure password input
import argparse

# Import our configuration
try:
    from config import DATA_DIR, VAULT_FILE
except ImportError:
    # Create a minimal config if the module isn't found
    DATA_DIR = os.path.join(os.path.expanduser("~"), ".truefa")
    VAULT_FILE = os.path.join(DATA_DIR, "vault.json")

# Use absolute imports instead of relative imports
from src.security.secure_storage import SecureStorage
from src.security.secure_string import SecureString
from src.totp.auth_opencv import TwoFactorAuth
from src.utils.screen import clear_screen

def main():
    """
    Main entry point for the application.
    
    Returns:
        int: 0 for successful execution, non-zero for errors
    """
    try:
        print("Importing modules...")
        
        # Check if we're running in a compiled binary or as a regular Python script
        if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
            bundle_dir = getattr(sys, '_MEIPASS')
            app_dir = os.path.dirname(sys.executable)
            print(f"Running from PyInstaller bundle. App dir: {app_dir}, Bundle dir: {bundle_dir}")
        else:
            print(f"Running from regular Python. Searching in: {os.getcwd()}")
            print(f"Current working directory: {os.getcwd()}")
        
        # Import required modules
        try:
            import cv2
            print("OpenCV imported successfully")
        except ImportError:
            print("Warning: OpenCV not found. QR code scanning will be disabled.")
        
        print("Creating SecureVault...")
        # Create the vault and secure storage
        vault = SecureVault()
        print(f"SecureVault created successfully")
        
        print("Creating SecureStorage...")
        # Create a shared storage instance that will be used by both the main app and TwoFactorAuth
        secure_storage = SecureStorage(vault)
        print(f"SecureStorage created successfully")
        
        print("Creating TwoFactorAuth...")
        # Pass the shared storage instance to TwoFactorAuth
        auth = TwoFactorAuth(storage=secure_storage)
        print(f"TwoFactorAuth created successfully")
        
        # Add object ID debugging
        print(f"DEBUG: Main app storage object id: {id(secure_storage)}")
        print(f"DEBUG: Main app vault object id: {id(secure_storage.vault)}")
        
        # Debug the auth storage
        print(f"DEBUG: Auth storage object id: {id(auth.storage)}")
        print(f"DEBUG: Auth vault object id: {id(auth.storage.vault)}")
        
        # Check if these are the same objects
        print(f"DEBUG: Storage objects are the same: {id(secure_storage) == id(auth.storage)}")
        print(f"DEBUG: Vault objects are the same: {id(secure_storage.vault) == id(auth.storage.vault)}")

        # Check if vault exists
        debug_vault_status(secure_storage)
        
        # Process command-line arguments for non-interactive operations
        if len(sys.argv) > 1:
            # ... existing command-line handling code ...
            pass

        # Main interactive loop
        while True:
            try:
                # Display menu
                # ... existing menu code ...
                pass
            except KeyboardInterrupt:
                print("\nExiting TrueFA. Goodbye!")
                break
            except Exception as e:
                print(f"Error in main loop: {e}")
                traceback.print_exc()
                
        print("Exiting securely...")
        return 0
        
    except Exception as e:
        print(f"Fatal error: {e}")
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="TrueFA-Py OpenCV Edition")
    parser.add_argument("--use-fallback", action="store_true", help="Force use of Python fallback for crypto operations")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument("--create-vault", action="store_true", help="Create a new vault")
    parser.add_argument("--vault-dir", type=str, help="Directory to store the vault in")
    parser.add_argument("--version", action="store_true", help="Show version information and exit")
    args = parser.parse_args()
    
    if args.use_fallback:
        print("Forcing use of Python fallback for crypto operations")
        # Set environment variable before imports
        import os
        os.environ["TRUEFA_USE_FALLBACK"] = "true"
    
    if args.debug:
        import logging
        logging.basicConfig(level=logging.DEBUG)
        print("Debug logging enabled")
    
    sys.exit(main())
