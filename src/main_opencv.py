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

# Configure logging before imports
import logging
logging.basicConfig(level=logging.ERROR)
logging.getLogger('truefa_crypto').setLevel(logging.ERROR)
logging.getLogger('truefa_crypto.loader').setLevel(logging.ERROR)

import sys
import time
import os
from pathlib import Path
import urllib.parse
import traceback
import getpass  # Add getpass module for secure password input
import argparse
import signal
import shutil
import platform

# Import our configuration
try:
    from config import DATA_DIR, VAULT_FILE, TEMP_DIR, IS_PYINSTALLER, LOG_TO_FILE, LOG_DIRECTORY
except ImportError:
    # Create a minimal config if the module isn't found
    DATA_DIR = os.path.join(os.path.expanduser("~"), ".truefa")
    VAULT_FILE = os.path.join(DATA_DIR, "vault.json")
    TEMP_DIR = os.path.join(DATA_DIR, "temp")
    IS_PYINSTALLER = False
    LOG_TO_FILE = True
    LOG_DIRECTORY = os.path.join(DATA_DIR, "logs")

# Use absolute imports instead of relative imports
from src.security.secure_storage import SecureStorage
from src.security.secure_string import SecureString
from src.totp.auth_opencv import TwoFactorAuth
from src.utils.screen import clear_screen
from src.utils.debug import debug_print, set_debug, close_logging
from src.security.vault_interfaces import SecureVault  # Add this import for SecureVault

# Initialize debug from environment variable (will be overridden by command-line args if provided)
if os.environ.get('TRUEFA_DEBUG', '').lower() in ('1', 'true', 'yes'):
    set_debug(True)

def debug_vault_status(storage):
    """Print debug information about vault status."""
    debug_print("Vault status:")
    debug_print(f"  Initialized: {storage.is_initialized}")
    debug_print(f"  Unlocked: {storage.is_unlocked}")

# Set up signal handlers for clean exits
def signal_handler(sig, frame):
    """Handle signals for proper shutdown."""
    debug_print("\nExiting due to signal...")
    # Call the exit function to clean up sensitive material
    sys.exit(0)

# Register signal handlers
try:
    signal.signal(signal.SIGINT, signal_handler)
    if platform.system() != "Windows":
        signal.signal(signal.SIGHUP, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
except (AttributeError, ValueError):
    # Some signals may not be available on all platforms
    pass

def main():
    """
    Main entry point for the application.
    
    Returns:
        int: 0 for successful execution, non-zero for errors
    """
    try:
        # Parse command-line arguments for debug mode
        parser = argparse.ArgumentParser(description="TrueFA-Py: TOTP Authenticator with OpenCV")
        parser.add_argument("--use-fallback", action="store_true", help="Force use of Python fallback for crypto operations")
        parser.add_argument("--debug", action="store_true", help="Enable debug logging")
        parser.add_argument("--create-vault", action="store_true", help="Create a new vault")
        parser.add_argument("--vault-dir", type=str, help="Directory to store the vault in")
        parser.add_argument("--version", action="store_true", help="Show version information and exit")
        args = parser.parse_args()
        
        # Force Python fallback if requested
        if args.use_fallback:
            # Set environment variable before imports to force fallback
            os.environ["TRUEFA_USE_FALLBACK"] = "true"
            debug_print("Forcing use of Python fallback for crypto operations")
        
        # Set debug mode based on args
        if args.debug:
            set_debug(True)
            debug_print("Debug logging enabled")
            debug_print("Debug system initialized and working")
            debug_print("Importing modules...")
            # Configure logging for debug mode - show INFO and above
            logging.basicConfig(level=logging.INFO)
            # Allow truefa_crypto logs in debug mode
            logging.getLogger('truefa_crypto').setLevel(logging.INFO)
            logging.getLogger('truefa_crypto.loader').setLevel(logging.INFO)
        else:
            # Already configured at ERROR level at the beginning of the file
            pass

        # Initialize debug output based on command line args
        debug_print(f"Running from regular Python. Searching in: {os.getcwd()}")
        debug_print(f"Current working directory: {os.getcwd()}")
        
        # Import our debug utilities but don't enable debug yet
        # (we'll do that below based on command-line args)
        debug_print("Importing modules...")
        
        # Check if we're running in a compiled binary or as a regular Python script
        if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
            bundle_dir = getattr(sys, '_MEIPASS')
            app_dir = os.path.dirname(sys.executable)
            debug_print(f"Running from PyInstaller bundle. App dir: {app_dir}, Bundle dir: {bundle_dir}")
        else:
            debug_print(f"Running from regular Python. Searching in: {os.getcwd()}")
            debug_print(f"Current working directory: {os.getcwd()}")
        
        # Try to import OpenCV
        try:
            import cv2
            debug_print("OpenCV imported successfully")
        except ImportError:
            print("Warning: OpenCV not found. QR code scanning will be disabled.")
        
        # Create the secure vault
        debug_print("Creating SecureVault...")
        secure_vault = SecureVault(args.vault_dir)
        debug_print("SecureVault created successfully")
        
        # Create secure storage
        debug_print("Creating SecureStorage...")
        secure_storage = SecureStorage(secure_vault)
        debug_print("SecureStorage created successfully")
        
        # Create authentication handler
        debug_print("Creating TwoFactorAuth...")
        auth = TwoFactorAuth(secure_storage)
        debug_print("TwoFactorAuth created successfully")
        
        # Add object ID debugging
        debug_print(f"Main app storage object id: {id(secure_storage)}")
        debug_print(f"Main app vault object id: {id(secure_storage.vault)}")
        
        # Debug the auth storage
        debug_print(f"Auth storage object id: {id(auth.storage)}")
        debug_print(f"Auth vault object id: {id(auth.storage.vault)}")
        
        # Check if these are the same objects
        debug_print(f"Storage objects are the same: {id(secure_storage) == id(auth.storage)}")
        debug_print(f"Vault objects are the same: {id(secure_storage.vault) == id(auth.storage.vault)}")

        # Check if vault exists
        debug_vault_status(secure_storage)
        
        # Check for version flag
        if args.version:
            print("TrueFA-Py OpenCV Edition")
            print("Version: 1.0.0")
            print(f"Platform: {sys.platform}")
            if hasattr(sys, 'frozen'):
                print("Running from frozen executable")
            else:
                print("Using Python fallback implementations for crypto functions")
            print("Exiting securely...")
            return 0

        # Main interactive loop
        while True:
            try:
                # Display menu
                print("\n=== TrueFA ===")
                print("1. Load QR code from image")
                print("2. Enter secret key manually")
                print("3. Save current secret")
                print("4. View saved secrets")
                print("5. Export secrets")
                print("6. Import secrets")
                print("7. Clear screen")
                print("8. Exit")
                print("\n")
                
                choice = input("Enter your choice (1-8): ")
                
                if choice == '8':
                    print("Exiting application...")
                    break
                elif choice == '7':
                    clear_screen()
                elif choice == '5':
                    # Export secrets
                    if not secure_storage.is_unlocked:
                        master_password = getpass.getpass("Enter your vault password: ")
                        if not secure_storage.unlock_vault(master_password):
                            print("Failed to unlock vault. Incorrect password.")
                            continue
                        print("Vault unlocked successfully.")
                    
                    # Get export path
                    export_path = input("Enter path for export file (or press Enter for default): ")
                    # Don't set a default path here, let secure_storage.export_secrets handle it
                    # This will use the exports directory inside the vault path
                    
                    # Get export password
                    export_password = getpass.getpass("Enter password to encrypt export: ")
                    confirm_password = getpass.getpass("Confirm password: ")
                    
                    if export_password != confirm_password:
                        print("Passwords do not match. Export cancelled.")
                        continue
                        
                    # Perform the export
                    success, message = secure_storage.export_secrets(export_path, export_password)
                    
                    if success:
                        print(f"Secrets exported successfully to {export_path}")
                        print("Note: This file is encrypted with your password and compatible with other authenticator apps.")
                    else:
                        print(f"Export failed: {message}")
                elif choice == '6':
                    # Import secrets
                    # First check if vault exists and needs to be created
                    debug_print("Checking vault initialization before import...")
                    
                    if not secure_storage.is_initialized:
                        # No vault exists yet, need to create one
                        print("\nNo vault found. You need to create a vault before importing secrets.")
                        
                        # Ask for master password and create vault
                        master_password = getpass.getpass("Create a master password for your vault: ")
                        if len(master_password) < 8:
                            print("Password must be at least 8 characters long")
                            continue
                        
                        confirm_password = getpass.getpass("Confirm master password: ")
                        if master_password != confirm_password:
                            print("Passwords do not match")
                            continue
                        
                        print("Creating new vault...")
                        if secure_storage.create_vault(master_password):
                            print("Vault created successfully.")
                            # Vault is now unlocked after creation
                        else:
                            print("Failed to create vault")
                            continue
                    elif not secure_storage.is_unlocked:
                        # Vault exists but is locked - need to unlock it
                        master_password = getpass.getpass("Enter your vault password: ")
                        if not secure_storage.unlock_vault(master_password):
                            print("Failed to unlock vault. Incorrect password.")
                            continue
                        print("Vault unlocked successfully.")
                    
                    # Get import path
                    import_path = input("Enter path to import file: ")
                    if not import_path:
                        print("No import file specified. Import cancelled.")
                        continue
                    
                    # Expand user paths
                    import_path = os.path.expanduser(import_path)
                    
                    # Check if file exists
                    if not os.path.exists(import_path):
                        print(f"File not found: {import_path}")
                        continue
                    
                    # Get import password
                    import_password = getpass.getpass("Enter password to decrypt import: ")
                    
                    # Perform the import
                    success, message = secure_storage.import_secrets(import_path, import_password)
                    
                    if success:
                        print(f"Import successful: {message}")
                    else:
                        print(f"Import failed: {message}")
                else:
                    print(f"Selected option {choice}. This feature is not fully implemented yet.")
                    time.sleep(1)
            except KeyboardInterrupt:
                print("\nExiting TrueFA. Goodbye!")
                break
            except Exception as e:
                print(f"Error in main loop: {e}")
                traceback.print_exc()
                
        print("Exiting securely...")
        # Clean up any temporary files that might have been created
        try:
            if os.path.exists(TEMP_DIR) and os.path.isdir(TEMP_DIR):
                debug_print(f"Cleaning up temporary files in {TEMP_DIR}")
                
                for item in os.listdir(TEMP_DIR):
                    item_path = os.path.join(TEMP_DIR, item)
                    try:
                        if os.path.isfile(item_path):
                            os.unlink(item_path)
                        elif os.path.isdir(item_path):
                            shutil.rmtree(item_path)
                    except Exception as e:
                        debug_print(f"Error cleaning up {item_path}: {e}")
        except Exception as e:
            debug_print(f"Error during cleanup: {e}")
            
        # Close logging
        close_logging()
        
        return 0
        
    except Exception as e:
        print(f"Fatal error: {e}")
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())

# Module-level initialization (for programmable API use)
def force_python_crypto():
    """Force the use of Python fallback crypto implementation."""
    from src.truefa_crypto import force_python_fallback
    force_python_fallback()
    
    # Only call debug_print if debug is enabled, to avoid circular imports
    try:
        from src.utils.debug import debug_print, is_debug_enabled
        if is_debug_enabled():
            debug_print("Forcing use of Python fallback for crypto operations")
    except ImportError:
        # Fall back to regular print if debug module can't be imported
        print("Forcing use of Python fallback for crypto operations")

def set_debug_output(enabled=True):
    """Enable or disable debug output."""
    try:
        from src.utils.debug import set_debug, debug_print
        set_debug(enabled)
        if enabled:
            debug_print("Debug logging enabled")
    except ImportError:
        # Fall back to regular print if debug module can't be imported
        print(f"Debug logging {'enabled' if enabled else 'disabled'}")

# For user-facing prints like these, keep them as prints:
print("TrueFA-Py TOTP Generator")
print("Vault unlocked successfully.")
print("Generated TOTP code: {code}")
