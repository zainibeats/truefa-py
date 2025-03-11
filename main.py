#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
TrueFA: Trustworthy Two-Factor Authentication
Main entry point for the terminal application.
"""

# Force disable the fallback crypto implementation to avoid vault persistence issues
# This overrides any system environment variable
import os
os.environ["TRUEFA_USE_FALLBACK"] = "0"

# Configure logging before imports
import logging
logging.basicConfig(level=logging.ERROR)
logging.getLogger('truefa_crypto').setLevel(logging.ERROR)
logging.getLogger('truefa_crypto.loader').setLevel(logging.ERROR)
# Disable ERROR messages from the vault_directory module to avoid duplicates
# We'll handle user-facing messages with colorprint
logging.getLogger('src.security.vault_directory').setLevel(logging.CRITICAL)

import os
import sys
import time
import argparse
import traceback
import getpass
from datetime import datetime
import json
import base64
import urllib.parse
from src.security.vault_interfaces import SecureVault
from src.security.secure_storage import SecureStorage
from src.totp.auth_opencv import TwoFactorAuth
from src.security.secure_string import SecureString
from src.config import get_repo_root
from src.utils.logger import debug, info, warning, error, critical, debug_print, setup_logger, set_console_level
from src.truefa_crypto import is_using_fallback
from src.utils.colorprint import print_warning, print_success, print_info
from src.utils.screen import clear_screen
from src.utils.file_utils import delete_truefa_vault

# Make sure the src directory is in the path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

# Comment out the old debug setting
# os.environ["DEBUG"] = "1"

# Parse command line arguments
def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="TrueFA-Py: TOTP Authenticator")
    parser.add_argument("--debug", action="store_true", help="Enable debug output to console")
    parser.add_argument("--no-log", action="store_true", help="Disable logging to file")
    parser.add_argument("--use-fallback", action="store_true", 
                        help="Force use of Python fallback for crypto operations")
    parser.add_argument("--create-vault", action="store_true", help="Create a new vault")
    parser.add_argument("--vault-dir", type=str, help="Directory to store the vault in")
    parser.add_argument("--version", action="store_true", help="Show version information and exit")
    return parser.parse_args()

try:
    # Parse arguments early
    args = parse_args()
    
    # Process fallback flag - only enable fallback if explicitly requested
    if args.use_fallback:
        os.environ["TRUEFA_USE_FALLBACK"] = "1"
        print_warning("Using Python fallback for cryptographic operations (not recommended)")
    else:
        os.environ["TRUEFA_USE_FALLBACK"] = "0"
    
    # Note: You may still see "Using fallback implementation for secure memory"
    # This is a separate fallback mechanism for memory protection only
    # and doesn't affect vault persistence or cryptographic security
    
    # Configure logging with independent debug and log settings
    if args.debug:
        # Debug mode: Console shows DEBUG level
        console_level = logging.DEBUG
    else:
        # Normal mode: Console shows only warnings and above
        console_level = logging.WARNING
        
    # Setup logger with the appropriate settings
    setup_logger(
        console_level=console_level,
        file_level=logging.DEBUG,  # File always logs everything
        log_to_file=not args.no_log  # Disable file logging if --no-log is specified
    )
    
    # Now that the logger is set up, we can log messages
    if args.debug:
        info("Debug logging enabled")
    
    # Configure truefa_crypto logging based on debug flag
    if args.debug:
        logging.getLogger('truefa_crypto').setLevel(logging.DEBUG)
        logging.getLogger('truefa_crypto.loader').setLevel(logging.DEBUG)
    else:
        logging.getLogger('truefa_crypto').setLevel(logging.ERROR)
        logging.getLogger('truefa_crypto.loader').setLevel(logging.ERROR)
    
    debug_print("Modules imported successfully")
    
    # Modified main function to ensure vault storage works in Docker
    def main():
        """
        Main entry point for the application.
        
        Returns:
            int: 0 for successful execution, non-zero for errors
        """
        try:
            # Track persistent session state
            session_state = {
                "vault_unlocked_this_session": False,
                "master_password": None
            }
            
            debug("Importing modules...")
            
            # Check if we're running in a compiled binary or as a regular Python script
            if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
                bundle_dir = getattr(sys, '_MEIPASS')
                app_dir = os.path.dirname(sys.executable)
                debug(f"Running from PyInstaller bundle. App dir: {app_dir}, Bundle dir: {bundle_dir}")
            else:
                debug(f"Running from regular Python. Searching in: {get_repo_root()}")
                debug(f"Current working directory: {os.getcwd()}")
            
            # Import required modules
            try:
                import cv2
                debug("OpenCV imported successfully")
            except ImportError:
                warning("OpenCV not found. QR code scanning will be disabled.")
            
            debug("Modules imported successfully")
            
            # Create the SecureVault
            debug("Creating SecureVault...")
            vault_dir = args.vault_dir if args.vault_dir else None
            secure_vault = SecureVault(vault_dir)
            debug("SecureVault created successfully")
            
            # Create the SecureStorage using our vault instance
            debug("Creating SecureStorage...")
            storage = SecureStorage(secure_vault)
            debug("SecureStorage created successfully")
            
            # Track vault unlock state and master password
            vault_unlocked = False
            master_password = None
            
            # Create the authentication utility (without passing a secret yet)
            debug("Creating TwoFactorAuth...")
            auth = TwoFactorAuth(storage=storage)
            debug(f"Using provided SecureStorage instance")
            debug(f"Using images directory: {os.path.join(get_repo_root(), 'images')}")
            debug("TwoFactorAuth created successfully")
            
            # Check if vault exists
            try:
                debug(f"Checking for vault at {storage.vault_dir}")
                vault_file = os.path.join(storage.vault_dir, 'vault.json')
                
                # Check if vault is properly initialized
                try:
                    debug(f"Checking vault initialization at: {vault_file}")
                    
                    if os.path.exists(vault_file):
                        with open(vault_file, 'r') as f:
                            metadata = json.load(f)
                            
                            # List all the keys in the metadata for debugging
                            debug(f"Vault metadata keys: {list(metadata.keys())}")
                            
                            # Check if all required keys are present
                            required_keys = ['version', 'created', 'password_hash', 'vault_salt']
                            if all(key in metadata for key in required_keys):
                                debug(f"Vault is properly initialized with all required fields")
                            else:
                                debug(f"Vault file missing required fields")
                    else:
                        info("No vault file found. You may need to create one.")
                except Exception as e:
                    error(f"Error reading vault metadata: {e}")
                
                debug(f"Vault exists: {os.path.exists(vault_file)}")
                
            except Exception as e:
                error(f"Error checking vault: {e}")
            
            # Track vault unlock state - initialize only once
            vault_unlocked = False
            
            # Track authentication status - always start locked
            vault_authenticated = False
            
            # Now process command-line arguments
            if args.version:
                # Show version information and exit
                print("TrueFA-Py OpenCV Edition")
                print("Version: 1.0.0")
                print(f"Platform: {sys.platform}")
                if is_using_fallback():
                    print_warning("Using Python fallback implementations for crypto functions")
                else:
                    print_success("Using Rust cryptographic module")
                print("Exiting securely...")
                return 0
            
            # Create vault if requested
            if args.create_vault:
                print("Creating a new vault...")
                password = getpass.getpass("Enter a master password: ")
                confirm = getpass.getpass("Confirm password: ")
                if password != confirm:
                    print("Passwords don't match. Exiting.")
                    return 1
                storage.create_vault(password)
                print("Vault created successfully.")
                
            # Set vault directory if specified
            if args.vault_dir:
                # Set the vault directory
                print(f"Setting vault directory to: {args.vault_dir}")
                storage.set_vault_directory(args.vault_dir)
            
            # Check if the vault exists now
            try:
                debug_print(f"Checking for vault at {storage.vault_dir}")
                vault_exists = os.path.exists(os.path.join(storage.vault_dir, "vault.json"))
                debug_print(f"Vault exists: {vault_exists}")
            except Exception as e:
                debug_print(f"Error checking if vault exists: {e}")
                vault_exists = False
                
            # Main loop for command-line interface
            while True:
                try:
                    # Security check: Periodically verify vault state is accurate
                    if hasattr(storage, 'verify_unlocked') and session_state["vault_unlocked_this_session"]:
                        debug_print("Performing periodic security check of vault state...")
                        if not storage.verify_unlocked():
                            debug_print("Security check failed: vault reports as locked but session thinks it's unlocked")
                            debug_print("Resetting session state to locked for security")
                            session_state["vault_unlocked_this_session"] = False
                        else:
                            debug_print("Security check passed: vault state and session state are in sync")
                    
                    # Display menu
                    print("\n=== TrueFA ===")
                    print("1. Load QR code from image")
                    print("2. Enter secret key manually")
                    print("3. Save current secret")
                    print("4. View saved secrets")
                    print("5. Export secrets")
                    print("6. Clear screen")
                    print("7. Delete vault")
                    print("8. Exit")
                    print()
                    
                    choice = input("Enter your choice (1-8): ")
                    
                    # Get diagnostics for debugging
                    debug_print(f"Before processing choice {choice}:")
                    debug_print(f"  - session_state: {session_state}")
                    debug_print(f"  - storage.is_unlocked: {storage.is_unlocked}")
                    
                    if choice == "8" or choice == "exit":
                        print("Exiting TrueFA. Goodbye!")
                        break

                    elif choice == "6":
                        # Clear the screen
                        clear_screen()
                        
                    elif choice == "7":
                        # Delete vault
                        print("\nWARNING: This will permanently delete all your secrets and vault data.")
                        print("All your authentication codes will be lost and cannot be recovered.")
                        confirmation = input("\nType 'DELETE' (all caps) to confirm deletion: ")
                        
                        if confirmation == "DELETE":
                            print("Deleting vault...")
                            success, message = delete_truefa_vault(confirm=True)
                            
                            if success:
                                print_success("Vault deleted successfully.")
                                if message:
                                    print(message)
                                    
                                # Reset application state
                                storage = SecureStorage()
                                auth = TwoFactorAuth(storage=storage)
                                session_state = {
                                    "vault_unlocked_this_session": False,
                                    "master_password": None
                                }
                                print("\nYou'll need to create a new vault before saving any secrets.")
                            else:
                                print_warning("Vault deletion failed.")
                                if message:
                                    print(message)
                        else:
                            print("Vault deletion cancelled.")
                        
                    elif choice == "3":
                        # Save current secret
                        if hasattr(auth, 'secret') and auth.secret:
                            name = input("Enter a name for this secret: ")
                            if not name:
                                print("No name provided. Cancelling save.")
                                continue
                                
                            error = auth.save_secret(name, auth.secret)
                            if error:
                                print(f"Error: {error}")
                            else:
                                print(f"Secret saved as '{name}'.")
                                
                                # Update session state if the vault is now unlocked
                                debug_print(f"After save_secret - storage.is_unlocked: {storage.is_unlocked}")
                                debug_print(f"After save_secret - storage.vault.is_unlocked: {storage.vault.is_unlocked}")
                                
                                # Verify the vault is truly unlocked using the secure method
                                is_truly_unlocked = storage.verify_unlocked()
                                debug_print(f"Secure verification after save: is_truly_unlocked = {is_truly_unlocked}")
                                
                                if is_truly_unlocked:
                                    # Update the session state with confidence
                                    session_state["vault_unlocked_this_session"] = True
                                    session_state["master_password"] = auth.last_used_password if hasattr(auth, 'last_used_password') else None
                                    debug_print("Updated session_state to mark vault as securely verified and unlocked")
                        else:
                            print("No secret to save. Please load a QR code or enter a secret first.")
                            continue
                    
                    elif choice == "1":
                        # Load QR code from image
                        qr_path = input("Enter the path to the QR code image: ")
                        if not os.path.exists(qr_path):
                            # Check if it might be in the images directory
                            images_dir = os.path.join(os.path.dirname(sys.executable) if getattr(sys, 'frozen', False) else os.getcwd(), "images")
                            if os.path.exists(images_dir) and os.path.exists(os.path.join(images_dir, qr_path)):
                                qr_path = os.path.join(images_dir, qr_path)
                            else:
                                print(f"File not found: {qr_path}")
                                continue

                        # Try to extract secret from QR code
                        try:
                            result, error = auth.extract_secret_from_qr(qr_path)
                            if result:
                                print("Secret extracted successfully.")
                                # Generate codes in real-time
                                try:
                                    print("\nGenerating TOTP codes in real-time. Press Ctrl+C to return to menu.")
                                    auth.continuous_generate()
                                except KeyboardInterrupt:
                                    print("\nStopped code generation.")
                                except Exception as gen_error:
                                    print(f"Error generating codes: {gen_error}")
                            else:
                                print(f"Error extracting secret: {error}")
                        except ImportError:
                            print("OpenCV is not available. QR code scanning is disabled.")
                            print("Please enter your secret manually using option 2.")
                        except Exception as e:
                            print(f"Error processing QR code: {e}")
                    
                    elif choice == "2":
                        # Enter secret key manually
                        secret_key = input("Enter the secret key: ")
                        issuer = input("Enter the issuer (e.g., Google, Microsoft): ")
                        account = input("Enter the account (e.g., user@example.com): ")
                        
                        # Set the secret and attributes
                        auth.secret = SecureString(secret_key.encode('utf-8'))
                        auth.issuer = issuer
                        auth.account = account
                        print("Secret set successfully.")
                        
                        # Generate codes in real-time
                        try:
                            print("\nGenerating TOTP codes in real-time. Press Ctrl+C to return to menu.")
                            auth.continuous_generate()
                        except KeyboardInterrupt:
                            print("\nStopped code generation.")
                        except Exception as gen_error:
                            print(f"Error generating codes: {gen_error}")
                    
                    elif choice == "4":
                        # View saved secrets
                        # Check if vault is initialized
                        debug_print(f"Checking vault initialization in menu option 4...")
                        debug_print(f"storage object id: {id(storage)}")
                        debug_print(f"storage.vault object id: {id(storage.vault)}")
                        debug_print(f"vault_unlocked tracking variable: {vault_unlocked}")
                        
                        try:
                            # Check if vault directory exists
                            debug_print(f"Vault dir: {storage.vault_dir}")
                            
                            # Check if vault file exists
                            vault_path = os.path.join(storage.vault_dir, "vault.json")
                            debug_print(f"Vault file path: {vault_path}")
                            debug_print(f"Vault file exists: {os.path.exists(vault_path)}")
                            
                            if os.path.exists(vault_path):
                                # Read file to check metadata
                                try:
                                    with open(vault_path, 'r') as f:
                                        metadata = json.load(f)
                                        debug_print(f"Vault metadata keys: {list(metadata.keys())}")
                                except Exception as e:
                                    debug_print(f"Error reading vault file: {e}")
                            
                            debug_print(f"Vault initialization status: {storage.is_initialized}")
                        except Exception as e:
                            debug_print(f"Error checking vault: {e}")
                            
                        if not storage.is_initialized:
                            print("No vault found. Please create a vault first.")
                            continue
                            
                        # Check if vault is already unlocked 
                        debug_print(f"Before unlock check - Vault is unlocked: {storage.is_unlocked}")
                        
                        # Use the secure verification method to check if truly unlocked
                        is_truly_unlocked = storage.verify_unlocked()
                        debug_print(f"Secure verification result: is_truly_unlocked = {is_truly_unlocked}")
                            
                        # If the vault is already unlocked (verified), skip directly to listing secrets
                        if is_truly_unlocked:
                            debug_print("Vault is verified as unlocked, proceeding directly to listing secrets")
                        # If vault was unlocked earlier in the session but object state was lost, restore it
                        elif session_state["vault_unlocked_this_session"] and session_state["master_password"]:
                            print("Restoring vault unlock state from session...")
                            success = storage.unlock(session_state["master_password"])
                            # Verify the unlock was successful with the secure method
                            if success and storage.verify_unlocked():
                                debug_print("Vault successfully unlocked with cached password and verified.")
                            else:
                                print_warning("Failed to restore vault unlock state. Please re-enter your password.")
                                # Reset the session state since our cached password doesn't work
                                session_state["vault_unlocked_this_session"] = False
                                session_state["master_password"] = None
                                
                        # Final check - if vault is still not unlocked, prompt for password
                        if not storage.verify_unlocked():
                            print("\nVault is locked. Please enter your master password to view your saved secrets.")
                            master_password = getpass.getpass("Enter your vault master password: ")
                            if not master_password:
                                print("No password entered. Unable to unlock the vault.")
                                continue
                            if not storage.unlock(master_password):
                                print("Invalid password. Unable to unlock the vault.")
                                continue
                                
                            # Verify unlock was successful with secure method
                            if not storage.verify_unlocked():
                                print_warning("Failed to verify vault unlock. Please try again.")
                                continue
                                
                            print("Vault unlocked successfully.")
                            # Store in session state for future operations
                            session_state["vault_unlocked_this_session"] = True
                            session_state["master_password"] = master_password
                        
                        # List the saved secrets
                        try:
                            secrets_list = storage.list_secrets()
                            
                            if not secrets_list:
                                print("No saved secrets found.")
                                continue
                                
                            print("\nSaved Secrets:")
                            for i, secret in enumerate(secrets_list, 1):
                                print(f"{i}. {secret}")
                            print()
                            
                            # Ask if the user wants to view a specific secret
                            selection = input("Enter the number of a secret to view (or 0 to return to main menu): ")
                            if selection == "0" or not selection.isdigit():
                                continue
                                
                            selection = int(selection)
                            if selection < 1 or selection > len(secrets_list):
                                print("Invalid selection.")
                                continue
                                
                            # Load the selected secret
                            selected_secret = secrets_list[selection - 1]
                            print(f"Loading secret: {selected_secret}")
                            
                            # Load the secret
                            debug_print(f"Vault is unlocked: {storage.is_unlocked}")
                            debug_print(f"session_state: {session_state}")
                            
                            try:
                                # If we're loading from "View Saved Secrets", we should already be unlocked
                                if storage.is_unlocked:
                                    # If vault is already unlocked, no need to pass the password
                                    secret_data = storage.load_secret(selected_secret)
                                else:
                                    # Fallback with password just in case
                                    secret_data = storage.load_secret(selected_secret, session_state["master_password"])
                                
                                if secret_data:
                                    print(f"\nSecret: {selected_secret}")
                                    print(f"Issuer: {secret_data.get('issuer', 'Unknown')}")
                                    print(f"Account: {secret_data.get('account', 'Unknown')}")
                                    
                                    # Generate TOTP code
                                    auth.set_secret(secret_data.get('secret', ''))
                                    auth.issuer = secret_data.get('issuer', '')
                                    auth.account = secret_data.get('account', '')
                                    
                                    print("\nGenerating TOTP codes...")
                                    try:
                                        auth.continuous_generate()
                                    except KeyboardInterrupt:
                                        print("\nStopped code generation.")
                                    except Exception as gen_error:
                                        print(f"Error generating codes: {gen_error}")
                                else:
                                    print(f"Error loading secret: {selected_secret}")
                            except Exception as e:
                                print(f"Error loading secret: {e}")
                            
                            # Make sure we retain the session state when returning to the menu
                            # Even if the vault object's state is lost, we'll remember we unlocked it
                            if storage.is_unlocked:
                                session_state["vault_unlocked_this_session"] = True
                        except Exception as e:
                            print(f"Error listing secrets: {e}")
                            continue
                    
                    elif choice == "5":
                        # Handle exporting all secrets
                        export_path = input("Enter the export path (leave blank for current directory): ").strip()
                        if not export_path:
                            export_path = os.getcwd()
                        
                        # Check if we have a vault first
                        if not hasattr(storage, 'vault') or not storage.vault.is_initialized:
                            print("No vault found. Please create a vault first.")
                            continue
                        
                        # Export secrets
                        print("Export options:")
                        print("1. Export as OTPAuth URI")
                        print("2. Export to encrypted GPG file")
                        export_choice = input("Enter your choice (or 'c' to cancel): ")
                        
                        if export_choice.lower() == 'c':
                            continue
                            
                        if export_choice == "1":
                            # Export as OTPAuth URI
                            if hasattr(auth, 'secret') and auth.secret:
                                import urllib.parse
                                
                                # Get current secret data
                                if not hasattr(auth, 'current_secret') or not auth.current_secret:
                                    auth.current_secret = {
                                        'secret': auth.secret.get_raw_value() if hasattr(auth.secret, 'get_raw_value') else str(auth.secret),
                                        'issuer': auth.issuer if hasattr(auth, 'issuer') else "",
                                        'account': auth.account if hasattr(auth, 'account') else ""
                                    }
                                
                                export_data = auth.current_secret
                                
                                # Construct label
                                label = export_data.get('account', '')
                                if export_data.get('issuer'):
                                    label = f"{export_data['issuer']}:{label}"
                                
                                uri = f"otpauth://totp/{urllib.parse.quote(label)}?secret={export_data.get('secret', '')}"
                                if export_data.get('issuer'):
                                    uri += f"&issuer={urllib.parse.quote(export_data['issuer'])}"
                                
                                print("\nOTPAuth URI:")
                                print(uri)
                            else:
                                print("No secret loaded. Please load a QR code or enter a secret first.")
                        elif export_choice == "2":
                            # Export to encrypted GPG file
                            export_password = getpass.getpass("Enter password for encryption: ")
                            confirm_password = getpass.getpass("Confirm password: ")
                            
                            if export_password != confirm_password:
                                print("Passwords do not match. Export cancelled.")
                                continue
                                
                            if not export_password:
                                print("Password cannot be empty. Export cancelled.")
                                continue
                                
                            # Export to GPG file
                            success = storage.export_secrets(export_path, export_password)
                            if success:
                                print(f"Secrets successfully exported to encrypted GPG file.")
                            else:
                                print("Export failed. Please check the logs for more information.")
                        else:
                            print("Invalid choice.")
                except KeyboardInterrupt:
                    print("\nOperation cancelled.")
                    break
                except Exception as e:
                    print(f"An error occurred: {str(e)}")
                    if os.environ.get("DEBUG", "").lower() in ("1", "true", "yes"):
                        traceback.print_exc()
                    
        except Exception as e:
            print(f"Application error: {str(e)}")
            if os.environ.get("DEBUG", "").lower() in ("1", "true", "yes"):
                traceback.print_exc()
            return 1
        finally:
            # Clean up and secure memory before exit
            try:
                print("Exiting securely...")
                auth.cleanup()
            except:
                pass
            
        return 0

    # Function to print debug vault status
    def debug_vault_status(storage):
        debug("===== VAULT STATUS CHECK =====")
        debug(f"Vault directory: {storage.vault_dir}")
        debug(f"Vault file path: {os.path.join(storage.vault_dir, 'vault.json')}")
        debug(f"Vault directory exists: {os.path.exists(storage.vault_dir)}")
        debug(f"Vault file exists: {os.path.exists(os.path.join(storage.vault_dir, 'vault.json'))}")
        
        # Check metadata if the file exists
        vault_file = os.path.join(storage.vault_dir, 'vault.json')
        if os.path.exists(vault_file):
            try:
                with open(vault_file, 'r') as f:
                    metadata = json.load(f)
                    debug(f"Vault metadata keys: {list(metadata.keys())}")
                    debug("All required fields present")
            except Exception as e:
                error(f"Error reading vault file: {e}")
            
        # Now check the is_initialized property
        debug(f"Checking vault initialization at: {os.path.join(storage.vault_dir, 'vault.json')}")
        debug(f"File exists: {os.path.exists(os.path.join(storage.vault_dir, 'vault.json'))}")
        
        if os.path.exists(os.path.join(storage.vault_dir, 'vault.json')):
            try:
                with open(os.path.join(storage.vault_dir, 'vault.json'), 'r') as f:
                    metadata = json.load(f)
                    debug(f"Vault metadata keys: {list(metadata.keys())}")
                    
                    # Check if all required fields are present
                    required_fields = ["version", "created", "password_hash", "vault_salt"]
                    if all(field in metadata for field in required_fields):
                        debug(f"Vault is properly initialized with all required fields")
                    else:
                        warning(f"Vault file missing required fields")
            except Exception as e:
                error(f"Error reading vault metadata: {e}")
        
        debug(f"is_initialized property returns: {storage.is_initialized}")
        debug(f"is_unlocked property returns: {storage.is_unlocked}")
        debug("===== END VAULT STATUS CHECK =====\n")

    if __name__ == "__main__":
        sys.exit(main())
        
except ImportError as e:
    print(f"Failed to import required modules: {e}")
    print("This could be due to missing dependencies or incorrect installation.")
    sys.exit(1)
except Exception as e:
    print(f"Unexpected error: {e}")
    traceback.print_exc()
    sys.exit(1) 