#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
TrueFA: Trustworthy Two-Factor Authentication
Main entry point for the terminal application.
"""

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

# Make sure the src directory is in the path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

# Enable debug mode
os.environ["DEBUG"] = "1"

try:
    print("Modules imported successfully")
    
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
            
            print("Importing modules...")
            
            # Check if we're running in a compiled binary or as a regular Python script
            if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
                bundle_dir = getattr(sys, '_MEIPASS')
                app_dir = os.path.dirname(sys.executable)
                print(f"Running from PyInstaller bundle. App dir: {app_dir}, Bundle dir: {bundle_dir}")
            else:
                print(f"Running from regular Python. Searching in: {get_repo_root()}")
                print(f"Current working directory: {os.getcwd()}")
            
            # Import required modules
            try:
                import cv2
                print("OpenCV imported successfully")
            except ImportError:
                print("Warning: OpenCV not found. QR code scanning will be disabled.")
            
            print("Modules imported successfully")
            
            # Create the SecureVault
            print("Creating SecureVault...")
            from src.security.vault_interfaces import SecureVault
            vault = SecureVault()
            print("SecureVault created successfully")
            
            # Create the SecureStorage using our vault instance
            print("Creating SecureStorage...")
            storage = SecureStorage(vault=vault)
            print("SecureStorage created successfully")
            
            # Track vault unlock state and master password
            vault_unlocked = False
            master_password = None
            
            # Create the TwoFactorAuth
            print("Creating TwoFactorAuth...")
            auth = TwoFactorAuth(storage=storage)
            print(f"Using provided SecureStorage instance")
            print(f"Using images directory: {os.path.join(get_repo_root(), 'images')}")
            print("TwoFactorAuth created successfully")
            
            # Check if vault exists
            print(f"Checking for vault at {storage.vault_dir}")
            if os.path.exists(os.path.join(storage.vault_dir, "vault.json")):
                # Check if the file is valid
                from src.security.vault_interfaces import SecureVault
                vault_file = os.path.join(storage.vault_dir, "vault.json")
                print(f"DEBUG: Checking vault initialization at: {vault_file}")
                try:
                    with open(vault_file, 'r') as f:
                        metadata = json.load(f)
                        print(f"DEBUG: File exists: {os.path.exists(vault_file)}")
                        print(f"DEBUG: Vault metadata keys: {list(metadata.keys())}")
                        
                        # Check for required fields
                        required_fields = ["version", "created", "password_hash", "vault_salt"]
                        if all(field in metadata for field in required_fields):
                            print(f"DEBUG: Vault is properly initialized with all required fields")
                        else:
                            print(f"DEBUG: Vault file missing required fields")
                except Exception as e:
                    print(f"DEBUG: Error reading vault metadata: {e}")
                
                print(f"Vault exists: {True}")
            else:
                print(f"Vault exists: {False}")
            
            # Track vault unlock state - initialize only once
            vault_unlocked = False
            
            # Track authentication status - always start locked
            vault_authenticated = False
            
            # Process command-line arguments for non-interactive operations
            parser = argparse.ArgumentParser(description="TrueFA-Py OpenCV Edition")
            parser.add_argument("--use-fallback", action="store_true", help="Force use of Python fallback for crypto operations")
            parser.add_argument("--debug", action="store_true", help="Enable debug logging")
            parser.add_argument("--create-vault", action="store_true", help="Create a new vault")
            parser.add_argument("--vault-dir", type=str, help="Directory to store the vault in")
            parser.add_argument("--version", action="store_true", help="Show version information and exit")
            args = parser.parse_args()
            
            # Process version flag first
            if args.version:
                print("TrueFA-Py OpenCV Edition")
                print("Version: 1.0.0")
                from sys import platform
                print(f"Platform: {platform}")
                if hasattr(auth, 'rust_crypto_available') and auth.rust_crypto_available:
                    print("Using Rust cryptographic module")
                else:
                    print("Using Python fallback implementations for crypto functions")
                return 0
            
            # Process create-vault flag
            if args.create_vault:
                if args.vault_dir:
                    storage.vault_dir = args.vault_dir
                master_password = getpass.getpass("Enter master password: ")
                return storage.create_vault(master_password)
            
            # Set vault directory if specified
            if args.vault_dir:
                print(f"Setting vault directory to: {args.vault_dir}")
                storage.vault_dir = args.vault_dir
            
            # Check for existing vault
            vault_exists = False
            try:
                print(f"Checking for vault at {storage.vault_dir}")
                # Use is_initialized method instead of vault_exists
                vault_exists = storage.vault.is_initialized if hasattr(storage, 'vault') else False
                print(f"Vault exists: {vault_exists}")
            except Exception as e:
                print(f"Error checking if vault exists: {e}")
                
            # Start interactive mode if no special flags were used
            # Start main interactive loop
            while True:
                try:
                    # Display menu
                    print("\n=== TrueFA ===")
                    print("1. Load QR code from image")
                    print("2. Enter secret key manually")
                    print("3. Save current secret")
                    print("4. View saved secrets")
                    print("5. Export secrets")
                    print("6. Clear screen")
                    print("7. Exit")
                    print()
                    
                    # Get user choice
                    choice = input("\nEnter your choice (1-7): ")
                    
                    # Process choice
                    if choice in ["1", "2", "3", "4", "5", "6", "7"]:
                        # Print debug information about session state
                        print(f"DEBUG: Before processing choice {choice}:")
                        print(f"DEBUG:   - session_state: {session_state}")
                        print(f"DEBUG:   - storage.is_unlocked: {storage.is_unlocked}")
                        
                        if choice == "7":
                            # Exit
                            print("Exiting TrueFA. Goodbye!")
                            break
                            
                        elif choice == "6":
                            # Clear the screen
                            clear_screen()
                            
                        elif choice == "3":
                            # Handle saving current secret
                            if auth.secret is None:
                                print("No secret to save. Please load a QR code or enter a secret first.")
                                continue
                                
                            # Get a name for the secret
                            suggested_name = f"{auth.issuer}-{auth.account}" if auth.issuer and auth.account else "unnamed"
                            name = input(f"Enter a name for this secret [{suggested_name}]: ").strip()
                            if not name:
                                name = suggested_name
                                
                            try:
                                # Check if vault is initialized
                                print(f"Vault initialized: {storage.is_initialized}")
                                print(f"DEBUG: vault_unlocked tracking variable: {vault_unlocked}")
                                
                                # Prepare the secret data
                                secret_data = {
                                    "secret": auth.secret.get_raw_value(),
                                    "issuer": auth.issuer,
                                    "account": auth.account
                                }
                                
                                # Save the secret
                                error = auth.save_secret(name, secret_data)
                                if error:
                                    print(f"Error: {error}")
                                else:
                                    print(f"Secret saved as '{name}'.")
                                    debug_vault_status(storage)
                                    # Update the vault unlocked state
                                    vault_unlocked = storage.is_unlocked
                                    print(f"DEBUG: Updated vault_unlocked to {vault_unlocked}")
                            except Exception as e:
                                print(f"An error occurred: {e}")
                                traceback.print_exc()
                        
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

                            # Warn about OpenCV limitations in Docker
                            print("\nWARNING: QR code scanning may fail in Docker environment due to missing OpenCV.")
                            try_anyway = input("Do you want to try anyway? (y/n): ")
                            if try_anyway.lower() != 'y':
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
                            # Handle viewing saved secrets
                            debug_vault_status(storage)
                            
                            # Check if vault exists
                            try:
                                print(f"DEBUG: Checking vault initialization in menu option 4...")
                                print(f"DEBUG: storage object id: {id(storage)}")
                                print(f"DEBUG: storage.vault object id: {id(storage.vault)}")
                                print(f"DEBUG: vault_unlocked tracking variable: {vault_unlocked}")
                                
                                # Enhanced debugging to check vault properties
                                if hasattr(storage, 'vault'):
                                    print(f"DEBUG: Vault dir: {storage.vault_dir}")
                                    vault_path = os.path.join(storage.vault_dir, "vault.json")
                                    print(f"DEBUG: Vault file path: {vault_path}")
                                    print(f"DEBUG: Vault file exists: {os.path.exists(vault_path)}")
                                    
                                    # Check metadata if file exists
                                    if os.path.exists(vault_path):
                                        try:
                                            with open(vault_path, 'r') as f:
                                                metadata = json.load(f)
                                                print(f"DEBUG: Vault metadata keys: {list(metadata.keys())}")
                                        except Exception as e:
                                            print(f"DEBUG: Error reading vault file: {e}")
                                
                                # Now check the is_initialized property
                                print(f"DEBUG: Vault initialization status: {storage.is_initialized}")
                            except Exception as e:
                                print(f"DEBUG: Error checking vault: {e}")
                                traceback.print_exc()
                                
                            # Check if vault exists
                            if not storage.is_initialized:
                                print("No vault found. Please create a vault first.")
                                continue
                            
                            # First, make sure the vault is unlocked before listing secrets
                            print(f"DEBUG: Vault is unlocked: {storage.is_unlocked}")
                            print(f"DEBUG: session_state: {session_state}")
                            
                            # Skip password prompt if we already unlocked it during this session
                            if session_state["vault_unlocked_this_session"] and not storage.is_unlocked and session_state["master_password"]:
                                print("Vault was previously unlocked in this session. Unlocking with cached password...")
                                success = storage.unlock(session_state["master_password"])
                                if success:
                                    print("Vault successfully unlocked with cached password.")
                                else:
                                    print("Failed to unlock with cached password. Password may have changed.")
                                    # Reset the session state since our cached password doesn't work
                                    session_state["vault_unlocked_this_session"] = False
                                    session_state["master_password"] = None
                            
                            # If vault is still not unlocked, prompt for password
                            if not storage.is_unlocked and not session_state["vault_unlocked_this_session"]:
                                print("\nVault is locked. Please enter your master password to view your saved secrets.")
                                master_password = getpass.getpass("Enter your vault master password: ")
                                if not master_password:
                                    print("No password entered. Unable to unlock the vault.")
                                    continue
                                if not storage.unlock(master_password):
                                    print("Invalid password. Unable to unlock the vault.")
                                    continue
                                print("Vault unlocked successfully.")
                                # Store in session state for future operations
                                session_state["vault_unlocked_this_session"] = True
                                session_state["master_password"] = master_password
                            else:
                                print("Using already unlocked vault.")
                            
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
                                secret_name = secrets_list[selection - 1]
                                print(f"Loading secret: {secret_name}")
                                
                                # Check the vault's unlock state
                                print(f"DEBUG: Vault is unlocked: {storage.is_unlocked}")
                                print(f"DEBUG: session_state: {session_state}")
                                
                                # If vault appears to be locked but we've unlocked it before
                                if not storage.is_unlocked:
                                    if session_state["vault_unlocked_this_session"] and session_state["master_password"]:
                                        print("Vault appears to have been locked.")
                                        print("Attempting to unlock vault with cached password...")
                                        if storage.unlock(session_state["master_password"]):
                                            print("Vault successfully unlocked with cached password.")
                                        else:
                                            print("Failed to unlock with cached password. Please enter it again.")
                                            master_password = getpass.getpass("Enter your vault master password: ")
                                            if not master_password:
                                                print("No password entered. Unable to unlock the vault.")
                                                continue
                                            if not storage.unlock(master_password):
                                                print("Invalid password. Unable to unlock the vault.")
                                                continue
                                            print("Vault unlocked successfully.")
                                            # Update the cached password with the new one
                                            session_state["master_password"] = master_password
                                    else:
                                        # No cached password, need to ask
                                        master_password = getpass.getpass("Enter your vault master password: ")
                                        if not master_password:
                                            print("No password entered. Unable to unlock the vault.")
                                            continue
                                        if not storage.unlock(master_password):
                                            print("Invalid password. Unable to unlock the vault.")
                                            continue
                                        print("Vault unlocked successfully.")
                                        # Store the password in session state
                                        session_state["master_password"] = master_password
                                        
                                    # Mark that we've successfully unlocked the vault in this session
                                    session_state["vault_unlocked_this_session"] = True
                                
                                # Load and display the secret (provide the master password directly)
                                secret_data = storage.load_secret(secret_name, session_state["master_password"])
                                if secret_data:
                                    print(f"\nSecret: {secret_name}")
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
                                    print(f"Error loading secret: {secret_name}")
                                
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
                            if hasattr(auth, 'secret') and auth.secret:
                                print("Export options:")
                                print("1. Export as OTPAuth URI")
                                export_choice = input("Enter your choice (or 'c' to cancel): ")
                                
                                if export_choice.lower() == 'c':
                                    continue
                                    
                                if export_choice == "1":
                                    # Export as OTPAuth URI
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
                                continue
                    else:
                        print("Invalid choice. Please enter a number between 1 and 7.")
                        
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
        print("\nDEBUG: VAULT STATUS CHECK")
        print(f"DEBUG: Vault directory: {storage.vault_dir}")
        print(f"DEBUG: Vault file path: {os.path.join(storage.vault_dir, 'vault.json')}")
        print(f"DEBUG: Vault directory exists: {os.path.exists(storage.vault_dir)}")
        print(f"DEBUG: Vault file exists: {os.path.exists(os.path.join(storage.vault_dir, 'vault.json'))}")
        
        # Check metadata if the file exists
        vault_file = os.path.join(storage.vault_dir, 'vault.json')
        if os.path.exists(vault_file):
            try:
                with open(vault_file, 'r') as f:
                    metadata = json.load(f)
                    print(f"DEBUG: Vault metadata keys: {list(metadata.keys())}")
                    print(f"DEBUG: All required fields present")
            except Exception as e:
                print(f"DEBUG: Error reading vault file: {e}")
            
        # Now check the is_initialized property
        print(f"DEBUG: Checking vault initialization at: {os.path.join(storage.vault_dir, 'vault.json')}")
        print(f"DEBUG: File exists: {os.path.exists(os.path.join(storage.vault_dir, 'vault.json'))}")
        
        if os.path.exists(os.path.join(storage.vault_dir, 'vault.json')):
            try:
                with open(os.path.join(storage.vault_dir, 'vault.json'), 'r') as f:
                    metadata = json.load(f)
                    print(f"DEBUG: Vault metadata keys: {list(metadata.keys())}")
                    
                    # Check if all required fields are present
                    required_fields = ["version", "created", "password_hash", "vault_salt"]
                    if all(field in metadata for field in required_fields):
                        print(f"DEBUG: Vault is properly initialized with all required fields")
                    else:
                        print(f"DEBUG: Vault file missing required fields")
            except Exception as e:
                print(f"DEBUG: Error reading vault metadata: {e}")
        
        print(f"DEBUG: is_initialized property returns: {storage.is_initialized}")
        print(f"DEBUG: is_unlocked property returns: {storage.is_unlocked}")
        print(f"DEBUG: END VAULT STATUS CHECK\n")

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