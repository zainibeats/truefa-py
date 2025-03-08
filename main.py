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

# Make sure the src directory is in the path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

# Enable debug mode
os.environ["DEBUG"] = "1"

try:
    # Import core modules directly
    print("Importing modules...")
    from src.totp.auth_opencv import TwoFactorAuth
    from src.security.vault_interfaces import SecureVault
    from src.security.secure_string import SecureString
    from src.utils.screen import clear_screen
    print("Modules imported successfully")
    
    # Modified main function to ensure vault storage works in Docker
    def main():
        # Initialize the authenticator and secure storage once
        try:
            print("Creating SecureVault...")
            storage = SecureVault()
            print("SecureVault created successfully")
            
            # Create a secure storage instance that will be shared
            print("Creating SecureStorage...")
            from src.security.secure_storage import SecureStorage
            secure_storage = SecureStorage()
            print("SecureStorage created successfully")
            
            print("Creating TwoFactorAuth...")
            # Pass the shared secure_storage instance to TwoFactorAuth
            auth = TwoFactorAuth(storage=secure_storage)
            print("TwoFactorAuth created successfully")
            
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
                                print("No secret currently loaded. Please load a secret first.")
                                continue
                                
                            # Get a name for the secret
                            default_name = f"{auth.issuer}-{auth.account}" if auth.issuer and auth.account else None
                            name = input(f"Enter a name for this secret [{default_name}]: ").strip()
                            if not name and default_name:
                                name = default_name
                            
                            # Check if vault exists
                            print(f"Vault initialized: {storage.is_initialized}")
                            
                            # If vault doesn't exist, create it
                            if not storage.is_initialized:
                                # Get a master password for the vault
                                while True:
                                    master_password = getpass.getpass("Create a master password for your vault: ")
                                    
                                    # Validate password length
                                    if len(master_password) < 8:
                                        print("Password must be at least 8 characters long.")
                                        continue
                                    
                                    # Confirm the password
                                    confirm_password = getpass.getpass("Confirm master password: ")
                                    if master_password != confirm_password:
                                        print("Passwords do not match. Please try again.")
                                        continue
                                    
                                    # Create the vault
                                    try:
                                        print("Creating new vault...")
                                        if storage.create_vault(master_password):
                                            print("Vault created successfully.")
                                            vault_authenticated = True
                                            break
                                        else:
                                            print("Failed to create vault. Please try again.")
                                            continue
                                    except Exception as e:
                                        print(f"Error creating vault: {e}")
                                        traceback.print_exc()
                                        continue
                            
                            # If vault exists but not authenticated, unlock it
                            elif not vault_authenticated:
                                master_password = getpass.getpass("Enter your vault master password: ")
                                try:
                                    if storage.unlock(master_password):
                                        print("Vault unlocked successfully.")
                                        vault_authenticated = True
                                    else:
                                        print("Failed to unlock vault with the provided password.")
                                except Exception as e:
                                    print(f"Error unlocking vault: {e}")
                                    traceback.print_exc()
                                continue
                            
                            # Now save the secret
                            try:
                                auth.save_secret(name)
                                print(f"Secret saved as '{name}'.")
                                debug_vault_status(secure_storage)
                            except Exception as e:
                                print(f"Error saving secret: {e}")
                        
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
                            debug_vault_status(secure_storage)
                            
                            # Check if vault exists
                            try:
                                print(f"DEBUG: Checking vault initialization in menu option 4...")
                                print(f"DEBUG: storage object id: {id(secure_storage)}")
                                print(f"DEBUG: storage.vault object id: {id(secure_storage.vault)}")
                                
                                # Enhanced debugging to check vault properties
                                if hasattr(secure_storage, 'vault'):
                                    print(f"DEBUG: Vault dir: {secure_storage.vault.vault_dir}")
                                    vault_path = os.path.join(secure_storage.vault.vault_dir, "vault.json")
                                    print(f"DEBUG: Vault file path: {vault_path}")
                                    print(f"DEBUG: Vault file exists: {os.path.exists(vault_path)}")
                                    
                                    # Check the contents of the vault file
                                    if os.path.exists(vault_path):
                                        try:
                                            with open(vault_path, 'r') as f:
                                                metadata = json.load(f)
                                            print(f"DEBUG: Vault metadata keys: {list(metadata.keys())}")
                                        except Exception as e:
                                            print(f"DEBUG: Error reading vault file: {e}")
                                
                                # Now check the is_initialized property
                                vault_initialized = secure_storage.vault.is_initialized if hasattr(secure_storage, 'vault') else False
                                print(f"DEBUG: Vault initialization status: {vault_initialized}")
                            except Exception as e:
                                print(f"DEBUG: Error checking vault initialization: {e}")
                                vault_initialized = False
                                
                            # If no vault is found, show a message
                            if not vault_initialized:
                                print("No vault found. Please create a vault first.")
                                continue
                            
                            # List the saved secrets
                            try:
                                secrets_list = secure_storage.list_secrets()
                                
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
                                
                                # If vault is not unlocked, we need a password
                                if not secure_storage.is_unlocked:
                                    password = getpass.getpass("Enter your vault master password: ")
                                    secure_storage.unlock(password)
                                    
                                # Load and display the secret
                                secret_data = secure_storage.load_secret(secret_name)
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
                            except Exception as e:
                                print(f"Error listing secrets: {e}")
                                continue
                        
                        elif choice == "5":
                            # Handle exporting all secrets
                            export_path = input("Enter the export path (leave blank for current directory): ").strip()
                            if not export_path:
                                export_path = os.getcwd()
                            
                            # Check if we have a vault first
                            if not hasattr(secure_storage, 'vault') or not secure_storage.vault.is_initialized:
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

    def debug_vault_status(storage_obj):
        """Check and report the status of vault files."""
        if not hasattr(storage_obj, 'vault'):
            print("DEBUG: No vault attribute found on storage object")
            return
        
        vault_dir = storage_obj.vault.vault_dir
        vault_path = os.path.join(vault_dir, "vault.json")
        
        print(f"\nDEBUG: VAULT STATUS CHECK")
        print(f"DEBUG: Vault directory: {vault_dir}")
        print(f"DEBUG: Vault file path: {vault_path}")
        print(f"DEBUG: Vault directory exists: {os.path.exists(vault_dir)}")
        print(f"DEBUG: Vault file exists: {os.path.exists(vault_path)}")
        
        if os.path.exists(vault_path):
            try:
                with open(vault_path, 'r') as f:
                    metadata = json.load(f)
                print(f"DEBUG: Vault metadata keys: {list(metadata.keys())}")
                
                # Check for required fields
                required_fields = ["version", "password_hash", "vault_salt", "master_key"]
                missing_fields = [field for field in required_fields if field not in metadata]
                if missing_fields:
                    print(f"DEBUG: Missing required fields: {missing_fields}")
                else:
                    print(f"DEBUG: All required fields present")
                    
            except Exception as e:
                print(f"DEBUG: Error reading vault file: {e}")
                
        print(f"DEBUG: is_initialized property returns: {storage_obj.vault.is_initialized}")
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