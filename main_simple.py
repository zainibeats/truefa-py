#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
TrueFA: Trustworthy Two-Factor Authentication
Simplified main entry point for the terminal application.
"""

import os
import sys
import time
import argparse
import traceback
import getpass
from datetime import datetime

# Make sure the src directory is in the path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

try:
    # Import core modules directly
    from src.totp.auth_opencv import TwoFactorAuth
    from src.security.secure_storage import SecureStorage
    from src.security.secure_string import SecureString
    from src.utils.screen import clear_screen
    
    # Modified main function to ensure vault storage works in Docker
    def main():
        # Initialize the authenticator and secure storage once
        try:
            auth = TwoFactorAuth()
            
            # Create storage with Docker-friendly path
            storage = SecureStorage()
            
            # In Docker, ensure we use a path we know we can write to
            if os.environ.get("DOCKER_CONTAINER") == "1" or os.path.exists("/.dockerenv"):
                # Use a path we know we can write to in Docker
                docker_vault_dir = os.path.expanduser("~/truefa_vault")
                print(f"Docker environment detected, using {docker_vault_dir} for vault storage")
                storage.vault_dir = docker_vault_dir
            elif "ContainerAdministrator" in os.path.expanduser("~"):
                # Detected Windows container
                docker_vault_dir = "C:\\truefa_vault"
                print(f"Windows container detected, using {docker_vault_dir} for vault storage")
                storage.vault_dir = docker_vault_dir
                # Ensure the directory exists with proper permissions
                os.makedirs(docker_vault_dir, exist_ok=True)
                try:
                    # Try to adjust permissions if needed
                    if os.name == "nt":
                        import stat
                        os.chmod(docker_vault_dir, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
                except Exception as e:
                    print(f"Warning: Could not set permissions on vault directory: {e}")
            
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
                vault_exists = storage.vault_exists()
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
                            if not hasattr(auth, 'secret') or auth.secret is None:
                                print("No secret to save. Please load a QR code or enter a secret first.")
                                continue
                                
                            # Get issuer and account from authenticator
                            issuer = getattr(auth, "issuer", "")
                            account = getattr(auth, "account", "")
                            
                            # Prompt for a custom name or use default
                            default_name = f"{issuer}-{account}" if issuer and account else "unnamed"
                            name = input(f"Enter a name for this secret [{default_name}]: ")
                            if not name:
                                name = default_name
                            
                            # Check if vault is initialized
                            try:
                                vault_initialized = storage.vault.is_initialized()
                                print(f"Vault initialized: {vault_initialized}")
                            except Exception as e:
                                print(f"Error checking vault initialization: {e}")
                                vault_initialized = False
                                
                            if not vault_initialized:
                                print("No vault found. Creating a new vault...")
                                master_password = getpass.getpass("Enter a new master password for your vault: ")
                                confirm_password = getpass.getpass("Confirm master password: ")
                                
                                if master_password != confirm_password:
                                    print("Passwords do not match.")
                                    continue
                                    
                                try:
                                    # Use fallback Python implementation for crypto in Docker
                                    if os.environ.get("DOCKER_CONTAINER") == "1" or os.path.exists("/.dockerenv") or "ContainerAdministrator" in os.path.expanduser("~"):
                                        os.environ["TRUEFA_USE_FALLBACK"] = "1"
                                        print("Using Python fallback implementation in Docker environment")
                                    
                                    print(f"Creating vault at {storage.vault_dir}")
                                    success = storage.create_vault(master_password)
                                    if success:
                                        print("Vault created successfully.")
                                        vault_initialized = True
                                    else:
                                        print("Failed to create vault.")
                                        # Try fallback location
                                        storage.vault_dir = os.path.join(os.path.expanduser("~"), ".truefa", "vault")
                                        print(f"Trying fallback location: {storage.vault_dir}")
                                        os.makedirs(storage.vault_dir, exist_ok=True)
                                        success = storage.create_vault(master_password)
                                        if success:
                                            print("Vault created successfully at fallback location.")
                                            vault_initialized = True
                                        else:
                                            print("Failed to create vault at fallback location.")
                                            continue
                                except Exception as e:
                                    print(f"Failed to create vault: {e}")
                                    traceback.print_exc()
                                    continue
                                    
                            # Unlock the vault if needed
                            if not storage.is_unlocked:
                                try:
                                    master_password = getpass.getpass("Enter your vault master password: ")
                                    success = False
                                    try:
                                        success = storage.unlock(master_password)
                                    except Exception as unlock_error:
                                        print(f"Error during unlock attempt: {unlock_error}")
                                        success = False
                                        
                                    if not success:
                                        print("Failed to unlock vault. Secret not saved.")
                                        continue
                                except Exception as e:
                                    print(f"Error unlocking vault: {e}")
                                    continue
                                
                            # Save the secret
                            try:
                                # Ensure we have the needed attributes and convert them safely
                                secret_value = ""
                                if hasattr(auth, 'secret') and auth.secret:
                                    if hasattr(auth.secret, 'get_value'):
                                        try:
                                            secret_value = auth.secret.get_value().decode('utf-8')
                                        except Exception as e:
                                            print(f"Warning: Could not decode secret: {e}")
                                            secret_value = str(auth.secret)
                                    else:
                                        secret_value = str(auth.secret)
                                
                                secret_data = {
                                    "secret": secret_value,
                                    "issuer": issuer,
                                    "account": account
                                }
                                
                                print(f"Saving secret '{name}' with issuer '{issuer}' and account '{account}'")
                                result = storage.save_secret(name, secret_data)
                                if result:
                                    print(f"Error: {result}")
                                else:
                                    print(f"Secret '{name}' saved successfully.")
                            except Exception as e:
                                print(f"An error occurred while saving secret: {e}")
                                traceback.print_exc()
                        
                        elif choice == "1":
                            # Handle QR code loading
                            print("NOTE: QR code scanning is likely to fail in the Docker container environment.")
                            print("This is expected behavior since Docker containers don't have OpenCV installed.")
                            print("In a normal user environment, this would work properly.")
                            print("Consider using option 2 to manually enter a secret instead.")
                            print()
                            
                            continue_anyway = input("Do you want to try scanning a QR code anyway? (y/n): ")
                            if continue_anyway.lower() != 'y':
                                continue
                                
                            image_path = input("Enter image path or filename: ")
                            try:
                                secret, error = auth.extract_secret_from_qr(image_path)
                                if error:
                                    print(f"Error: {error}")
                                else:
                                    print("QR code processed successfully.")
                                    
                                    # Generate codes in real-time
                                    print("\nGenerating TOTP codes in real-time. Press Ctrl+C to return to menu.")
                                    try:
                                        # Pass debug_mode=True if DEBUG environment variable is set
                                        debug_mode = os.environ.get("DEBUG", "").lower() in ("1", "true", "yes")
                                        auth.continuous_generate(debug_mode=debug_mode)
                                    except KeyboardInterrupt:
                                        # Handle interruption cleanly by printing a newline and message
                                        print("\nStopped code generation.")
                                    
                                    # Try to save the secret
                                    save_choice = input("Would you like to save this secret to your vault? (y/n): ")
                                    if save_choice.lower() == 'y':
                                        if not vault_exists:
                                            print("No vault exists. Create a vault first using option 3.")
                                            continue
                                        
                                        try:
                                            # Create a dictionary like the current_secret structure
                                            auth.current_secret = {
                                                'secret': auth.secret.get_raw_value() if hasattr(auth, 'secret') and auth.secret else "",
                                                'issuer': auth.issuer if hasattr(auth, 'issuer') else "",
                                                'account': auth.account if hasattr(auth, 'account') else ""
                                            }
                                            success = storage.save_secret(auth.current_secret)
                                            if success:
                                                print("Secret saved successfully!")
                                            else:
                                                print("Failed to save secret.")
                                        except Exception as e:
                                            print(f"Error saving secret: {str(e)}")
                            except Exception as e:
                                print(f"Error processing QR code: {str(e)}")
                                if "cv2" in str(e):
                                    print("OpenCV is not available in this environment.")
                                    print("This is expected in the Docker container for testing.")
                                    print("Try using option 2 to manually enter a secret instead.")
                        
                        elif choice == "2":
                            # Handle manual entry
                            secret_key = input("Enter the secret key: ")
                            issuer = input("Enter the issuer (e.g., Google, Microsoft): ")
                            account = input("Enter the account (e.g., user@example.com): ")
                            
                            # Create a secure string from the entered secret
                            secure_secret = SecureString(secret_key)
                            
                            # Set the values directly to the auth object
                            auth.secret = secure_secret
                            auth.issuer = issuer
                            auth.account = account
                            
                            print("Secret set successfully.")
                            
                            # Generate codes in real-time
                            print("\nGenerating TOTP codes in real-time. Press Ctrl+C to return to menu.")
                            try:
                                auth.continuous_generate()
                            except KeyboardInterrupt:
                                print("\nStopped code generation.")
                            
                            # Try to save the secret
                            save_choice = input("Would you like to save this secret to your vault? (y/n): ")
                            if save_choice.lower() == 'y':
                                if not vault_exists:
                                    print("No vault exists. Create a vault first using option 3.")
                                    continue
                                
                                try:
                                    # Construct a dictionary like the current_secret structure
                                    auth.current_secret = {
                                        'secret': secret_key,
                                        'issuer': issuer,
                                        'account': account
                                    }
                                    success = storage.save_secret(auth.current_secret)
                                    if success:
                                        print("Secret saved successfully!")
                                    else:
                                        print("Failed to save secret.")
                                except Exception as e:
                                    print(f"Error saving secret: {str(e)}")
                                
                        elif choice == "4":
                            # Handle viewing saved secrets
                            
                            # Check if vault exists
                            try:
                                vault_initialized = storage.vault.is_initialized()
                            except:
                                vault_initialized = False
                            
                            if not vault_initialized:
                                print("No vault found. Please create a vault first.")
                                continue
                            
                            # Unlock vault if needed
                            if not storage.is_unlocked:
                                master_password = getpass.getpass("Enter your vault master password: ")
                                if not storage.unlock(master_password):
                                    print("Failed to unlock vault.")
                                    continue
                            
                            # List secrets
                            secrets_list = storage.list_secrets()
                            if not secrets_list:
                                print("No saved secrets found.")
                                continue
                            
                            print("\nAvailable secrets:")
                            for i, name in enumerate(secrets_list, 1):
                                print(f"{i}. {name}")
                            
                            # Add option for currently loaded secret
                            if hasattr(auth, 'secret') and auth.secret:
                                print(f"{len(secrets_list) + 1}. Currently loaded secret")
                            
                            # Prompt for selection
                            try:
                                selection = input("\nEnter number to view code: ")
                                selection = int(selection)
                                
                                if selection > 0 and selection <= len(secrets_list):
                                    # Load selected secret
                                    name = secrets_list[selection - 1]
                                    secret_data = storage.get_secret(name)
                                    
                                    # Set the secret in the authenticator
                                    if hasattr(auth, 'set_secret') and callable(getattr(auth, 'set_secret')):
                                        auth.set_secret(
                                            secret_data.get("secret", ""),
                                            issuer=secret_data.get("issuer", ""),
                                            account=secret_data.get("account", "")
                                        )
                                    else:
                                        # Direct attribute setting if set_secret method is not available
                                        auth.secret = SecureString(secret_data.get("secret", "").encode('utf-8'))
                                        auth.issuer = secret_data.get("issuer", "")
                                        auth.account = secret_data.get("account", "")
                                    
                                    issuer = secret_data.get("issuer", "")
                                    account = secret_data.get("account", "")
                                    if issuer and account:
                                        print(f"Loaded secret for: {issuer} ({account})")
                                    else:
                                        print(f"Loaded secret: {name}")
                                    
                                    # Generate codes in real-time
                                    print("\nGenerating TOTP codes in real-time. Press Ctrl+C to return to menu.")
                                    try:
                                        if hasattr(auth, 'continuous_generate') and callable(getattr(auth, 'continuous_generate')):
                                            auth.continuous_generate()
                                        else:
                                            # Fallback implementation if continuous_generate is not available
                                            import time
                                            try:
                                                while True:
                                                    code = auth.generate_totp()
                                                    remaining = 30 - (int(time.time()) % 30)
                                                    print(f"Code: {code} (expires in {remaining}s)", end="\r")
                                                    time.sleep(1)
                                            except KeyboardInterrupt:
                                                pass
                                    except KeyboardInterrupt:
                                        print("\nStopped code generation.")
                                
                                elif selection == len(secrets_list) + 1 and hasattr(auth, 'secret') and auth.secret:
                                    # Use currently loaded secret
                                    issuer = getattr(auth, "issuer", "")
                                    account = getattr(auth, "account", "")
                                    
                                    if issuer and account:
                                        print(f"Using current secret for: {issuer} ({account})")
                                    else:
                                        print("Using currently loaded secret")
                                        
                                    # Generate codes in real-time
                                    print("\nGenerating TOTP codes in real-time. Press Ctrl+C to return to menu.")
                                    try:
                                        if hasattr(auth, 'continuous_generate') and callable(getattr(auth, 'continuous_generate')):
                                            auth.continuous_generate()
                                        else:
                                            # Fallback implementation if continuous_generate is not available
                                            import time
                                            try:
                                                while True:
                                                    code = auth.generate_totp()
                                                    remaining = 30 - (int(time.time()) % 30)
                                                    print(f"Code: {code} (expires in {remaining}s)", end="\r")
                                                    time.sleep(1)
                                            except KeyboardInterrupt:
                                                pass
                                    except KeyboardInterrupt:
                                        print("\nStopped code generation.")
                                else:
                                    print("Invalid selection.")
                                
                            except ValueError:
                                print("Please enter a valid number.")
                            except Exception as e:
                                print(f"An error occurred: {e}")
                                
                        elif choice == "5":
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