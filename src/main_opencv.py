"""
TrueFA-Py: TOTP Authenticator Application

A robust and secure Two-Factor Authentication (2FA) application that 
implements Time-based One-Time Password (TOTP) authentication according 
to RFC 6238. This application uses OpenCV for reliable QR code scanning.

Key Features:
- Secure extraction and storage of TOTP secrets from QR codes
- Vault-based encryption for protecting authentication secrets
- Memory-safe handling of sensitive data
- Command-line interface with intuitive navigation
- Secure export and backup capabilities

Security Implementation:
- Envelope encryption with a master key protected by a vault password
- Automatic memory sanitization after use
- Platform-specific secure storage with appropriate permissions
- Protection against common memory disclosure vulnerabilities
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
    Main application entry point and interactive command loop.
    
    Provides a menu-driven interface for:
    - Loading TOTP secrets from QR code images (using OpenCV)
    - Manually entering TOTP secrets
    - Generating TOTP codes
    - Saving and retrieving secrets from an encrypted vault
    - Exporting secrets for backup
    
    Command-line arguments are processed for non-interactive operation.
    
    Returns:
        int: 0 for successful execution, non-zero for errors
    """
    # Initialize the authenticator and secure storage once
    try:
        auth = TwoFactorAuth()
        secure_storage = SecureStorage()
        
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
            print("Using Python fallback implementations for crypto functions")
            return 0
            
        # Check if we need to create a vault
        if args.create_vault:
            # Check if vault directory was specified
            if args.vault_dir:
                # Set vault directory
                print(f"Setting vault directory to: {args.vault_dir}")
                os.makedirs(args.vault_dir, exist_ok=True)
                secure_storage.set_vault_directory(args.vault_dir)
            
            # Check if we have input from stdin (non-interactive password)
            if not sys.stdin.isatty():
                # Read password from stdin
                password = sys.stdin.readline().strip()
                
                # Create the vault
                print("Creating vault with password from stdin...")
                try:
                    # Create vault and verify it was created successfully
                    if secure_storage.create_vault(password):
                        print("Vault created successfully.")
                        secure_storage.vault.unlock(password)
                        print("Vault unlocked and ready to use.")
                        
                        # Check if vault exists
                        vault_dir = secure_storage.vault_dir
                        vault_file = os.path.join(vault_dir, "vault.json")
                        if os.path.exists(vault_file):
                            print(f"Vault metadata file created at: {vault_file}")
                        else:
                            print(f"WARNING: Vault metadata file not found at: {vault_file}")
                            
                        return 0
                    else:
                        print("Failed to create vault. See error log for details.")
                        return 1
                except Exception as e:
                    print(f"Error creating vault: {str(e)}")
                    traceback.print_exc()
                    return 1
            else:
                # No stdin input, prompt for password interactively
                try:
                    password = getpass.getpass("Enter vault password: ")
                    password_confirm = getpass.getpass("Confirm vault password: ")
                    
                    if password != password_confirm:
                        print("Passwords do not match.")
                        return 1
                    
                    # Create vault and verify it was created successfully
                    if secure_storage.create_vault(password):
                        print("Vault created successfully.")
                        secure_storage.vault.unlock(password)
                        print("Vault unlocked and ready to use.")
                        
                        # Check if vault exists
                        vault_dir = secure_storage.vault_dir
                        vault_file = os.path.join(vault_dir, "vault.json")
                        if os.path.exists(vault_file):
                            print(f"Vault metadata file created at: {vault_file}")
                        else:
                            print(f"WARNING: Vault metadata file not found at: {vault_file}")
                            
                        return 0
                    else:
                        print("Failed to create vault. See error log for details.")
                        return 1
                except Exception as e:
                    print(f"Error creating vault: {str(e)}")
                    traceback.print_exc()
                    return 1
                
        # Show app directory information
        if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
            bundle_dir = getattr(sys, '_MEIPASS')
            app_dir = os.path.dirname(sys.executable)
            print(f"Running from PyInstaller bundle. App dir: {app_dir}, Bundle dir: {bundle_dir}")
        
        # Check and create directories
        images_dir = os.path.join(os.path.dirname(sys.executable) if getattr(sys, 'frozen', False) else os.getcwd(), "images")
        if not os.path.exists(images_dir):
            try:
                os.makedirs(images_dir)
            except:
                pass
        
        print(f"You can use either the full path or just the filename if it's in the images directory: {images_dir}")
        
        # Check for OpenCV
        try:
            import cv2
        except ImportError:
            print("OpenCV not found. Installation will be skipped.")
            print("QR code functionality will be limited.")
            print("This executable requires OpenCV for QR code scanning.")
            print("The application will continue with limited functionality.")
            print("To enable QR code scanning, please use the full installer version.")
            print()

        # Check if the vault is initialized
        if secure_storage.vault.is_initialized():
            print(f"Successfully loaded vault configuration from {secure_storage.vault.vault_file}")
            print()
        else:
            print(f"Vault metadata not found at: {secure_storage.vault.vault_file}")
            print()
            
        # Place QR image instructions
        print(f"Note: Place your QR code images in: {images_dir}")
        print("You can use either the full path or just the filename if it's in the images directory")
        print()
        
        # Start main interactive loop
        # The rest of the main function code continues here...
                
        # Display menu and process user input
        while True:
            try:
                # Display menu
                print("=== TrueFA ===")
                print("1. Load QR code from image")
                print("2. Enter secret key manually")
                print("3. Save current secret")
                print("4. View saved secrets")
                print("5. Export secrets")
                print("6. Clear screen")
                print("7. Exit")
                print()
                
                # Get user choice
                choice = input("Enter your choice (1-7): ")
                print(f"DEBUG: Received input choice: '{choice}'")
                
                # Process choice
                if choice in ["1", "2", "3", "4", "5", "6", "7"]:
                    if choice == "7":
                        # Exit
                        print("Exiting TrueFA. Goodbye!")
                        break
                        
                    elif choice == "6":
                        # Clear the screen
                        clear_screen()
                    
                    elif choice == "1":
                        # Handle QR code loading
                        image_path = input("Enter image path or filename: ")
                        secret, error = auth.extract_secret_from_qr(image_path)
                        if error:
                            print(f"Error: {error}")
                        else:
                            print("QR code processed successfully.")
                            
                            # Generate codes in real-time immediately after successful QR scan
                            print("\nGenerating TOTP codes in real-time. Press Ctrl+C to return to menu.")
                            try:
                                # Pass debug_mode=True if DEBUG environment variable is set
                                debug_mode = os.environ.get("DEBUG", "").lower() in ("1", "true", "yes")
                                auth.continuous_generate(debug_mode=debug_mode)
                            except KeyboardInterrupt:
                                # Handle interruption cleanly by printing a newline and message
                                print("\nStopped code generation.")
                            except Exception as e:
                                # Log any unexpected errors but continue program execution
                                print(f"\nError during code generation: {e}")
                                if debug_mode:
                                    traceback.print_exc()
                            
                            # After code generation is stopped, ask if the user wants to save the secret
                            # If vault exists and is initialized, offer to auto-save
                            if secure_storage.vault.is_initialized():
                                # Try to auto-unlock if needed
                                if not secure_storage.is_unlocked:
                                    master_password = getpass.getpass("Enter your vault master password to save this secret: ")
                                    if not secure_storage.unlock(master_password):
                                        print("Failed to unlock vault. Secret loaded but not saved.")
                                    else:
                                        # Auto-save with confirmation
                                        issuer = getattr(auth, "issuer", "Unknown")
                                        account = getattr(auth, "account", "Unknown")
                                        name = f"{issuer}-{account}"
                                        
                                        save_confirm = input(f"Save this secret as '{name}'? (Y/n): ").strip().lower()
                                        if save_confirm != 'n':
                                            try:
                                                secret_data = {
                                                    "secret": auth.secret.get_raw_value() if auth.secret else "",
                                                    "issuer": getattr(auth, "issuer", ""),
                                                    "account": getattr(auth, "account", "")
                                                }
                                                result = secure_storage.save_secret(name, secret_data)
                                                if result:
                                                    print(f"Error: {result}")
                                                else:
                                                    print(f"Secret '{name}' saved successfully.")
                                            except Exception as e:
                                                print(f"An error occurred: {e}")
                    
                    elif choice == "2":
                        # Handle manual secret entry
                        secret = input("Enter the TOTP secret key: ")
                        issuer = input("Enter the issuer (e.g., 'Google'): ")
                        account = input("Enter the account name (e.g., 'user@example.com'): ")
                        
                        # Set the secret in the authenticator
                        try:
                            auth.set_secret(secret, issuer=issuer, account=account)
                            print("Secret set successfully.")
                            
                            # Generate codes in real-time
                            print("\nGenerating TOTP codes in real-time. Press Ctrl+C to return to menu.")
                            try:
                                auth.continuous_generate()
                            except KeyboardInterrupt:
                                print("\nStopped code generation.")
                                
                            # After code generation is stopped, ask if the user wants to save the secret
                            if secure_storage.vault.is_initialized():
                                if not secure_storage.is_unlocked:
                                    master_password = getpass.getpass("Enter your vault master password to save this secret: ")
                                    secure_storage.unlock(master_password)
                                
                                if secure_storage.is_unlocked:
                                    name = f"{issuer}-{account}"
                                    save_confirm = input(f"Save this secret as '{name}'? (Y/n): ").strip().lower()
                                    if save_confirm != 'n':
                                        try:
                                            secret_data = {
                                                "secret": auth.secret.get_raw_value(),
                                                "issuer": issuer,
                                                "account": account
                                            }
                                            result = secure_storage.save_secret(name, secret_data)
                                            if result:
                                                print(f"Error: {result}")
                                            else:
                                                print(f"Secret '{name}' saved successfully.")
                                        except Exception as e:
                                            print(f"An error occurred: {e}")
                                    except Exception as e:
                            print(f"Error setting secret: {e}")
                    
                    elif choice == "3":
                        # Handle saving current secret
                        if not auth.secret:
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
                        if not secure_storage.vault.is_initialized():
                            print("No vault found. Creating a new vault...")
                            master_password = getpass.getpass("Enter a new master password for your vault: ")
                            confirm_password = getpass.getpass("Confirm master password: ")
                            
                            if master_password != confirm_password:
                                print("Passwords do not match.")
                                continue
                                
                            if not secure_storage.create_vault(master_password):
                                print("Failed to create vault.")
                                continue
                                
                        # Unlock the vault if needed
                        if not secure_storage.is_unlocked:
                            master_password = getpass.getpass("Enter your vault master password: ")
                            if not secure_storage.unlock(master_password):
                                print("Failed to unlock vault. Secret not saved.")
                                continue
                                                
                        # Save the secret
                        try:
                            secret_data = {
                                "secret": auth.secret.get_raw_value(),
                                "issuer": issuer,
                                "account": account
                            }
                            result = secure_storage.save_secret(name, secret_data)
                            if result:
                                print(f"Error: {result}")
                            else:
                                print(f"Secret '{name}' saved successfully.")
                        except Exception as e:
                            print(f"An error occurred: {e}")
                    
                    elif choice == "4":
                        # Handle viewing saved secrets
                        
                        # Check if vault exists
                        if not secure_storage.vault.is_initialized():
                            print("No vault found. Please create a vault first.")
                            continue
                        
                        # Unlock vault if needed
                        if not secure_storage.is_unlocked:
                            master_password = getpass.getpass("Enter your vault master password: ")
                            if not secure_storage.unlock(master_password):
                                print("Failed to unlock vault.")
                                continue
                        
                        # List secrets
                        secrets_list = secure_storage.list_secrets()
                        if not secrets_list:
                            print("No saved secrets found.")
                            continue
                        
                        print("\nAvailable secrets:")
                        for i, name in enumerate(secrets_list, 1):
                            print(f"{i}. {name}")
                        
                        # Add option for currently loaded secret
                        if auth.secret:
                            print(f"{len(secrets_list) + 1}. Currently loaded secret")
                        
                        # Prompt for selection
                        try:
                            selection = input("\nEnter number to view code: ")
                            selection = int(selection)
                            
                            if selection > 0 and selection <= len(secrets_list):
                                # Load selected secret
                                name = secrets_list[selection - 1]
                                secret_data = secure_storage.get_secret(name)
                                
                                # Set the secret in the authenticator
                                auth.set_secret(
                                    secret_data.get("secret", ""),
                                    issuer=secret_data.get("issuer", ""),
                                    account=secret_data.get("account", "")
                                )
                                
                                issuer = secret_data.get("issuer", "")
                                account = secret_data.get("account", "")
                                if issuer and account:
                                    print(f"Loaded secret for: {issuer} ({account})")
                                else:
                                    print(f"Loaded secret: {name}")
                                
                                # Generate codes in real-time
                                print("\nGenerating TOTP codes in real-time. Press Ctrl+C to return to menu.")
                                try:
                                    auth.continuous_generate()
                                except KeyboardInterrupt:
                                    print("\nStopped code generation.")
                            
                            elif selection == len(secrets_list) + 1 and auth.secret:
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
                                    auth.continuous_generate()
                                except KeyboardInterrupt:
                                    print("\nStopped code generation.")
                            
                            else:
                                print("Invalid selection.")
                        
                        except ValueError:
                            print("Please enter a valid number.")
                        except Exception as e:
                            print(f"An error occurred: {e}")
                    
                    elif choice == "5":
                        # Handle export
                        if not auth.secret:
                            print("No secret to export. Please load a QR code or enter a secret first.")
                            continue
                            
                        print("\nWarning: Exporting secrets can be insecure. Only do this if you understand the risks.")
                        confirm = input("Type 'CONFIRM' to export the current secret: ")
                        if confirm == "CONFIRM":
                            export_data = {
                                "secret": auth.secret.get_raw_value() if auth.secret else "",
                                "issuer": getattr(auth, "issuer", ""),
                                "account": getattr(auth, "account", "")
                            }
                            print("\nExported secret (KEEP THIS SECURE):")
                            print(f"Secret: {export_data['secret']}")
                            print(f"Issuer: {export_data['issuer']}")
                            print(f"Account: {export_data['account']}")
                            
                            if export_data['secret']:
                                label = export_data['account']
                                if export_data['issuer']:
                                    label = f"{export_data['issuer']}:{label}"
                                
                                uri = f"otpauth://totp/{urllib.parse.quote(label)}?secret={export_data['secret']}"
                                if export_data['issuer']:
                                    uri += f"&issuer={urllib.parse.quote(export_data['issuer'])}"
                                
                                print("\nOTPAuth URI:")
                                print(uri)
                        else:
                            print("Export cancelled.")
                    
                else:
                    print("Invalid choice. Please enter a number between 1 and 7.")
                    
            except EOFError:
                print("\nInput error detected. Exiting.")
                break
            except KeyboardInterrupt:
                print("\nOperation cancelled. Exiting.")
                break
            except Exception as e:
                print(f"An error occurred: {str(e)}")
                
    except Exception as e:
        print(f"Application error: {str(e)}")
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
