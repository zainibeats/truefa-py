"""
Modified main module for TrueFA that uses OpenCV instead of pyzbar for QR scanning
"""

import sys
import time
import os
from pathlib import Path
import urllib.parse

from src.security.secure_storage import SecureStorage
from src.security.secure_string import SecureString
from src.totp.auth_opencv import TwoFactorAuth
from src.utils.screen import clear_screen

def main():
    """Main application entry point and UI loop"""
    auth = TwoFactorAuth()
    
    try:
        # Print the images directory location
        print(f"\nNote: Place your QR code images in: {auth.images_dir}")
        print("You can use either the full path or just the filename if it's in the images directory\n")
        
        # Initialize the vault and secure storage
        vault_path = Path.home() / ".truefa" / "vault.data"
        vault_path.parent.mkdir(parents=True, exist_ok=True)
        secure_storage = SecureStorage()
        
        # Main application loop
        while True:
            # Display menu
            print("\n=== TrueFA (OpenCV Edition) ===")
            print("1. Load QR code from image")
            print("2. Enter secret key manually")
            print("3. Save current secret")
            print("4. Load saved secret")
            print("5. Export secrets")
            print("6. Clear screen")
            print("7. Exit")
            
            try:
                # Improved input handling for stdin
                choice = input("\nEnter your choice (1-7): ").strip()
                # Debug the input
                print(f"DEBUG: Received input choice: '{choice}'")
                
                if choice in ["1", "2", "3", "4", "5", "6", "7"]:
                    if choice == "7":
                        print("Exiting TrueFA. Goodbye!")
                        break
                        
                    elif choice == "6":
                        # Clear the screen
                        os.system('cls' if os.name == 'nt' else 'clear')
                        continue
                    
                    elif choice == "1":
                        # Handle QR code loading
                        image_path = input("Enter image path or filename: ")
                        secret, error = auth.extract_secret_from_qr(image_path)
                        if error:
                            print(f"Error: {error}")
                        else:
                            # Generate a code immediately to verify
                            code, remaining = auth.generate_totp()
                            if code:
                                print(f"Current code: {code} (expires in {remaining}s)")
                            else:
                                print("Failed to generate TOTP code")
                    
                    elif choice == "2":
                        # Handle manual secret entry
                        secret_key = input("Enter TOTP secret (base32): ")
                        issuer = input("Enter issuer name (optional): ")
                        account = input("Enter account name (optional): ")
                        
                        secret_key = secret_key.upper().strip()
                        auth.secret = SecureString(secret_key)
                        
                        # Set the issuer and account if provided
                        if issuer or account:
                            auth.issuer = issuer
                            auth.account = account
                        
                        # Generate a code immediately to verify
                        code, remaining = auth.generate_totp()
                        if code:
                            print(f"Current code: {code} (expires in {remaining}s)")
                        else:
                            print("Failed to generate TOTP code")
                    
                    elif choice == "3":
                        # Handle save
                        if not auth.secret:
                            print("No secret to save. Please load a QR code or enter a secret first.")
                            continue
                            
                        name = input("Enter a name for this secret: ")
                        
                        # First-time vault setup when a master password is needed
                        if not secure_storage.vault.is_initialized():
                            print("\nYou'll need to create a master password for your TrueFA vault.")
                            print("This password will protect all your secret keys.")
                            master_password = input("Enter master password: ")
                            if not master_password:
                                print("Master password cannot be empty!")
                                continue
                                
                            confirm_master = input("Confirm master password: ")
                            if master_password != confirm_master:
                                print("Master passwords don't match. Try again.")
                                continue
                                
                            # Create the vault with the master password
                            if not secure_storage.create_vault(master_password):
                                print("Failed to create vault!")
                                continue
                                
                            print("Vault created successfully!")
                        elif not secure_storage.is_unlocked:
                            # Vault exists but is locked, prompt for password
                            master_password = input("Enter your vault master password: ")
                            if not secure_storage.unlock_vault(master_password):
                                print("Failed to unlock vault with the provided password.")
                                continue
                                                
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
                    
                    elif choice == "4":
                        # Handle load
                        if not secure_storage.vault.is_initialized():
                            print("No vault found. Please save a secret first.")
                            continue
                            
                        if not secure_storage.is_unlocked:
                            master_password = input("Enter your vault master password: ")
                            if not secure_storage.unlock_vault(master_password):
                                continue  # Error message already shown in unlock_vault
                                
                        secrets = secure_storage.list_secrets()
                        if not secrets:
                            print("No saved secrets found.")
                            continue
                            
                        print("\nAvailable secrets:")
                        for i, name in enumerate(secrets, 1):
                            print(f"{i}. {name}")
                            
                        selection = input("\nEnter number to load: ")
                        try:
                            idx = int(selection) - 1
                            if 0 <= idx < len(secrets):
                                secret_data = secure_storage.load_secret(secrets[idx])
                                if secret_data:
                                    auth.secret = SecureString(secret_data.get("secret", ""))
                                    auth.issuer = secret_data.get("issuer", "")
                                    auth.account = secret_data.get("account", "")
                                    
                                    code, remaining = auth.generate_totp()
                                    if code:
                                        print(f"Loaded secret for: {auth.issuer or 'Unknown'} ({auth.account or 'Unknown'})")
                                        print(f"Current code: {code} (expires in {remaining}s)")
                                    else:
                                        print("Failed to generate TOTP code with the loaded secret.")
                                else:
                                    print("Failed to decrypt secret.")
                            else:
                                print("Invalid selection.")
                        except ValueError:
                            print("Invalid input. Please enter a number.")
                    
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
    finally:
        # Clean up and secure memory before exit
        auth.cleanup()

if __name__ == "__main__":
    main()
