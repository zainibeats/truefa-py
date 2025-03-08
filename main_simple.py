#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
TrueFA: Trustworthy Two-Factor Authentication
Simplified main entry point for the terminal application.
"""

import os
import sys
import argparse
import traceback
import getpass

# Make sure the src directory is in the path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

try:
    # Import core modules directly
    from src.totp.auth_opencv import TwoFactorAuth
    from src.security.secure_storage import SecureStorage
    from src.security.secure_string import SecureString
    from src.utils.screen import clear_screen
    
    # Copy the main functionality from main_opencv.py
    def main():
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
                if hasattr(auth, 'rust_crypto_available') and auth.rust_crypto_available:
                    print("Using Rust cryptographic module")
                else:
                    print("Using Python fallback implementations for crypto functions")
                return 0
            
            # Process create-vault flag
            if args.create_vault:
                if args.vault_dir:
                    secure_storage.vault_dir = args.vault_dir
                return secure_storage.create_vault()
            
            # Set vault directory if specified
            if args.vault_dir:
                print(f"Setting vault directory to: {args.vault_dir}")
                secure_storage.vault_dir = args.vault_dir
            
            # Check for existing vault
            vault_exists = False
            try:
                vault_exists = secure_storage.check_vault_exists()
            except:
                pass
                
            # Start interactive mode if no special flags were used
            # Start main interactive loop
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
                    print("7. Create or initialize vault")
                    print("8. Exit")
                    print()
                    
                    # Get user choice
                    choice = input("Enter your choice (1-8): ")
                    
                    # Process choice
                    if choice in ["1", "2", "3", "4", "5", "6", "7", "8"]:
                        if choice == "8":
                            # Exit
                            print("Exiting TrueFA. Goodbye!")
                            break
                            
                        elif choice == "6":
                            # Clear the screen
                            clear_screen()
                            
                        elif choice == "7":
                            # Create or initialize vault
                            print("\nCreating new vault...")
                            custom_dir = input("Enter a custom directory for the vault (leave empty for default): ")
                            if custom_dir:
                                secure_storage.vault_dir = custom_dir
                            
                            print("\nYou need to set a master password to protect your vault.")
                            success = secure_storage.create_vault()
                            if success == 0:
                                print("Vault created successfully!")
                                vault_exists = True
                            else:
                                print(f"Failed to create vault. Error code: {success}")
                        
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
                                            print("No vault exists. Create a vault first using option 7.")
                                            continue
                                        
                                        try:
                                            # Create a dictionary like the current_secret structure
                                            auth.current_secret = {
                                                'secret': auth.secret.get_raw_value() if hasattr(auth, 'secret') and auth.secret else "",
                                                'issuer': auth.issuer if hasattr(auth, 'issuer') else "",
                                                'account': auth.account if hasattr(auth, 'account') else ""
                                            }
                                            success = secure_storage.save_secret(auth.current_secret)
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
                                    print("No vault exists. Create a vault first using option 7.")
                                    continue
                                
                                try:
                                    # Construct a dictionary like the current_secret structure
                                    auth.current_secret = {
                                        'secret': secret_key,
                                        'issuer': issuer,
                                        'account': account
                                    }
                                    success = secure_storage.save_secret(auth.current_secret)
                                    if success:
                                        print("Secret saved successfully!")
                                    else:
                                        print("Failed to save secret.")
                                except Exception as e:
                                    print(f"Error saving secret: {str(e)}")
                                
                        elif choice == "3":
                            # Save current secret
                            if not vault_exists:
                                print("No vault exists. Create a vault first using option 7.")
                                continue
                                
                            if hasattr(auth, 'secret') and auth.secret:
                                try:
                                    # Construct a dictionary like the current_secret structure if it doesn't exist
                                    if not hasattr(auth, 'current_secret') or not auth.current_secret:
                                        auth.current_secret = {
                                            'secret': auth.secret.get_raw_value() if hasattr(auth.secret, 'get_raw_value') else str(auth.secret),
                                            'issuer': auth.issuer if hasattr(auth, 'issuer') else "",
                                            'account': auth.account if hasattr(auth, 'account') else ""
                                        }
                                    
                                    success = secure_storage.save_secret(auth.current_secret)
                                    if success:
                                        print("Secret saved successfully!")
                                    else:
                                        print("Failed to save secret.")
                                except Exception as e:
                                    print(f"Error saving secret: {str(e)}")
                            else:
                                print("No secret loaded. Please load a QR code or enter a secret first.")
                                
                        elif choice == "4":
                            # View saved secrets
                            if not vault_exists:
                                print("No vault exists. Create a vault first using option 7.")
                                continue
                                
                            try:
                                secrets = secure_storage.list_secrets()
                                if not secrets:
                                    print("No saved secrets found.")
                                    continue
                                    
                                print("Available secrets:")
                                for idx, secret in enumerate(secrets, 1):
                                    print(f"{idx}. {secret}")
                                    
                                if not secrets:
                                    continue
                                    
                                try:
                                    select = input("Enter the number of the secret to view (or 'c' to cancel): ")
                                    if select.lower() == 'c':
                                        continue
                                        
                                    idx = int(select) - 1
                                    if 0 <= idx < len(secrets):
                                        secret_data = secure_storage.get_secret(secrets[idx])
                                        if secret_data:
                                            # Create a secure string and set attributes
                                            secret_key = secret_data.get("secret", "")
                                            secure_secret = SecureString(secret_key)
                                            auth.secret = secure_secret
                                            auth.issuer = secret_data.get("issuer", "")
                                            auth.account = secret_data.get("account", "")
                                            
                                            # Generate codes in real-time
                                            print("\nGenerating TOTP codes in real-time. Press Ctrl+C to return to menu.")
                                            try:
                                                auth.continuous_generate()
                                            except KeyboardInterrupt:
                                                print("\nStopped code generation.")
                                        else:
                                            print("Failed to load secret.")
                                    else:
                                        print("Invalid selection.")
                                except ValueError:
                                    print("Invalid input. Please enter a number.")
                            except Exception as e:
                                print(f"Error loading secrets: {str(e)}")
                                
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
                        print("Invalid choice. Please enter a number between 1 and 8.")
                        
                except KeyboardInterrupt:
                    print("\nOperation cancelled. Exiting.")
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