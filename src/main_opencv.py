"""
Modified main module for TrueFA that uses OpenCV instead of pyzbar for QR scanning
"""

import sys
import time
import os
from pathlib import Path

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
        print("You can use either the full path or just the filename if it's in the images directory")
        
        while True:
            # Auto-cleanup of old secrets (e.g., after 5 minutes)
            if auth.secret and auth.secret.age() > 300:  # 5 minutes
                print("\nAuto-clearing old secret for security...")
                auth.cleanup()

            print("\n=== TrueFA (OpenCV Edition) ===")
            print("1. Load QR code from image")
            print("2. Enter secret key manually")
            print("3. Save current secret")
            print("4. Load saved secret") 
            print("5. Export secrets")
            print("6. Clear screen")
            print("7. Exit")
            
            choice = input("\nEnter your choice (1-7): ")
            
            if choice == '1':
                # Auto-cleanup before new secret
                if auth.secret:
                    auth.cleanup()
                
                image_path = input("Enter the path to the QR code image: ")
                secret, error = auth.extract_secret_from_qr(image_path)
                
                if error:
                    print(f"Error: {error}")
                    continue
                
                auth.secret = secret
                print("Secret key successfully extracted from QR code!")
                
                # Generate a code immediately to verify
                code, remaining = auth.generate_totp()
                if code:
                    print(f"Current code: {code} (expires in {remaining}s)")
                else:
                    print("Invalid secret key format. Please try again.")
                    auth.cleanup()
            
            elif choice == '2':
                # Auto-cleanup before new secret
                if auth.secret:
                    auth.cleanup()
                
                secret_key = input("Enter your secret key: ")
                if not secret_key.strip():
                    print("Secret key cannot be empty.")
                    continue
                
                auth.secret = SecureString(secret_key)
                print("Secret key successfully saved!")
                
                # Generate a code immediately to verify
                code, remaining = auth.generate_totp()
                if code:
                    print(f"Current code: {code} (expires in {remaining}s)")
                else:
                    print("Invalid secret key format. Please try again.")
                    auth.cleanup()
            
            elif choice == '3':
                if not auth.secret:
                    print("No secret key available to save.")
                    continue
                
                name = input("Enter a name for this secret: ")
                if not name.strip():
                    print("Name cannot be empty.")
                    continue
                
                error = auth.save_secret(name)
                if error:
                    print(f"Error: {error}")
                else:
                    print(f"Secret '{name}' saved successfully!")
            
            elif choice == '4':
                # Show available secrets
                saved_secrets = auth.list_saved_secrets()
                
                if not saved_secrets:
                    print("No saved secrets found.")
                    continue
                
                print("\nAvailable secrets:")
                for i, name in enumerate(saved_secrets, 1):
                    print(f"{i}. {name}")
                
                choice = input("\nEnter the number of the secret to load: ")
                try:
                    idx = int(choice) - 1
                    if 0 <= idx < len(saved_secrets):
                        name = saved_secrets[idx]
                        error = auth.load_secret(name)
                        
                        if error:
                            print(f"Error: {error}")
                        else:
                            print(f"Secret '{name}' loaded successfully!")
                            
                            # Generate a code immediately
                            code, remaining = auth.generate_totp()
                            if code:
                                print(f"Current code: {code} (expires in {remaining}s)")
                    else:
                        print("Invalid selection.")
                except ValueError:
                    print("Please enter a valid number.")
            
            elif choice == '5':
                export_path = input("Enter the export file path: ")
                if not export_path.strip():
                    print("Export path cannot be empty.")
                    continue
                
                result = auth.export_secrets(export_path)
                print(result)
            
            elif choice == '6':
                clear_screen()
            
            elif choice == '7':
                auth.cleanup()
                print("Exiting securely...")
                break
            
            elif choice.lower() == 'g':
                if not auth.secret:
                    print("No secret key available. Please enter a secret first.")
                    continue
                
                print("\nGenerating codes. Press Ctrl+C to stop.")
                try:
                    auth.continuous_generate()
                except KeyboardInterrupt:
                    pass
            
            else:
                print("Invalid choice. Please try again.")
                
    except KeyboardInterrupt:
        # Handle Ctrl+C
        auth.cleanup()
        print("\nExiting securely...")
    except Exception as e:
        # Handle other exceptions
        auth.cleanup()
        print(f"\nAn error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
