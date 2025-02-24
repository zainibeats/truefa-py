import sys
import time
import os
from pathlib import Path

from .security.secure_storage import SecureStorage
from .security.secure_string import SecureString
from .totp.auth import TwoFactorAuth
from .utils.screen import clear_screen

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

            print("\n=== TrueFA ===")
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
                    
                # Require master password before showing codes
                if not auth.ensure_unlocked("view 2FA codes"):
                    auth.cleanup()
                    continue
                    
                auth.secret = secret
                print("Secret key successfully extracted from QR code!")
                
            elif choice == '2':
                # Auto-cleanup before new secret
                if auth.secret:
                    auth.cleanup()
                
                secret_input = input("Enter the secret key: ").strip()
                if not auth.validate_secret(secret_input):
                    print("Error: Invalid secret key format. Must be base32 encoded.")
                    continue
                    
                # Require master password before showing codes
                if not auth.ensure_unlocked("view 2FA codes"):
                    continue
                    
                auth.secret = SecureString(secret_input)
                print("Secret key successfully set!")

            elif choice == '3':
                if not auth.secret:
                    print("No secret currently set!")
                    continue
                
                if not auth.ensure_unlocked("save the secret"):
                    continue
                
                name = input("Enter a name for this secret: ").strip()
                if not name:
                    print("Name cannot be empty!")
                    continue
                
                try:
                    with SecureString(auth.secret.get()) as temp_secret:
                        encrypted = auth.storage.encrypt_secret(temp_secret.get(), name)
                    
                    # Save to file
                    with open(os.path.join(auth.storage.storage_path, f"{name}.enc"), "w") as f:
                        f.write(encrypted)
                    
                    print(f"Secret saved as '{name}'")
                except Exception as e:
                    print("Error saving secret!")
                    continue

            elif choice == '4':
                if not auth.ensure_unlocked("load saved secrets"):
                    continue
                    
                name = input("Enter the name of the secret to load: ").strip()
                if not name:
                    print("Name cannot be empty!")
                    continue
                
                file_path = os.path.join(auth.storage.storage_path, f"{name}.enc")
                if not os.path.exists(file_path):
                    print(f"No saved secret found with name '{name}'")
                    continue
                
                try:
                    with open(file_path, "r") as f:
                        encrypted = f.read()
                    
                    decrypted = auth.storage.decrypt_secret(encrypted, name)
                    if not decrypted:
                        print("Failed to decrypt secret")
                        continue
                    
                    # Auto-cleanup before new secret
                    if auth.secret:
                        auth.cleanup()
                    
                    auth.secret = SecureString(decrypted)
                    print(f"Secret '{name}' loaded successfully!")
                except Exception as e:
                    print("Error loading secret!")
                    continue

            elif choice == '5':
                
                # First verify master password
                if not auth.storage.is_unlocked:
                    print("\nPlease enter your master password to access secrets.")
                    if not auth.ensure_unlocked("access secrets for export"):
                        continue

                # Then check if we have any secrets to export
                secrets = auth.storage.load_all_secrets()
                if not secrets:
                    print("\nNo secrets available to export.")
                    continue
                                
                output_path = input("\nEnter name for exported file (will be encrypted): ").strip()
                if not output_path:
                    print("Export cancelled.")
                    continue
                    
                if not output_path.endswith('.gpg'):
                    output_path += '.gpg'
                
                print("\nNow enter a password to encrypt your export file.")
                print("This can be different from your master password.")
                print("You'll need this password when decrypting the file later.")
                export_password = input("Export file password: ")
                if not export_password:
                    print("Export cancelled.")
                    continue
                
                confirm = input("Confirm export file password: ")
                if export_password != confirm:
                    print("Passwords don't match. Export cancelled.")
                    continue
                
                if auth.storage.export_secrets(output_path, export_password):
                    print("You can decrypt this file using: gpg -d " + output_path)
                else:
                    print("Failed to export secrets")
                continue
                
            elif choice == '6':
                clear_screen()
                continue
                
            elif choice == '7':
                auth.cleanup()
                print("Goodbye!")
                sys.exit(0)
                
            else:
                print("Invalid choice. Please try again.")
                continue
                
            # Generate codes if secret is set
            if auth.secret:
                print("\nGenerating TOTP codes. Press Ctrl+C to stop.")
                auth.is_generating = True
                try:
                    while auth.is_generating:
                        code = auth.generate_code()
                        remaining = auth.get_remaining_time()
                        print(f"\rCurrent code: {code} (refreshes in {remaining}s)", end='', flush=True)
                        time.sleep(1)
                except KeyboardInterrupt:
                    auth.is_generating = False
                    print("\nStopped code generation.")
                    # Don't clear the secret here, let it auto-clear after timeout

    except Exception as e:
        # Secure cleanup on any exception
        auth.cleanup()
        print("\nAn error occurred. Exiting securely...")
        sys.exit(1)

if __name__ == "__main__":
    main() 