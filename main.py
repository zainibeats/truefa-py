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
            
            # Track authentication status - always start locked
            vault_authenticated = False
            
            # In Docker, ensure we use a path we know we can write to
            if os.environ.get("DOCKER_CONTAINER") == "1" or os.path.exists("/.dockerenv"):
                # Use a path we know we can write to in Docker
                docker_vault_dir = os.path.expanduser("~/truefa_vault")
                print(f"Docker environment detected, using {docker_vault_dir} for vault storage")
                storage.vault_dir = docker_vault_dir
            elif "ContainerAdministrator" in os.path.expanduser("~"):
                # Detected Windows container
                docker_vault_dir = "C:\\test_vault"
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
                # Use is_initialized method instead of vault_exists
                vault_exists = storage.vault.is_initialized() if hasattr(storage, 'vault') else False
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
                                vault_initialized = storage.vault.is_initialized() if hasattr(storage, 'vault') else False
                                print(f"Vault initialized: {vault_initialized}")
                            except Exception as e:
                                print(f"Error checking vault initialization: {e}")
                                vault_initialized = False
                                
                            if not vault_initialized:
                                print("No vault found. Creating a new vault...")
                                
                                # Set vault directory to a location that works in Docker
                                if "ContainerAdministrator" in os.path.expanduser("~"):
                                    # Force use of C:\test_vault which is known to work in Docker
                                    print("Forcing use of C:\\test_vault for Docker environment")
                                    storage.vault_dir = "C:\\test_vault"
                                    os.makedirs("C:\\test_vault", exist_ok=True)
                                
                                master_password = getpass.getpass("Enter a new master password for your vault: ")
                                confirm_password = getpass.getpass("Confirm master password: ")
                                
                                if master_password != confirm_password:
                                    print("Passwords do not match.")
                                    continue
                                    
                                # Use fallback Python implementation for crypto in Docker
                                if os.environ.get("DOCKER_CONTAINER") == "1" or os.path.exists("/.dockerenv") or "ContainerAdministrator" in os.path.expanduser("~"):
                                    os.environ["TRUEFA_USE_FALLBACK"] = "1"
                                    print("Using Python fallback implementation in Docker environment")
                                
                                # Direct fallback for Docker environments
                                if "ContainerAdministrator" in os.path.expanduser("~"):
                                    try:
                                        # Import all modules needed for the entire function here
                                        import json
                                        import hashlib
                                        import base64
                                        import re
                                        
                                        print(f"Creating vault at {storage.vault_dir}")
                                        os.makedirs(storage.vault_dir, exist_ok=True)
                                        vault_meta_path = os.path.join(storage.vault_dir, "vault.json")
                                        
                                        # Create vault metadata with password hash
                                        password_hash = hashlib.sha256(master_password.encode()).hexdigest()
                                        vault_meta = {
                                            "version": "1.0",
                                            "created": datetime.now().isoformat(),
                                            "password_hash": password_hash
                                        }
                                        
                                        with open(vault_meta_path, 'w') as f:
                                            json.dump(vault_meta, f)
                                            
                                        print(f"Created basic vault metadata at {vault_meta_path}")
                                        vault_initialized = True
                                        vault_authenticated = True
                                        
                                        # Now save the secret directly
                                        secret_file = os.path.join(storage.vault_dir, f"{name}.enc")
                                        
                                        # Get the secret value
                                        secret_value = ""
                                        if hasattr(auth, 'secret') and auth.secret:
                                            if hasattr(auth.secret, 'get_value'):
                                                try:
                                                    secret_value = auth.secret.get_value().decode('utf-8') 
                                                except Exception:
                                                    secret_value = str(auth.secret)
                                            else:
                                                secret_value = str(auth.secret)
                                        
                                        # Format for TOTP if needed
                                        if not re.match(r'^[A-Z2-7]+=*$', secret_value):
                                            print("Converting secret to proper base32 format for TOTP")
                                            if isinstance(secret_value, str):
                                                secret_bytes = secret_value.encode('ascii')
                                            else:
                                                secret_bytes = secret_value
                                            secret_value = base64.b32encode(secret_bytes).decode('ascii')
                                        
                                        # Create and save the secret data
                                        secret_data = {
                                            "secret": secret_value,
                                            "issuer": issuer,
                                            "account": account
                                        }
                                        
                                        with open(secret_file, 'w') as f:
                                            json.dump(secret_data, f)
                                        
                                        print(f"Saved secret '{name}' directly to {secret_file}")
                                        print(f"Secret '{name}' saved successfully.")
                                        continue  # Skip the rest of the vault handling code
                                    except Exception as direct_save_error:
                                        print(f"Error with direct save: {direct_save_error}")
                                        traceback.print_exc()
                                
                                # Try standard vault creation if Docker fallback failed
                                try:
                                    success = storage.create_vault(master_password)
                                    if success:
                                        print("Vault created successfully.")
                                        vault_initialized = True
                                        vault_authenticated = True
                                    else:
                                        print("Failed to create vault.")
                                        # Try alternative location
                                        alt_dir = os.path.join(os.path.expanduser("~"), ".truefa", "vault")
                                        print(f"Trying alternative location: {alt_dir}")
                                        storage.vault_dir = alt_dir
                                        os.makedirs(alt_dir, exist_ok=True)
                                        
                                        success = storage.create_vault(master_password)
                                        if success:
                                            print("Vault created successfully at alternative location.")
                                            vault_initialized = True
                                            vault_authenticated = True
                                        else:
                                            print("Failed to create vault at alternative location.")
                                            continue
                                except Exception as e:
                                    print(f"Failed to create vault: {e}")
                                    traceback.print_exc()
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
                                    print("\nGenerating TOTP codes in real-time. Press Ctrl+C to return to menu.")
                                    try:
                                        auth.continuous_generate()
                                    except KeyboardInterrupt:
                                        print("\nStopped code generation.")
                                        # Don't prompt to save on first run if no vault exists
                                        try:
                                            vault_exists = storage.vault.is_initialized() if hasattr(storage, 'vault') else False
                                            # Check for Docker fallback vault
                                            if not vault_exists and "ContainerAdministrator" in os.path.expanduser("~"):
                                                docker_vault_dir = "C:\\test_vault"
                                                if os.path.exists(docker_vault_dir) and os.path.isfile(os.path.join(docker_vault_dir, "vault.json")):
                                                    vault_exists = True
                                        
                                            # Only ask to save if a vault already exists
                                            if vault_exists:
                                                save_choice = input("Would you like to save this secret to your vault? (y/n): ")
                                                if save_choice.lower() == 'y':
                                                    # Directly go to save flow (option 3) with the current secret
                                                    # We'll implement this by simply letting the next loop
                                                    # iteration handle it with a flag
                                                    print("Use option 3 from the menu to save this secret.")
                                        except Exception as e:
                                            print(f"Error checking vault: {e}")
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
                            print("\nGenerating TOTP codes in real-time. Press Ctrl+C to return to menu.")
                            try:
                                if hasattr(auth, 'continuous_generate'):
                                    auth.continuous_generate()
                                else:
                                    # Fallback implementation
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
                                
                                # Don't prompt to save on first run if no vault exists
                                try:
                                    vault_exists = storage.vault.is_initialized() if hasattr(storage, 'vault') else False
                                    # Check for Docker fallback vault
                                    if not vault_exists and "ContainerAdministrator" in os.path.expanduser("~"):
                                        docker_vault_dir = "C:\\test_vault"
                                        if os.path.exists(docker_vault_dir) and os.path.isfile(os.path.join(docker_vault_dir, "vault.json")):
                                            vault_exists = True
                                    
                                    # Only ask to save if a vault already exists
                                    if vault_exists:
                                        save_choice = input("Would you like to save this secret to your vault? (y/n): ")
                                        if save_choice.lower() == 'y':
                                            # Tell the user to use option 3
                                            print("Use option 3 from the menu to save this secret.")
                                except Exception as e:
                                    print(f"Error checking vault: {e}")
                        
                        elif choice == "4":
                            # Handle viewing saved secrets
                            
                            # Check if vault exists
                            try:
                                vault_initialized = storage.vault.is_initialized() if hasattr(storage, 'vault') else False
                            except:
                                vault_initialized = False
                            
                            # Docker fallback check - look for our simple vault
                            docker_vault = False
                            if "ContainerAdministrator" in os.path.expanduser("~"):
                                # Check for our simplified vault in the Docker environment
                                docker_vault_dir = "C:\\test_vault"
                                if os.path.exists(docker_vault_dir) and os.path.isfile(os.path.join(docker_vault_dir, "vault.json")):
                                    print(f"Found Docker fallback vault at {docker_vault_dir}")
                                    vault_initialized = True
                                    docker_vault = True
                                    storage.vault_dir = docker_vault_dir
                            
                            if not vault_initialized:
                                print("No vault found. Please create a vault first.")
                                continue
                            
                            # Docker fallback path
                            if docker_vault:
                                # Check if we're already authenticated this session
                                if not vault_authenticated:
                                    # Require master password authentication
                                    master_password = getpass.getpass("Enter your vault master password: ")
                                    
                                    # For Docker fallback, read the vault file to check if password is correct
                                    try:
                                        import json
                                        import hashlib
                                        
                                        # Read the vault metadata
                                        vault_meta_path = os.path.join(storage.vault_dir, "vault.json")
                                        with open(vault_meta_path, 'r') as f:
                                            vault_meta = json.load(f)
                                        
                                        # If vault has a password_hash, verify it
                                        if 'password_hash' in vault_meta:
                                            # Hash the entered password
                                            password_hash = hashlib.sha256(master_password.encode()).hexdigest()
                                            if password_hash != vault_meta['password_hash']:
                                                print("Incorrect password. Access denied.")
                                                continue
                                        else:
                                            # First time, store the password hash
                                            password_hash = hashlib.sha256(master_password.encode()).hexdigest()
                                            vault_meta['password_hash'] = password_hash
                                            with open(vault_meta_path, 'w') as f:
                                                json.dump(vault_meta, f)
                                        
                                        print("Vault unlocked successfully.")
                                        vault_authenticated = True
                                    except Exception as auth_error:
                                        print(f"Authentication error: {auth_error}")
                                        print("Access denied.")
                                        continue
                                
                                # Load secrets directly from files in the Docker fallback vault
                                import json
                                import glob
                                
                                secret_files = glob.glob(os.path.join(storage.vault_dir, "*.enc"))
                                if not secret_files:
                                    print("No saved secrets found.")
                                    continue
                                
                                print("\nAvailable secrets:")
                                secrets_list = []
                                for i, secret_file in enumerate(secret_files, 1):
                                    name = os.path.basename(secret_file).replace(".enc", "")
                                    secrets_list.append(name)
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
                                        secret_file = os.path.join(storage.vault_dir, f"{name}.enc")
                                        
                                        try:
                                            with open(secret_file, 'r') as f:
                                                secret_data = json.load(f)
                                            
                                            # Set the secret in the authenticator with proper TOTP format
                                            secret_value = secret_data.get("secret", "")
                                            print(f"Loading secret value: {len(secret_value)} characters")
                                            
                                            # Ensure the secret is properly base32 encoded for TOTP
                                            try:
                                                import base64
                                                import re
                                                
                                                # Check if it's a valid base32 string (TOTP requires base32)
                                                if not re.match(r'^[A-Z2-7]+=*$', secret_value):
                                                    # If not, encode it as base32
                                                    print("Converting secret to proper base32 format for TOTP")
                                                    if isinstance(secret_value, str):
                                                        # First decode from ascii if it's already a string
                                                        secret_bytes = secret_value.encode('ascii')
                                                    else:
                                                        secret_bytes = secret_value
                                                    # Then encode as base32 and format properly
                                                    secret_value = base64.b32encode(secret_bytes).decode('ascii')
                                                    # Remove padding (= characters) if any, as TOTP doesn't use them
                                                    secret_value = secret_value.rstrip('=')
                                            except Exception as format_error:
                                                print(f"Warning: Could not format secret for TOTP: {format_error}")
                                            
                                            # Create a secure string with the secret
                                            auth.secret = SecureString(secret_value.encode('utf-8'))
                                            auth.issuer = secret_data.get("issuer", "")
                                            auth.account = secret_data.get("account", "")
                                            
                                            issuer = secret_data.get("issuer", "")
                                            account = secret_data.get("account", "")
                                            
                                            if issuer and account:
                                                print(f"Loaded secret for: {issuer} ({account})")
                                            else:
                                                print(f"Loaded secret: {name}")
                                            
                                            # Manual TOTP code generation
                                            try:
                                                # Directly generate a TOTP code to verify it works
                                                import pyotp
                                                import time
                                                
                                                # Try to create a TOTP object directly 
                                                totp = pyotp.TOTP(secret_value)
                                                current_code = totp.now()
                                                remaining = 30 - (int(time.time()) % 30)
                                                
                                                print(f"Current TOTP code: {current_code} (expires in {remaining}s)")
                                                print("\nGenerating TOTP codes in real-time. Press Ctrl+C to return to menu.")
                                                
                                                # Continuous generation
                                                try:
                                                    while True:
                                                        totp_code = totp.now()
                                                        remaining = 30 - (int(time.time()) % 30)
                                                        print(f"Code: {totp_code} (expires in {remaining}s)", end="\r")
                                                        time.sleep(1)
                                                except KeyboardInterrupt:
                                                    print("\nStopped code generation.")
                                            except Exception as totp_error:
                                                print(f"Error generating TOTP code: {totp_error}")
                                                print(f"This might be due to an invalid secret format. Secret length: {len(secret_value)}")
                                                
                                                # Fallback to direct auth TOTP generation 
                                                print("\nTrying fallback TOTP generation method...")
                                                try:
                                                    code, remaining = auth.generate_totp()
                                                    print(f"Fallback code: {code} (expires in {remaining}s)")
                                                    
                                                    print("\nGenerating TOTP codes in real-time. Press Ctrl+C to return to menu.")
                                                    try:
                                                        while True:
                                                            code, remaining = auth.generate_totp()
                                                            print(f"Code: {code} (expires in {remaining}s)", end="\r")
                                                            time.sleep(1)
                                                    except KeyboardInterrupt:
                                                        print("\nStopped code generation.")
                                                except Exception as fallback_error:
                                                    print(f"Fallback TOTP generation also failed: {fallback_error}")
                                        except Exception as e:
                                            print(f"Error loading secret: {e}")
                                        
                                    elif selection == len(secrets_list) + 1 and hasattr(auth, 'secret') and auth.secret:
                                        # Use currently loaded secret
                                        print("Using currently loaded secret")
                                        # Generate codes in real-time
                                        print("\nGenerating TOTP codes in real-time. Press Ctrl+C to return to menu.")
                                        try:
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
                                
                                # Skip the rest of the complex vault unlocking process
                                continue
                            
                            # Normal vault path (not Docker fallback)
                            # Unlock vault if needed
                            if not vault_authenticated:
                                # Always require password again for security, even if we think we're unlocked
                                master_password = getpass.getpass("Enter your vault master password: ")
                                try:
                                    if storage.unlock(master_password):
                                        print("Vault unlocked successfully.")
                                        vault_authenticated = True
                                    else:
                                        print("Incorrect password. Access denied.")
                                        continue
                                except Exception as unlock_error:
                                    print(f"Error unlocking vault: {unlock_error}")
                                    print("Access denied.")
                                    continue
                            
                            # List secrets
                            try:
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
                            except Exception as list_error:
                                print(f"Error listing secrets: {list_error}")
                                continue
                            
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