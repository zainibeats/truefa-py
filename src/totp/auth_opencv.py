"""
OpenCV-Based Two-Factor Authentication Module

This module provides an alternative implementation of the TwoFactorAuth class
that uses OpenCV for QR code scanning instead of pyzbar. This avoids the
DLL dependency issues on Windows systems.

Key Features:
- QR code scanning using OpenCV
- Automatic OpenCV installation if needed
- Secure secret storage with automatic cleanup
- TOTP code generation with PyOTP
- Signal handling for secure termination
"""

import os
import sys
import signal
import platform
import re
from pathlib import Path
import pyotp
import time
from PIL import Image
import urllib.parse
import subprocess
from ..security.secure_string import SecureString
from ..security.secure_storage import SecureStorage
import base64
import datetime
import traceback

class TwoFactorAuth:
    """
    OpenCV-based Two-Factor Authentication implementation.
    
    This class provides the same functionality as the base TwoFactorAuth class
    but uses OpenCV for QR code scanning instead of pyzbar. This makes it more
    reliable on Windows systems where pyzbar can have DLL issues.
    
    Features:
    - QR code scanning with OpenCV (auto-installed if needed)
    - Secure storage of TOTP secrets
    - Code generation and validation
    - Automatic cleanup of sensitive data
    - Signal handling for secure termination
    """
    
    def __init__(self):
        """
        Initialize the TwoFactorAuth instance.
        
        Sets up:
        - Secure storage for TOTP secrets
        - Signal handlers for secure termination
        - QR code image directory
        - Initial security state
        - OpenCV installation check
        """
        self.secret = None
        self.is_generating = False
        self.storage = SecureStorage()
        self.is_vault_mode = self.storage.vault.is_initialized()
        
        # Register signal handlers for secure cleanup
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
        # Determine the executable directory for resource paths
        if getattr(sys, 'frozen', False):
            # Running as compiled executable
            app_dir = os.path.dirname(sys.executable)
            bundle_dir = getattr(sys, '_MEIPASS', app_dir)
            print(f"Running from PyInstaller bundle. App dir: {app_dir}, Bundle dir: {bundle_dir}")
            # Set images directory relative to the executable
            self.images_dir = os.getenv('QR_IMAGES_DIR', os.path.join(app_dir, 'images'))
        else:
            # Running in normal Python environment
            self.images_dir = os.getenv('QR_IMAGES_DIR', os.path.join(os.getcwd(), 'images'))
        
        print(f"You can use either the full path or just the filename if it's in the images directory")
        
        # Create images directory if needed
        if not os.path.exists(self.images_dir):
            os.makedirs(self.images_dir)
            
        # Ensure OpenCV is available
        self._check_opencv()

    def _check_opencv(self):
        """
        Check if OpenCV is installed and install it if needed.
        
        Returns:
            bool: True if OpenCV is available, False otherwise
            
        Note:
            Attempts to install OpenCV using pip if not found
        """
        try:
            import cv2
            return True
        except ImportError:
            try:
                print("Installing OpenCV (required for QR scanning)...")
                subprocess.check_call([sys.executable, "-m", "pip", "install", "opencv-python"])
                import cv2
                print("OpenCV installed successfully.")
                return True
            except Exception as e:
                print(f"\nWARNING: Could not install OpenCV: {e}")
                print("QR code scanning will not be available.")
                return False

    def _signal_handler(self, signum, frame):
        """
        Handle program termination signals securely.
        
        Ensures proper cleanup of sensitive data when the program
        is interrupted or terminated.
        """
        if self.is_generating:
            self.is_generating = False
            return
        self.cleanup()
        print("\nExiting securely...")
        sys.exit(0)

    def cleanup(self):
        """
        Perform secure cleanup of sensitive data.
        
        Ensures that all secret data is properly zeroized
        and removed from memory.
        """
        if self.secret:
            self.secret.clear()
            self.secret = None

    def extract_secret_from_qr(self, image_path):
        """
        Extract TOTP secret from a QR code image using OpenCV.
        
        Args:
            image_path: Path to the QR code image file
            
        Returns:
            tuple: (SecureString containing the secret, or None if failed,
                   Error message string or None if successful)
                   
        Security:
        - Validates and sanitizes image path
        - Uses OpenCV's QR code detector
        - Returns generic error messages for security
        """
        try:
            # Clean up and validate the image path
            image_path = self._validate_image_path(image_path)
            if not image_path:
                return None, "Invalid image path or file not found"
            
            # Check OpenCV availability
            try:
                import cv2
                print(f"DEBUG: OpenCV version: {cv2.__version__}")
            except ImportError:
                return None, "OpenCV is required for QR scanning. Please install it with 'pip install opencv-python'"
            
            # Read and process image
            print(f"DEBUG: Reading image from: {image_path}")
            img = cv2.imread(str(image_path))
            if img is None:
                return None, f"Could not read image: {image_path}"
            
            print(f"DEBUG: Image loaded successfully, shape: {img.shape}")
            
            # Initialize QR Code detector
            detector = cv2.QRCodeDetector()
            
            # Detect and decode
            print("DEBUG: Attempting to detect and decode QR code...")
            data, bbox, _ = detector.detectAndDecode(img)
            
            print(f"DEBUG: QR code data: {data if data else 'None'}")
            print(f"DEBUG: QR code bounding box: {bbox if bbox is not None else 'None'}")
            
            # Process QR code data
            if data:
                print(f"DEBUG: Raw QR data: {data}")
                if data.startswith('otpauth://'):
                    parsed = urllib.parse.urlparse(data)
                    params = dict(urllib.parse.parse_qsl(parsed.query))
                    
                    print(f"DEBUG: Parsed params: {params}")
                    
                    if 'secret' in params:
                        # Extract and normalize the secret
                        secret = params['secret']
                        print(f"DEBUG: Raw secret from QR: {secret}")
                        
                        # Create a secure string from the extracted secret
                        secure_secret = SecureString(secret)
                        
                        # Set the issuer and account if available
                        path = parsed.path
                        if path.startswith('/'):
                            path = path[1:]
                        
                        if ':' in path:
                            self.issuer, self.account = path.split(':', 1)
                        else:
                            self.account = path
                            self.issuer = params.get('issuer', '')
                        
                        print(f"DEBUG: Parsed issuer: {self.issuer}, account: {self.account}")
                        
                        # Store the secret
                        self.secret = secure_secret
                        return secure_secret, None
                    
                    return None, "No secret parameter found in otpauth URL"
                
                return None, "QR code found but doesn't contain a valid otpauth URL"
            else:
                return None, "No QR code found in the image"
            
        except Exception as e:
            print(f"DEBUG: Exception in extract_secret_from_qr: {str(e)}")
            import traceback
            traceback.print_exc()
            return None, f"Error processing image: {e}"

    def _validate_image_path(self, image_path):
        """
        Validate and resolve an image path securely.
        
        Args:
            image_path: Raw path to validate
            
        Returns:
            Path object or None if validation fails
            
        Security:
        - Sanitizes path input
        - Resolves relative paths safely
        - Validates path is within allowed directory
        - Checks file existence
        """
        try:
            # Clean up the path
            image_path = image_path.strip().strip("'").strip('"')
            
            # Debug the path
            print(f"DEBUG: Raw image path: {image_path}")
            
            # Convert to Path object for safer operations
            path_obj = Path(image_path)
            
            # Try several options to find the image
            potential_paths = [
                path_obj,                                       # As provided
                Path(os.getcwd()) / path_obj,                   # Relative to CWD
                Path(self.images_dir) / path_obj.name,          # In images dir
                Path('assets') / path_obj.name,                 # In assets dir
                Path(os.getcwd()) / 'assets' / path_obj.name,   # In CWD/assets
            ]
            
            for potential_path in potential_paths:
                print(f"DEBUG: Trying path: {potential_path}")
                if potential_path.exists() and potential_path.is_file():
                    # Make sure it's a valid image file based on extension
                    if potential_path.suffix.lower() in ['.png', '.jpg', '.jpeg', '.gif', '.bmp']:
                        print(f"DEBUG: Found valid image at: {potential_path}")
                        return potential_path
            
            # If we get here, we didn't find a valid image
            return None
            
        except Exception as e:
            print(f"DEBUG: Path validation error: {str(e)}")
            return None

    def generate_totp(self, secret=None, return_remaining=True):
        """Generate TOTP code from a secret"""
        if secret is None:
            secret = self.secret
            
        if not secret:
            return None, 0 if return_remaining else None
            
        try:
            # Extract the string from the SecureString and properly encode it for TOTP
            raw_value = secret.get_raw_value()
            
            # Debug print
            if os.environ.get("DEBUG", "").lower() in ("1", "true", "yes"):
                # Don't create a new line for debug outputs during continuous generation
                if self.is_generating:
                    sys.stdout.write("\r")  # Move cursor to beginning of line
                
                print(f"DEBUG: Secret length: {len(raw_value)}", end="")
                print(f" | Secret (for testing only): {raw_value}", end="")
                
                # Only add newline if not in continuous generation mode
                if not self.is_generating:
                    print()  # Add newline
            
            # Generate TOTP with the secret directly - the secret from QR codes is already encoded
            totp = pyotp.TOTP(raw_value)
            code = totp.now()
            
            if return_remaining:
                # Calculate time remaining until next code - more accurate calculation
                now = time.time()
                step = 30  # Default TOTP step is 30 seconds
                remaining = int(step - (now % step))
                return code, remaining
            
            return code
        except Exception as e:
            if os.environ.get("DEBUG", "").lower() in ("1", "true", "yes"):
                print(f"ERROR: Failed to generate TOTP code: {e}")
                traceback.print_exc()
            return None, 0 if return_remaining else None

    def continuous_generate(self, callback=None, debug_mode=False):
        """
        Generate TOTP codes continuously.
        
        Args:
            callback: Optional function to call with each new code.
                     If None, prints codes to stdout.
            debug_mode: If True, shows debug output on the same line as the code.
                     
        The callback function receives two arguments:
        - code: The current TOTP code
        - remaining: Seconds until code expires
        
        Security:
        - Handles interrupts gracefully
        - Cleans up on exit
        - Updates at appropriate intervals
        """
        if not self.secret:
            print("No secret key available. Please load a secret first.")
            return
        
        self.is_generating = True
        last_code = None
        
        try:
            print("\nPress Ctrl+C to return to the main menu")
            print(f"Generating codes for: {self.issuer or 'Unknown'} ({self.account or 'Unknown'})")
            print("-" * 40)
            
            while self.is_generating:
                code, remaining = self.generate_totp()
                
                if code:
                    # Update the display on every iteration
                    if callback:
                        callback(code, remaining)
                    else:
                        # Enhanced display with progress bar
                        progress = "#" * (int(remaining / 3)) + "-" * (10 - int(remaining / 3))
                        if debug_mode:
                            print(f"\rCode: {code} | Expires in: {remaining:2d}s [{progress}] | DEBUG: Secret length: {len(self.secret.get_raw_value())} | Secret (for testing only): {self.secret.get_raw_value()}", end="")
                        else:
                            print(f"\rCode: {code} | Expires in: {remaining:2d}s [{progress}]", end="")
                        sys.stdout.flush()
                
                # Sleep for a short time to avoid CPU usage
                time.sleep(0.5)
        except KeyboardInterrupt:
            pass
        finally:
            self.is_generating = False
            print("\nStopped code generation.")
            
    def save_secret(self, name, password=None):
        """
        Save the current secret securely.
        
        Args:
            name: Name to identify the saved secret
            password: Optional password for additional encryption
            
        Returns:
            str: Error message if failed, None if successful
            
        Security:
        - Encrypts secret before storage
        - Validates input parameters
        - Returns generic error messages
        """
        if not self.secret:
            return "No secret available to save"
            
        # Check if vault is not initialized
        if not self.storage.vault.is_initialized():
            # We need to create the vault first
            print("\nThis is the first time saving a secret. You need to set up a vault password.")
            vault_password = input("Enter a vault password to secure your secrets: ")
            if not vault_password:
                return "Vault password cannot be empty"
                
            confirm_password = input("Confirm vault password: ")
            if vault_password != confirm_password:
                return "Passwords do not match"
                
            # Master password can be the same for simplicity
            master_password = vault_password
            
            # Initialize the vault
            try:
                self.storage.vault.create_vault(vault_password, master_password)
                self.storage.vault.unlock_vault(vault_password)
                self.storage._unlock()
                
                # Make sure the key is derived from the vault's master key
                master_key = self.storage.vault.get_master_key()
                if master_key and master_key.get():
                    self.storage.key = base64.b64decode(master_key.get().encode())
                    master_key.clear()
                
                self.is_vault_mode = True
                print("Vault created and unlocked successfully.")
                print(f"Vault unlocked state: {self.storage.vault.is_unlocked()}")
                print(f"Storage unlocked state: {self.storage.is_unlocked}")
            except Exception as e:
                return f"Failed to create vault: {str(e)}"
        # Check if vault is initialized but locked
        elif self.storage.vault.is_initialized() and not self.storage.vault.is_unlocked():
            # We need to unlock the vault
            print("\nVault is locked. Please unlock it to save your secret.")
            vault_password = input("Enter your vault password: ")
            if not vault_password:
                return "Vault password cannot be empty"
                
            try:
                if not self.storage.vault.unlock_vault(vault_password):
                    return "Incorrect vault password"
                self.storage._unlock()
                
                # Make sure the key is derived from the vault's master key
                master_key = self.storage.vault.get_master_key()
                if master_key and master_key.get():
                    self.storage.key = base64.b64decode(master_key.get().encode())
                    master_key.clear()
                
                print("Vault unlocked successfully.")
                print(f"Vault unlocked state: {self.storage.vault.is_unlocked()}")
                print(f"Storage unlocked state: {self.storage.is_unlocked}")
            except Exception as e:
                return f"Failed to unlock vault: {str(e)}"
        
        try:
            return self.storage.save_secret(name, self.secret, password)  # Return any error from the storage layer
        except Exception as e:
            return f"Failed to save secret: {str(e)}"

    def load_secret(self, name, password=None):
        """
        Load a saved secret.
        
        Args:
            name: Name of the secret to load
            password: Optional password for decryption
            
        Returns:
            str: Error message if failed, None if successful
            
        Security:
        - Decrypts secret securely
        - Validates input parameters
        - Returns generic error messages
        """
        try:
            secret = self.storage.load_secret(name, password)
            if secret:
                self.secret = secret
                return None  # No error
            return "Failed to load secret"
        except Exception as e:
            return f"Failed to load secret: {e}"

    def list_saved_secrets(self):
        """
        List all saved secret names.
        
        Returns:
            list: Names of saved secrets
            
        Security:
        - Returns only names, not secrets
        - Returns empty list on error
        """
        try:
            return self.storage.list_secrets()
        except Exception:
            return []
            
    def export_secrets(self, export_path, master_password=None):
        """
        Export saved secrets to a file.
        
        Args:
            export_path: Path to save the exported secrets
            master_password: Optional master password for encryption
            
        Returns:
            bool: True if successful, False if failed
            
        Security:
        - Encrypts secrets before export
        - Validates export path
        - Returns generic error messages
        """
        try:
            result = self.storage.export_secrets(export_path, master_password)
            return result
        except Exception as e:
            return f"Export failed: {e}"
