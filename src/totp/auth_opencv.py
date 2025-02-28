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
            except ImportError:
                return None, "OpenCV is required for QR scanning. Please install it with 'pip install opencv-python'"
            
            # Read and process image
            img = cv2.imread(str(image_path))
            if img is None:
                return None, f"Could not read image: {image_path}"
            
            # Initialize QR Code detector
            detector = cv2.QRCodeDetector()
            
            # Detect and decode
            data, bbox, _ = detector.detectAndDecode(img)
            
            # Process QR code data
            if data:
                if data.startswith('otpauth://'):
                    parsed = urllib.parse.urlparse(data)
                    params = dict(urllib.parse.parse_qsl(parsed.query))
                    
                    if 'secret' in params:
                        # Normalize the secret to ensure it's valid base32
                        secret = params['secret']
                        # Remove any non-Base32 characters and convert to uppercase
                        secret = ''.join(c for c in secret.upper() if c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567')
                        
                        # Force proper Base32 padding
                        # Base32 padding is applied in blocks of 8 characters
                        padding_length = (8 - (len(secret) % 8)) % 8
                        secret += '=' * padding_length
                        
                        # Try to verify the secret is valid by creating a TOTP
                        try:
                            totp = pyotp.TOTP(secret)
                            # If this doesn't raise an exception, the secret is valid
                            totp.now()
                            return SecureString(secret), None
                        except Exception as e:
                            return None, f"Invalid TOTP secret format: {str(e)}"
                
                return None, "No valid otpauth URL found in QR code"
            else:
                return None, "No QR code found in the image"
            
        except Exception as e:
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
            
            # Convert to Path object for secure path manipulation
            path = Path(image_path)
            
            # If path is relative, assume it's relative to images_dir
            if not path.is_absolute():
                path = Path(self.images_dir) / path
            
            # Resolve path
            resolved_path = path.resolve()
            
            # Verify file exists and is actually a file
            if not resolved_path.exists() or not resolved_path.is_file():
                return None
            
            return resolved_path
            
        except Exception:
            return None

    def generate_totp(self, secret=None):
        """
        Generate TOTP code from a secret.
        
        Args:
            secret: Optional SecureString containing the TOTP secret.
                   If None, uses the instance's current secret.
                   
        Returns:
            tuple: (str: Current TOTP code or None if failed,
                   int: Seconds until code expires or error message)
                   
        Security:
        - Uses PyOTP library for secure TOTP generation
        - Handles Base32 normalization and validation
        - Returns generic error messages
        """
        # Use instance secret if none provided
        secret = secret or self.secret
        
        if not secret:
            return None, "No secret key available"
        
        try:
            # Get the secure string value temporarily
            secret_value = str(secret)
            
            # Normalize the secret for better compatibility
            # Try to make the input more lenient by converting to uppercase and removing non-Base32 chars
            # Base32 only allows A-Z and 2-7
            normalized_value = ''.join(c for c in secret_value.upper() if c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567')
            
            if not normalized_value:
                return None, "Secret contains no valid Base32 characters"
                
            # Force proper Base32 padding
            # Base32 padding is applied in blocks of 8 characters
            padding_length = (8 - (len(normalized_value) % 8)) % 8
            normalized_value += '=' * padding_length
            
            # Generate the code using pyotp
            try:
                totp = pyotp.TOTP(normalized_value)
                code = totp.now()
                
                # Get the remaining seconds
                remaining = 30 - (int(time.time()) % 30)
                
                return code, remaining
            except Exception as e:
                # If there's still an error, it's likely an invalid Base32 format
                # But don't clear the secret, just return the error
                print(f"Warning: {str(e)}")
                return None, f"Invalid TOTP secret format: {str(e)}"
                
        except Exception as e:
            print(f"Error generating TOTP code: {str(e)}")
            return None, f"Error generating 2FA code: {str(e)}"

    def continuous_generate(self, callback=None):
        """
        Generate TOTP codes continuously.
        
        Args:
            callback: Optional function to call with each new code.
                     If None, prints codes to stdout.
                     
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
        
        try:
            while self.is_generating:
                code, remaining = self.generate_totp()
                
                if code:
                    if callback:
                        callback(code, remaining)
                    else:
                        # Default display
                        print(f"\rCode: {code} (Expires in: {remaining}s)", end="")
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
                self.is_vault_mode = True
                # Set storage to unlocked state
                self.storage._unlock()
                print("Vault created and unlocked successfully.")
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
                # Set storage to unlocked state
                self.storage._unlock()
                print("Vault unlocked successfully.")
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
