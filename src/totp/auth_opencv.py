"""
OpenCV-Based Two-Factor Authentication Module

This module provides the implementation of the TwoFactorAuth class
using OpenCV for QR code scanning, which works reliably across
all platforms.

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
import getpass  # Add getpass module for secure password input
from ..security.secure_string import SecureString
from ..security.secure_storage import SecureStorage
import base64
import datetime
import traceback

class TwoFactorAuth:
    """
    OpenCV-based Two-Factor Authentication implementation.
    
    This class implements Two-Factor Authentication using OpenCV
    for reliable QR code scanning across all platforms.
    
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
        # Store the current TOTP secret
        self.secret = None
        # Flag to track if we're continuously generating codes
        self.is_generating = False
        # Initialize secure storage for secrets
        self.storage = SecureStorage()
        # Check if vault is already initialized
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
            
            # First check if we have write permission to the app directory
            test_file = os.path.join(app_dir, 'images', '.test')
            try:
                # Create images directory if it doesn't exist
                if not os.path.exists(os.path.join(app_dir, 'images')):
                    os.makedirs(os.path.join(app_dir, 'images'), exist_ok=True)
                
                # Test if directory is writable
                with open(test_file, 'w') as f:
                    f.write('test')
                os.remove(test_file)
                # We can write to the directory, use the app's images folder
                self.images_dir = os.getenv('QR_IMAGES_DIR', os.path.join(app_dir, 'images'))
            except Exception:
                # Can't write to program directory, use user's documents folder instead
                user_dir = os.path.join(os.path.expanduser('~'), 'Documents', 'TrueFA-Py', 'images')
                os.makedirs(user_dir, exist_ok=True)
                self.images_dir = os.getenv('QR_IMAGES_DIR', user_dir)
                print(f"Using personal images directory in Documents folder: {user_dir}")
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
            # Try to import OpenCV
            import cv2
            return True
        except ImportError:
            print("OpenCV not found. Installing...")
            try:
                # Install OpenCV using pip
                subprocess.check_call([sys.executable, "-m", "pip", "install", "opencv-python"])
                print("OpenCV installed successfully.")
                import cv2
                return True
            except Exception as e:
                print(f"Failed to install OpenCV: {e}")
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
        # Clear the TOTP secret if it exists
        if self.secret:
            self.secret.clear()
            self.secret = None
        
        # Stop continuous generation if active
        self.is_generating = False

    def scan_qr_code(self, image_path):
        """
        Scan a QR code image using OpenCV to extract a TOTP secret
        
        Args:
            image_path: Path to the QR code image
            
        Returns:
            str: Extracted TOTP secret or None if not found
            
        Raises:
            Exception: If QR code scanning fails
        """
        try:
            # Securely validate and sanitize the image path
            validated_path, error = self._validate_image_path(image_path)
            if not validated_path:
                print(f"Image validation error: {error}")
                return None
                
            # Load the image
            image = cv2.imread(validated_path)
            if image is None:
                print(f"Error: Failed to load image at {validated_path}")
                return None
                
            # Initialize the QR Code detector
            qr_detector = cv2.QRCodeDetector()
            
            # Detect and decode the QR code
            data, bbox, _ = qr_detector.detectAndDecode(image)
            
            if not data:
                # Try with image preprocessing if direct detection fails
                preprocessed = self._preprocess_image(image)
                data, bbox, _ = qr_detector.detectAndDecode(preprocessed)
                
            if not data:
                print("No QR code found in the image")
                return None
                
            # Parse the data to extract the TOTP secret
            # Typically in format: otpauth://totp/Label:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Label&algorithm=SHA1&digits=6&period=30
            parsed_data = self._parse_otpauth(data)
            
            # Verify we have a valid secret
            if not parsed_data or 'secret' not in parsed_data or not parsed_data['secret']:
                print("Invalid or missing TOTP secret in QR code")
                return None
                
            # Sanitize the extracted secret
            secret = parsed_data['secret'].strip().upper()
            
            # Validate the secret format (Base32 characters only)
            if not all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567' for c in secret):
                print("Invalid TOTP secret format (not Base32)")
                return None
                
            print(f"Successfully extracted TOTP secret from QR code")
            return secret
            
        except Exception as e:
            print(f"Error scanning QR code: {str(e)}")
            return None

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
        - Securely stores extracted secret
        """
        try:
            # Import OpenCV - this should be available after _check_opencv
            import cv2
            
            # Validate the image path
            valid_path, error_msg = self._validate_image_path(image_path)
            if not valid_path:
                return None, error_msg
                
            # Adjusted path might be relative to images directory
            full_path = os.path.join(self.images_dir, valid_path) if not os.path.isabs(valid_path) else valid_path
            
            # Check if file exists after adjustments
            if not os.path.exists(full_path):
                # Try finding file in images directory if not found at full path
                if not os.path.isabs(valid_path):
                    alternate_path = os.path.join(self.images_dir, os.path.basename(valid_path))
                    if os.path.exists(alternate_path):
                        full_path = alternate_path
                    else:
                        return None, f"File not found: {valid_path}"
                else:
                    return None, f"File not found: {full_path}"
            
            # Load and process the image with OpenCV
            try:
                # Load the image using OpenCV
                img = cv2.imread(str(full_path))
                if img is None:
                    return None, f"Could not read image: {full_path}"
                
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
        Validate and sanitize an image path for security.
        
        Prevents path traversal attacks and ensures file exists.
        Only allows specified image formats for security.
        
        Args:
            image_path: Path to potential QR code image
            
        Returns:
            tuple: (validated_path, error_message)
        """
        # Check for path traversal attempts
        path_to_check = Path(image_path)
        
        # Normalize the path
        try:
            normalized_path = path_to_check.resolve()
        except (ValueError, OSError):
            return None, "Invalid path format"
        
        # Prevent path traversal by checking resolved path
        images_dir_abs = Path(self.images_dir).resolve()
        is_in_images_dir = False
        
        try:
            # Check if the path resolves to something inside the images directory
            if images_dir_abs in normalized_path.parents or images_dir_abs == normalized_path.parent:
                is_in_images_dir = True
        except (ValueError, OSError):
            return None, "Path traversal attempt detected"
        
        # If path doesn't exist and not in images_dir, return error
        if not path_to_check.exists() and not is_in_images_dir:
            # Try with images directory
            if not Path(self.images_dir).exists():
                try:
                    os.makedirs(self.images_dir, exist_ok=True)
                except (PermissionError, OSError):
                    return None, f"Cannot create images directory: {self.images_dir}"
                
            # Check if it might be a filename in the images directory
            alt_path = Path(self.images_dir) / Path(image_path).name
            if not alt_path.exists():
                return None, f"Image file not found: {image_path}"
            path_to_check = alt_path
        
        # Verify the file is actually an image
        valid_extensions = ['.png', '.jpg', '.jpeg', '.bmp', '.gif', '.webp']
        if path_to_check.suffix.lower() not in valid_extensions:
            return None, f"Invalid image format. Allowed formats: {', '.join(valid_extensions)}"
        
        # Validate the file size to prevent loading very large images
        try:
            file_size = path_to_check.stat().st_size
            if file_size > 5 * 1024 * 1024:  # 5 MB limit
                return None, "Image file too large (>5MB)"
            if file_size == 0:
                return None, "Empty file"
        except (OSError, PermissionError):
            return None, "Cannot access file"
        
        # Basic file type validation - check file headers
        try:
            with open(path_to_check, 'rb') as f:
                header = f.read(8)  # Read first 8 bytes for file signature
                
            # Check common image format signatures
            valid_signatures = [
                b'\x89PNG\r\n\x1a\n',  # PNG
                b'\xff\xd8\xff',        # JPEG (first 3 bytes)
                b'GIF87a', b'GIF89a',   # GIF
                b'BM',                  # BMP (first 2 bytes)
                b'RIFF'                 # WEBP (starts with RIFF)
            ]
            
            is_valid = False
            for sig in valid_signatures:
                if header.startswith(sig):
                    is_valid = True
                    break
                
            if not is_valid:
                return None, "Invalid image file type"
        except (OSError, PermissionError):
            return None, "Cannot read file"
        
        return str(path_to_check), None

    def generate_totp(self, secret=None, return_remaining=True):
        """
        Generate a TOTP code from the provided or stored secret.
        
        Args:
            secret: The secret key to use. If None, uses self.secret
            return_remaining: Whether to return remaining time until code expiration
        
        Returns:
            If return_remaining is True:
                tuple: (TOTP code string, int seconds remaining until expiration)
            If return_remaining is False:
                str: TOTP code string
            If error or no secret:
                (None, 0) or None depending on return_remaining
        """
        # Use stored secret if none provided
        if secret is None:
            secret = self.secret
            
        # Return immediately if no secret available
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
            # Log error in debug mode
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
        # Check if a secret is available
        if not self.secret:
            print("No secret key available. Please load a secret first.")
            return
        
        # Set the continuous generation flag
        self.is_generating = True
        
        try:
            # Store the last code to avoid unnecessary updates
            last_code = None
            
            # Continue until interrupted
            while self.is_generating:
                try:
                    # Generate the current code and get remaining time
                    code, remaining = self.generate_totp()
                    
                    # Only update if the code has changed or we're close to expiration
                    if code != last_code or remaining <= 5:
                        # If a callback is provided, use it; otherwise print to console
                        if callback:
                            callback(code, remaining)
                        else:
                            # Clear the line and print the new code with expiration time
                            sys.stdout.write('\r' + ' ' * 50 + '\r')  # Clear line
                            
                            # Print code with color based on remaining time
                            if remaining <= 5:
                                # Red when close to expiring
                                color_code = "\033[91m"  # Red
                            elif remaining <= 10:
                                # Yellow for warning
                                color_code = "\033[93m"  # Yellow
                            else:
                                # Green for plenty of time
                                color_code = "\033[92m"  # Green
                                
                            # Reset color code after printing
                            reset_code = "\033[0m"
                            
                            # Format and print current code and time
                            sys.stdout.write(f"Code: {color_code}{code}{reset_code} (expires in {remaining}s)")
                            sys.stdout.flush()
                        
                        # Update last code
                        last_code = code
                except KeyboardInterrupt:
                    pass
        except Exception as e:
            print(f"ERROR: Exception in continuous_generate: {e}")
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
        # Check if we have a secret to save
        if not self.secret:
            return "No secret available to save"
            
        # Check if vault is not initialized
        if not self.storage.vault.is_initialized():
            # First-time setup: create the vault
            print("\nThis is the first time saving a secret. You need to set up a vault password.")
            
            # Securely get and confirm the vault password
            vault_password = getpass.getpass("Enter a vault password to secure your secrets: ")
            if not vault_password:
                return "Vault password cannot be empty"
                
            confirm_password = getpass.getpass("Confirm vault password: ")
            if vault_password != confirm_password:
                return "Passwords do not match"
                
            # Use vault password as master password for simplicity
            master_password = vault_password
            
            # Initialize the vault with the passwords
            try:
                # Create the vault with the passwords
                self.storage.vault.create_vault(vault_password, master_password)
                # Unlock the vault for immediate use
                self.storage.vault.unlock_vault(vault_password)
                # Mark storage as unlocked
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
            
            # Get the vault password
            vault_password = getpass.getpass("Enter your vault password: ")
            if not vault_password:
                return "Vault password cannot be empty"
                
            try:
                # Attempt to unlock the vault
                if not self.storage.vault.unlock_vault(vault_password):
                    return "Incorrect vault password"
                
                # Mark storage as unlocked
                self.storage._unlock()
                
                # Get the master key for encryption
                master_key = self.storage.vault.get_master_key()
                if master_key and master_key.get():
                    self.storage.key = base64.b64decode(master_key.get().encode())
                    master_key.clear()
                
                self.is_vault_mode = True
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

    def _preprocess_image(self, image):
        """
        Preprocess an image to improve QR code detection
        
        Args:
            image: OpenCV image
            
        Returns:
            Preprocessed image
        """
        # Convert to grayscale
        gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
        
        # Apply adaptive thresholding
        thresh = cv2.adaptiveThreshold(gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, 
                                       cv2.THRESH_BINARY, 11, 2)
        
        # Apply image enhancement techniques
        blur = cv2.GaussianBlur(gray, (5, 5), 0)
        _, binary = cv2.threshold(blur, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
        
        # Return both processed versions (the QR detector will try both)
        return binary
        
    def _parse_otpauth(self, uri):
        """
        Parse an otpauth:// URI to extract TOTP parameters
        
        Args:
            uri: otpauth URI string
            
        Returns:
            dict: Parsed parameters or None if invalid
        """
        # Basic validation - must start with otpauth://
        if not uri or not uri.startswith('otpauth://'):
            return None
            
        # Extract the secret and other parameters
        try:
            # Security check - limit URI length to prevent DoS
            if len(uri) > 1024:
                return None
                
            # Parse the URI
            parsed = {}
            
            # Get the query parameters
            if '?' in uri:
                query_string = uri.split('?', 1)[1]
                pairs = query_string.split('&')
                
                for pair in pairs:
                    if '=' in pair:
                        key, value = pair.split('=', 1)
                        # Sanitize the keys and values
                        key = key.strip().lower()
                        value = value.strip()
                        
                        # Only accept known keys for security
                        if key in ['secret', 'issuer', 'algorithm', 'digits', 'period']:
                            parsed[key] = value
            
            return parsed
        except Exception:
            return None
