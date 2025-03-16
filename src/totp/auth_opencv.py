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
import socket  # For anti-debug
import threading  # For anti-debug
import hmac  # For file integrity verification
import hashlib  # For file integrity verification
import json
import random
import logging
import shutil  # For copying files
from src.utils.logger import warning, info, error

# Import new security modules
from ..security.file_integrity import FileIntegrityVerifier, add_hmac_to_file, verify_file_integrity
from ..security.security_events import record_security_event
from ..utils.debug import debug_print

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
    
    def __init__(self, storage=None):
        """
        Initialize the TwoFactorAuth instance.
        
        Args:
            storage: Optional SecureStorage instance to use for saving/loading secrets
        """
        # Core configuration
        self.secret = None
        self.issuer = None
        self.account = None
        self.algorithm = 'SHA1'
        self.digits = 6
        self.period = 30
        
        # Use provided storage or create a new one
        if storage is not None:
            debug_print("Using provided SecureStorage instance")
            self.storage = storage
        else:
            debug_print("Creating new SecureStorage instance")
            from ..security.secure_storage import SecureStorage
            self.storage = SecureStorage()
        
        # Verify we have paths for images
        self.images_dir = self._find_storage_dirs()
        
        # Set up OpenCV if available
        self.opencv_available = self._check_opencv()
        
        try:
            # Check for debugger
            if os.environ.get("TRUEFA_SKIP_DEBUGGER_CHECK", "").lower() not in ("1", "true", "yes"):
                self._check_debugger()
            
            # Register signal handlers for secure cleanup
            signal.signal(signal.SIGINT, self._signal_handler)
            signal.signal(signal.SIGTERM, self._signal_handler)
            if hasattr(signal, 'SIGHUP'):  # Not available on Windows
                signal.signal(signal.SIGHUP, self._signal_handler)
                
            # Setup instance variables
            self.continuous_thread = None
            self.should_stop = threading.Event()
            self.is_generating = False  # Flag for continuous generation
            
            # Initialize the logger
            self.logger = logging.getLogger(__name__)
            
        except Exception as e:
            print(f"Error initializing TwoFactorAuth: {str(e)}")
            raise

    def _check_opencv(self):
        """
        Check if OpenCV is installed and use a graceful fallback if not.
        
        Returns:
            bool: True if OpenCV is available, False otherwise
        """
        try:
            # Try to import OpenCV
            import cv2
            return True
        except ImportError:
            print("OpenCV not found. Installation will be skipped.")
            print("QR code functionality will be limited.")
            
            # Instead of trying to install at runtime, provide clear instructions
            if getattr(sys, 'frozen', False):
                print("This executable requires OpenCV for QR code scanning.")
                print("The application will continue with limited functionality.")
                print("To enable QR code scanning, please use the full installer version.")
            else:
                print("To enable QR code scanning, install OpenCV manually:")
                print("pip install opencv-python")
            
            return False

    def _signal_handler(self, signum, frame):
        """
        Handle program termination signals securely.
        
        Ensures proper cleanup of sensitive data when the program
        is interrupted or terminated.
        """
        # Stop continuous generation if it's running
        if self.is_generating:
            print("\nStopping code generation...")
            self.is_generating = False
            self.should_stop.set()
            time.sleep(0.5)  # Give a moment for the generation to stop
            return  # Return to menu without cleaning up or locking the vault
        
        # Otherwise clean up and exit (only for actual program termination)
        self.cleanup()
        #print("\nExiting securely...")
        sys.exit(0)

    def cleanup(self):
        """
        Perform secure cleanup of sensitive data.
        
        Ensures that all secret data is properly zeroized
        and removed from memory without affecting the vault's locked state.
        """
        # Clear the TOTP secret if it exists
        if self.secret:
            self.secret.clear()
            self.secret = None
        
        # Clear other sensitive data
        self.issuer = None
        self.account = None
        
        # Note: We intentionally don't lock the vault here to maintain
        # its state between operations in the same session

    def _secure_create_file(self, file_path, content="", mode=0o600):
        """
        Securely create a file with proper permissions.
        
        Args:
            file_path: Path to the file to create
            content: Optional content to write to the file
            mode: File permissions to set (default: 0o600 - user read/write only)
            
        Returns:
            bool: True if successful, False otherwise
            
        Security:
        - Sets restrictive permissions immediately after creation
        - Uses atomic write operations where possible
        - Creates parent directories with secure permissions if needed
        """
        try:
            # Ensure parent directory exists with secure permissions
            parent_dir = os.path.dirname(file_path)
            if not os.path.exists(parent_dir):
                os.makedirs(parent_dir, mode=0o700, exist_ok=True)
            
            # Create the file atomically if possible
            # First write to a temporary file, then rename
            temp_path = f"{file_path}.tmp"
            with open(temp_path, 'w') as f:
                f.write(content)
                # Ensure data is flushed to disk
                f.flush()
                os.fsync(f.fileno())
            
            # Set permissions before moving to final location
            try:
                os.chmod(temp_path, mode)
            except Exception as e:
                # Continue even if chmod fails, this is best-effort
                warning(f"Could not set file permissions: {e}")
            
            # Move temp file to final location (atomic on POSIX systems)
            if os.path.exists(file_path):
                os.unlink(file_path)
            os.rename(temp_path, file_path)
            
            return True
        except Exception as e:
            print(f"Error creating secure file: {e}")
            # Clean up temp file if it exists
            if os.path.exists(temp_path):
                try:
                    os.unlink(temp_path)
                except:
                    pass
            return False

    def _validate_secret_data(self, data):
        """
        Validate secret data before use to prevent unsafe deserialization.
        
        Args:
            data: The data to validate
            
        Returns:
            tuple: (bool validity, str error_message if invalid)
            
        Security:
        - Ensures only expected data types and fields are present
        - Prevents injection of malicious data
        - Validates format of critical fields
        """
        if not isinstance(data, dict):
            return False, "Invalid data format"
        
        # Validate required fields
        if "secret" not in data:
            return False, "Missing required 'secret' field"
        
        # Validate field types
        if not isinstance(data.get("secret"), str):
            return False, "Secret must be a string"
        
        # Optional fields should be of correct type if present
        if "issuer" in data and not isinstance(data["issuer"], str):
            return False, "Issuer must be a string"
        
        if "account" in data and not isinstance(data["account"], str):
            return False, "Account must be a string"
        
        # Validate secret format (base32 encoding)
        secret = data.get("secret", "")
        if secret:
            # Basic validation for base32-encoded string
            base32_pattern = re.compile(r'^[A-Z2-7]+=*$')
            if not base32_pattern.match(secret):
                return False, "Secret does not appear to be in valid base32 format"
        
        return True, None

    def extract_secret_from_qr(self, image_path):
        """
        Extract TOTP secret from a QR code image.
        
        Args:
            image_path (str): Path to the QR code image
            
        Returns:
            tuple: (SecureString or None, str) - The extracted secret and status message
            
        Features:
        - Validates image path for security
        - Extracts otpauth:// URL from QR code
        - Parses URL to extract secret, issuer, and account
        - Securely stores extracted secret
        """
        from ..utils.debug import debug_print
        
        try:
            # Import OpenCV
            import cv2
            debug_print("OpenCV imported successfully")
            
            # Check if image_path is None
            if image_path is None:
                debug_print("image_path is None")
                return None, "No image path provided"
            
            # Validate the image path
            valid_path, error_msg = self._validate_image_path(image_path)
            if not valid_path:
                debug_print(f"Path validation failed: {error_msg}")
                return None, error_msg
            
            debug_print(f"Reading image from validated path: {valid_path}")
            
            # Load the image using OpenCV
            img = cv2.imread(valid_path)
            if img is None:
                debug_print(f"Failed to read image: {valid_path}")
                return None, f"Could not read image: {valid_path}"
            
            debug_print(f"Image loaded successfully, shape: {img.shape}")
            
            # Initialize QR Code detector
            detector = cv2.QRCodeDetector()
            
            # Detect and decode
            debug_print("Attempting to detect and decode QR code...")
            data, bbox, _ = detector.detectAndDecode(img)
            
            debug_print(f"QR code data: {data if data else 'None'}")
            debug_print(f"QR code bounding box: {bbox if bbox is not None else 'None'}")
            
            # Process QR code data
            if data:
                debug_print(f"Raw QR data: {data}")
                if data.startswith('otpauth://'):
                    parsed = urllib.parse.urlparse(data)
                    params = dict(urllib.parse.parse_qsl(parsed.query))
                    
                    debug_print(f"Parsed params: {params}")
                    
                    if 'secret' in params:
                        # Extract and normalize the secret
                        secret = params['secret']
                        debug_print(f"Raw secret from QR: {secret}")
                        
                        # Create a secure string from the extracted secret
                        secure_secret = SecureString(secret)
                        
                        # Set the issuer and account if available
                        path = parsed.path
                        if path.startswith('/'):
                            path = path[1:]
                        
                        if ':' in path:
                            issuer_account = path.split(':')
                            if len(issuer_account) >= 2:
                                self.issuer = issuer_account[0]
                                self.account = issuer_account[1]
                        
                        # If issuer is in params, it takes precedence
                        if 'issuer' in params:
                            self.issuer = params['issuer']
                            
                        debug_print(f"Parsed issuer: {self.issuer}, account: {self.account}")
                        
                        # Store the secret in the instance for later use with continuous_generate
                        self.secret = secure_secret
                        debug_print("Secret successfully stored in the TwoFactorAuth instance")
                        
                        return secure_secret, "Secret extracted successfully"
                    else:
                        return None, "QR code does not contain a valid TOTP secret"
                else:
                    return None, "QR code does not contain an otpauth:// URL"
            else:
                return None, "No QR code detected in the image"
                
        except ImportError as e:
            debug_print(f"ImportError: {e}")
            return None, "OpenCV not available. Cannot process QR codes."
        except Exception as e:
            debug_print(f"Exception in extract_secret_from_qr: {str(e)}")
            return None, f"Error processing QR code: {str(e)}"

    def process_qr_code(self, image_path):
        """
        Process a QR code image and extract TOTP account information.
        
        This method is primarily used by the GUI to extract formatted account 
        information from a QR code image. It wraps extract_secret_from_qr with
        additional processing to format the data for the GUI.
        
        Args:
            image_path (str): Path to the QR code image
            
        Returns:
            tuple: (account_data, error_message)
                - account_data: Dictionary with keys 'secret', 'account', 'issuer'
                  or None if extraction failed
                - error_message: Error message if failed, None if successful
        """
        from ..utils.debug import debug_print
        
        try:
            # First extract the secret using the base method
            secret_obj, error_msg = self.extract_secret_from_qr(image_path)
            
            if error_msg or not secret_obj:
                debug_print(f"Failed to extract secret: {error_msg}")
                return None, error_msg or "Failed to extract TOTP data from QR code"
            
            # Get the raw secret value
            if hasattr(secret_obj, 'get_raw_value'):
                secret_value = secret_obj.get_raw_value()
            elif hasattr(secret_obj, 'get'):
                secret_value = secret_obj.get()
            else:
                secret_value = str(secret_obj)
            
            # Ensure it's a string
            if isinstance(secret_value, bytes):
                try:
                    secret_value = secret_value.decode('utf-8')
                except UnicodeDecodeError:
                    # If we can't decode as UTF-8, use base64 encoding
                    secret_value = "base64:" + base64.b64encode(secret_value).decode('ascii')
            
            # Create the account data dictionary
            account_data = {
                'secret': secret_value,
                'account': self.account or "Unknown",
                'issuer': self.issuer or ""
            }
            
            debug_print(f"Successfully processed QR code: account={account_data['account']}, issuer={account_data['issuer']}")
            return account_data, None
            
        except Exception as e:
            debug_print(f"Exception in process_qr_code: {str(e)}")
            return None, f"Error processing QR code: {str(e)}"

    def _validate_image_path(self, image_path):
        """
        Validate and resolve an image path securely.
        
        Args:
            image_path: Raw path to validate
            
        Returns:
            tuple: (valid_path, error_message) - valid_path is None if validation fails
            
        Security:
        - Sanitizes path input
        - Resolves relative paths safely
        - Validates path is within allowed directory
        - Checks file existence
        """
        from ..utils.debug import debug_print
        
        # Basic validation
        if image_path is None:
            debug_print("image_path is None")
            return None, "No image path provided"
            
        try:
            # Clean up the path
            image_path = str(image_path).strip().strip("'").strip('"')
            debug_print(f"Raw image path after cleanup: {image_path}")
            
            # Ensure images directory exists
            os.makedirs(self.images_dir, exist_ok=True)
            
            # List of paths to try
            paths_to_try = [
                image_path,  # As provided
                os.path.join(os.getcwd(), image_path),  # Relative to CWD
                os.path.join(self.images_dir, image_path),  # In images dir
                os.path.join(self.images_dir, os.path.basename(image_path))  # Just basename in images dir
            ]
            
            # Try each path
            for path in paths_to_try:
                debug_print(f"Trying path: {path}")
                if os.path.exists(path) and os.path.isfile(path):
                    # Validate file extension
                    _, ext = os.path.splitext(path)
                    if ext.lower() not in ['.png', '.jpg', '.jpeg', '.gif', '.bmp']:
                        return None, f"File must be an image type (.png, .jpg, .jpeg, .gif, .bmp)"
                    
                    # Additional security check
                    full_path = os.path.abspath(path)
                    
                    # Verify path is within allowed directories
                    allowed_dirs = [
                        os.path.abspath(self.images_dir),
                        os.path.abspath(os.getcwd()),
                        os.path.abspath(os.path.join(os.getcwd(), 'assets'))
                    ]
                    
                    is_allowed = False
                    for allowed_dir in allowed_dirs:
                        if full_path.startswith(allowed_dir):
                            is_allowed = True
                            break
                    
                    if not is_allowed:
                        debug_print(f"Security warning: Path outside of allowed directories: {full_path}")
                        return None, "Path is outside of allowed directories"
                    
                    debug_print(f"Found valid image at: {full_path}")
                    return full_path, None
            
            # If we get here, no valid path was found
            return None, f"Could not find image file: {image_path}"
            
        except Exception as e:
            debug_print(f"Path validation error: {str(e)}")
            return None, f"Error validating path: {str(e)}"

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
        from ..utils.debug import debug_print
        
        # Use stored secret if none provided
        if secret is None:
            secret = self.secret
            
        # Return immediately if no secret available
        if not secret:
            return None, 0 if return_remaining else None
            
        try:
            # Extract the secret value based on type
            secret_value = None
            
            # Handle different types of secret objects
            if hasattr(secret, 'get'):
                # It's our SecureString class
                secret_value = secret.get()
            elif hasattr(secret, 'get_raw_value'):
                # Legacy method
                secret_value = secret.get_raw_value()
            elif hasattr(secret, 'get_value'):
                # Another potential method
                try:
                    value = secret.get_value()
                    if isinstance(value, bytes):
                        # Bytes should be handled as base32 for TOTP
                        try:
                            secret_value = value.decode('utf-8', errors='strict')
                        except UnicodeDecodeError:
                            # If we can't decode as UTF-8, log error
                            debug_print(f"Error: Unable to decode bytes as UTF-8. TOTP may be incorrect.")
                            secret_value = str(value)
                    else:
                        secret_value = str(value)
                except Exception as e:
                    debug_print(f"Error getting value: {e}")
                    secret_value = str(secret)
            else:
                # Process direct string or bytes
                if isinstance(secret, bytes):
                    try:
                        secret_value = secret.decode('utf-8', errors='strict')
                    except UnicodeDecodeError:
                        debug_print(f"Error: Unable to decode bytes as UTF-8. TOTP may be incorrect.")
                        secret_value = str(secret)
                else:
                    # Try direct string conversion as a last resort
                    secret_value = str(secret)
            
            # Ensure the secret is in the correct format for TOTP
            # TOTP expects base32 encoded strings
            if secret_value and not self._is_valid_base32(secret_value):
                debug_print(f"Warning: Secret does not appear to be valid base32. TOTP may be incorrect.")
            
            # Debug print
            if os.environ.get("DEBUG", "").lower() in ("1", "true", "yes"):
                # Don't create a new line for debug outputs during continuous generation
                if self.is_generating:
                    sys.stdout.write("\r")  # Move cursor to beginning of line
                
                debug_print(f"Secret length: {len(secret_value)}", end="")
                debug_print(f" | Secret type: {type(secret_value).__name__}", end="")
                
                # Only add newline if not in continuous generation mode
                if not self.is_generating:
                    print()  # Add newline
            
            # Generate TOTP with the secret
            totp = pyotp.TOTP(secret_value)
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
                debug_print(f"Failed to generate TOTP code: {e}")
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
        - Updates at fixed 1-second intervals for smooth display
        """
        from ..utils.debug import debug_print
        
        # Check if a secret is available
        if not self.secret:
            print("No secret key available. Please load a secret first.")
            return
        
        # Reset the stop event
        self.should_stop.clear()
        
        # Set the continuous generation flag
        self.is_generating = True
        
        try:
            # Store the last code and remaining time to avoid redundant updates
            last_code = None
            last_remaining = 0
            
            # Continue until interrupted
            while self.is_generating and not self.should_stop.is_set():
                try:
                    # Generate the current code and get remaining time
                    code, remaining = self.generate_totp()
                    
                    # Only update the display if the code or remaining time has changed
                    if code != last_code or remaining != last_remaining:
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
                        
                        # Store the current values for next comparison
                        last_code = code
                        last_remaining = remaining
                    
                    # Sleep for a full second to maintain a consistent update rate
                    # Only use shorter sleep when very close to expiration to ensure we catch the new code
                    time.sleep(1.0)
                        
                except KeyboardInterrupt:
                    debug_print("\nKeyboard interrupt detected. Stopping code generation...")
                    self.should_stop.set()
                    
        except Exception as e:
            debug_print(f"ERROR: Exception in continuous_generate: {e}")
        finally:
            # Clean up
            self.is_generating = False
            print("\nStopping code generation...")
            
    def save_secret(self, name, secret=None, password=None):
        """
        Save a secret to the vault.
        
        Args:
            name: Name to identify the secret
            secret: Optional secret data to save (uses current secret if None)
            password: Optional password to unlock vault if needed
            
        Returns:
            str: Error message on failure, None on success
        """
        from ..utils.debug import debug_print
        
        try:
            # Basic validation
            if not name or not isinstance(name, str):
                return "Invalid secret name"
            
            # Sanitize the name
            sanitized_name = re.sub(r'[^\w\s-]', '', name)
            if sanitized_name != name:
                return "Name contains invalid characters (only letters, numbers, spaces, underscores, and dashes are allowed)"
            
            # Prevent common injection patterns
            if '..' in name or '/' in name or '\\' in name:
                return "Name contains invalid characters"
            
            # Get the vault file path
            vault_file = os.path.join(self.storage.vault_dir, "vault.json")
            debug_print(f"Vault file exists: {os.path.exists(vault_file)}")
            debug_print(f"Checking vault.is_initialized property: {self.storage.vault.is_initialized}")
            
            # Track if we created a new vault
            created_new_vault = False
            
            # Handle vault initialization
            if not self.storage.vault.is_initialized:
                # Need to create a new vault
                print("\nThis is the first time saving a secret. You need to set up a vault password.")
                
                # Ask for master password and create vault
                master_password = getpass.getpass("Create a master password for your vault: ")
                if len(master_password) < 8:
                    return "Password must be at least 8 characters long"
                
                confirm_password = getpass.getpass("Confirm master password: ")
                if master_password != confirm_password:
                    return "Passwords do not match"
                
                print("Creating new vault...")
                if self.storage.create_vault(master_password):
                    print("Vault created successfully.")
                    # Set the password parameter for the upcoming save operation
                    password = master_password
                    created_new_vault = True
                    # Store the password for session tracking
                    self.last_used_password = master_password
                else:
                    return "Failed to create vault"
            elif not self.storage.vault.is_unlocked:
                # Vault exists but is locked - need to unlock it
                # Check if password was provided
                if password is None:
                    master_password = getpass.getpass("Enter your vault master password: ")
                    password = master_password
                
                if not self.storage.unlock(password):
                    return "Invalid master password"
                # Store the password for session tracking
                self.last_used_password = password
            
            # If we created a new vault, we need to explicitly unlock it with the password
            if created_new_vault:
                print("Unlocking newly created vault...")
                self.storage.unlock(password)
                # We already stored the password above, but make sure session tracking works
                self.last_used_password = password
            
            # Prepare the secret data
            if secret is not None:
                # Use the provided secret
                if isinstance(secret, dict):
                    # Already in the right format
                    data_to_save = secret
                else:
                    # Get the raw value and ensure it's properly encoded for JSON
                    try:
                        raw_value = secret.get_raw_value()
                        
                        # TOTP secrets must be preserved in their original format
                        # They are typically base32-encoded strings, so we'll store as-is
                        if isinstance(raw_value, bytes):
                            # For bytes, we need to ensure consistent decoding
                            # TOTP secrets are typically base32 encoded
                            try:
                                # First try UTF-8 which should work for most base32 strings
                                secret_str = raw_value.decode('utf-8', errors='strict')
                            except UnicodeDecodeError:
                                # If that fails, preserve the exact bytes with base64
                                secret_str = "base64:" + base64.b64encode(raw_value).decode('ascii')
                        else:
                            # If it's already a string, keep it exactly as-is
                            secret_str = str(raw_value)
                        
                        data_to_save = {
                            'secret': secret_str,
                            'issuer': self.issuer or '',
                            'account': self.account or ''
                        }
                    except Exception as e:
                        debug_print(f"Exception while processing secret data: {e}")
                        return f"Error processing secret data: {str(e)}"
            else:
                # Use the current secret from the instance
                if self.secret is None:
                    return "No secret to save"
                
                # Get the raw value and ensure it's properly encoded for JSON
                try:
                    raw_value = self.secret.get_raw_value()
                    
                    # TOTP secrets must be preserved in their original format
                    # They are typically base32-encoded strings, so we'll store as-is
                    if isinstance(raw_value, bytes):
                        # For bytes, we need to ensure consistent decoding
                        # TOTP secrets are typically base32 encoded
                        try:
                            # First try UTF-8 which should work for most base32 strings
                            secret_str = raw_value.decode('utf-8', errors='strict')
                        except UnicodeDecodeError:
                            # If that fails, preserve the exact bytes with base64
                            secret_str = "base64:" + base64.b64encode(raw_value).decode('ascii')
                        else:
                            # If it's already a string, keep it exactly as-is
                            secret_str = str(raw_value)
                        
                        data_to_save = {
                            'secret': secret_str,
                            'issuer': self.issuer or '',
                            'account': self.account or ''
                        }
                except Exception as e:
                    debug_print(f"Exception while processing secret data: {e}")
                    return f"Error processing secret data: {str(e)}"
            
            # Save the secret to the vault - the updated save_secret returns a boolean
            success = self.storage.save_secret(name, data_to_save)
            if not success:
                debug_print(f"Failed to save secret '{name}'")
                return "Failed to save secret"
                
            debug_print(f"Successfully saved secret '{name}'")
            return None
            
        except Exception as e:
            debug_print(f"Exception in save_secret: {e}")
            return f"Error saving secret: {str(e)}"

    def load_secret(self, name, password=None):
        """
        Load a secret by name.
        
        Args:
            name: Name of the secret to load
            password: Optional password to unlock the vault if needed
        
        Returns:
            Success message or error message
        """
        try:
            # Get the path to the secret file
            secret_file_path = self.storage.get_secret_path(name)
            
            # If the file exists, verify its integrity first
            if secret_file_path and os.path.exists(secret_file_path):
                # Get a key for HMAC - derive from the storage key if available
                hmac_key = None
                if hasattr(self.storage, 'key') and self.storage.key:
                    hmac_key = hashlib.sha256(self.storage.key).digest()
                
                # Check if we have an integrity-protected backup
                backup_path = f"{secret_file_path}.backup"
                if os.path.exists(backup_path):
                    # Verify the backup's integrity
                    is_valid, content = verify_file_integrity(backup_path, hmac_key)
                    if is_valid:
                        print(f"Using integrity-verified backup for {name}")
                        
                        # Write the original content back to the main file
                        with open(secret_file_path, 'wb') as f:
                            f.write(content)
            
            # Load the secret
            try:
                secret = self.storage.load_secret(name, password)
                
                # Check if secret is a string (error message) or a dictionary (actual secret)
                if isinstance(secret, str):
                    return f"Error loading secret: {secret}"
                
                # Extract the secret data
                if isinstance(secret, dict):
                    secret_value = secret.get('secret')
                    issuer = secret.get('issuer', '')
                    account = secret.get('account', '')
                    
                    if not secret_value:
                        return "Invalid secret data: missing 'secret' field"
                        
                    # Handle specially encoded base64 values
                    if isinstance(secret_value, str) and secret_value.startswith("base64:"):
                        try:
                            # Extract and decode the base64 part
                            base64_part = secret_value[7:]  # Remove "base64:" prefix
                            secret_value = base64.b64decode(base64_part)
                            debug_print(f"Decoded base64 secret, length: {len(secret_value)}")
                        except Exception as e:
                            debug_print(f"Error decoding base64 secret: {e}")
                            # Continue with the original value if decoding fails
                    
                    # Set the extracted values
                    self.set_secret(secret_value, issuer, account)
                    return f"Secret: {name}"
                else:
                    # Handle the case where secret is not a dict or string
                    return f"Error: Unexpected secret format: {type(secret)}"
            except Exception as e:
                return f"Error listing secrets: {str(e)}"
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

    def _check_debugger(self):
        """
        Basic anti-debugging check.
        
        Detects common debugging methods without being too aggressive.
        Can be bypassed with TRUEFA_SKIP_DEBUG_CHECK=1 environment variable.
        """
        try:
            # Only run checks in release mode, not during development
            if getattr(sys, 'frozen', False):
                # Skip checks in Docker environments
                if os.path.exists('/.dockerenv') or os.environ.get('TRUEFA_IN_CONTAINER'):
                    return
                
                # Check for common debugger traces
                debug_detected = False
                
                # Check common debugger environment variables
                debug_env_vars = ['PYTHONINSPECT', 'PYTHONDEBUG', 'PYTHONTRACEMALLOC']
                for var in debug_env_vars:
                    if os.environ.get(var):
                        debug_detected = True
                        break
                        
                # Check for tracers in parent process (basic check)
                if platform.system() == 'Windows':
                    try:
                        import psutil
                        parent = psutil.Process(os.getppid())
                        if any(trace in parent.name().lower() for trace in ['debug', 'trace', 'ida']):
                            debug_detected = True
                    except:
                        pass
                
                if debug_detected:
                    # Don't exit, just log a warning - we don't want to be too aggressive
                    print("Warning: Debugging environment detected. Some security features may be limited.")
        except:
            # If anything fails, continue silently
            pass

    def _record_security_event(self, event_type, details=None):
        """
        Record a security-related event for monitoring.
        
        Args:
            event_type: Type of security event
            details: Additional details (optional)
            
        Returns:
            None
            
        Security:
        - Tracks potential security violations
        - Implements cooldown periods to prevent alert fatigue
        - Provides feedback for security monitoring
        """
        # Forward to the dedicated security event tracking module
        record_security_event(event_type, details)

    def get_all_secrets(self):
        """
        Get a list of all saved secrets with integrity verification.
        
        Returns:
            list: Names of all saved secrets
            
        Security:
        - Verifies integrity of each secret
        - Logs integrity violations
        - Includes backup verification
        """
        from ..utils.debug import debug_print
        
        try:
            # Get the list of secrets from the vault
            if not self.storage.vault.is_unlocked:
                return []
                
            # Get the list of secrets
            secrets = self.storage.list_secrets()
            
            # Verify each secret's integrity
            verified_secrets = []
            hmac_key = self.storage.vault.get_hmac_key()
            
            for secret_name in secrets:
                try:
                    # Get the path to the secret file
                    secret_path = os.path.join(self.storage.vault_dir, f"{secret_name}.json")
                    
                    # Verify the file's integrity
                    is_valid, _ = verify_file_integrity(secret_path, hmac_key)
                    
                    if not is_valid:
                        # Try to use the backup if available
                        backup_path = os.path.join(self.storage.vault_dir, f"{secret_name}.json.bak")
                        if os.path.exists(backup_path):
                            is_backup_valid, _ = verify_file_integrity(backup_path, hmac_key)
                            if is_backup_valid:
                                # Use the backup instead
                                debug_print(f"Using integrity-verified backup for {secret_name}")
                                # Restore the backup
                                shutil.copy2(backup_path, secret_path)
                                verified_secrets.append(secret_name)
                                continue
                    
                    # If we get here, either the original is valid or both are invalid
                    if is_valid:
                        verified_secrets.append(secret_name)
                    else:
                        # Record integrity violation but still include in list
                        self._record_security_event("integrity_violation", 
                                                   {"secret": secret_name})
                        debug_warning(f"Integrity check failed for {secret_name}")
                        verified_secrets.append(secret_name)
                    
                    # Also check backup integrity for monitoring purposes
                    backup_path = os.path.join(self.storage.vault_dir, f"{secret_name}.json.bak")
                    if os.path.exists(backup_path):
                        # Verify the backup's integrity
                        is_valid, _ = verify_file_integrity(backup_path, hmac_key)
                        if not is_valid:
                            # Record and log integrity violation, but still include in list
                            self._record_security_event("integrity_violation")
                            debug_warning(f"Integrity check failed for {secret_name}")
                    
                    # Add to verified list regardless of integrity status to allow user access
                    verified_secrets.append(secret_name)
                    
                except Exception as e:
                    debug_warning(f"Error checking integrity for {secret_name}: {str(e)}")
                    # Still include in list to avoid blocking user access
                    verified_secrets.append(secret_name)
            
            return verified_secrets
        except Exception as e:
            debug_print(f"Error retrieving secrets: {e}")
            return []

    def _find_storage_dirs(self):
        """
        Determine the appropriate directories for storing images and other data.
        
        Sets up:
        - Image directory for QR codes
        - Creates directories if they don't exist
        
        Security:
        - Uses OS-appropriate paths
        - Creates directories with correct permissions
        
        Returns:
            str: Path to the images directory
        """
        from ..utils.debug import debug_print
        
        try:
            # Determine the executable directory for resource paths
            if getattr(sys, 'frozen', False):
                # Running as compiled executable
                app_dir = os.path.dirname(sys.executable)
                bundle_dir = getattr(sys, '_MEIPASS', app_dir)
                debug_print(f"Running from PyInstaller bundle. App dir: {app_dir}, Bundle dir: {bundle_dir}")
                
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
                    images_dir = os.getenv('QR_IMAGES_DIR', os.path.join(app_dir, 'images'))
                except Exception:
                    # Can't write to program directory, use user's documents folder instead
                    user_dir = os.path.join(os.path.expanduser('~'), 'Documents', 'TrueFA-Py', 'images')
                    os.makedirs(user_dir, exist_ok=True)
                    images_dir = os.getenv('QR_IMAGES_DIR', user_dir)
                    debug_print(f"Using personal images directory in Documents folder: {user_dir}")
            else:
                # Running in normal Python environment
                images_dir = os.getenv('QR_IMAGES_DIR', os.path.join(os.getcwd(), 'images'))
            
            # Ensure the directory exists
            os.makedirs(images_dir, exist_ok=True)
            
            debug_print(f"Using images directory: {images_dir}")
            return images_dir
            
        except Exception as e:
            debug_print(f"Error setting up storage directories: {e}")
            # Fallback to a simple directory in the current working directory
            fallback_dir = os.path.join(os.getcwd(), 'images')
            os.makedirs(fallback_dir, exist_ok=True)
            debug_print(f"Using fallback images directory: {fallback_dir}")
            return fallback_dir

    def set_secret(self, secret, issuer=None, account=None):
        """
        Set the secret key, issuer, and account for TOTP generation.
        
        Args:
            secret (str or bytes): The secret key
            issuer (str): The service provider (e.g., 'Google')
            account (str): The user account (e.g., 'user@example.com')
            
        Returns:
            bool: True if successful, False otherwise
        """
        from ..utils.debug import debug_print
        
        try:
            # Process the secret to ensure it's in a format suitable for TOTP
            if isinstance(secret, str) and secret.startswith("base64:"):
                try:
                    # Extract and decode the base64 part
                    base64_part = secret[7:]  # Remove "base64:" prefix
                    secret = base64.b64decode(base64_part)
                    debug_print(f"Decoded base64 secret in set_secret, length: {len(secret)}")
                except Exception as e:
                    debug_print(f"Error decoding base64 secret in set_secret: {e}")
            
            # Ensure the secret is a secure string
            from ..security.secure_string import SecureString
            if not isinstance(secret, SecureString):
                secret = SecureString(secret)
                debug_print(f"Converted secret to SecureString in set_secret")
            
            # Set the secret
            self.secret = secret
            
            # Set issuer and account
            if issuer:
                self.issuer = issuer
            if account:
                self.account = account
                
            return True
        except Exception as e:
            debug_print(f"Error setting secret: {e}")
            return False

    def _is_valid_base32(self, secret_value):
        """
        Check if the string is valid base32 encoding
        
        Args:
            secret_value (str): The string to check
            
        Returns:
            bool: True if valid base32, False otherwise
        """
        try:
            # Remove any spaces
            secret_value = secret_value.replace(" ", "")
            
            # Basic pattern check (BASE32 alphabet)
            base32_pattern = re.compile(r'^[A-Z2-7]+=*$')
            if not base32_pattern.match(secret_value):
                return False
                
            # Add proper padding if missing
            if len(secret_value) % 8 != 0:
                padding = 8 - (len(secret_value) % 8)
                secret_value = secret_value + ('=' * padding)
                
            # Try to decode
            import base64
            base64.b32decode(secret_value)
            return True
        except Exception:
            return False
    
    def validate_totp_secret(self, secret):
        """
        Validate if a string is a valid TOTP secret.
        
        This method checks if the provided string is a valid TOTP secret
        by verifying it's proper base32 encoding format, which is the standard
        for TOTP secrets.
        
        Args:
            secret (str): The secret key to validate
            
        Returns:
            bool: True if the secret is valid, False otherwise
        """
        if not secret:
            return False
            
        # Remove spaces which are sometimes used for readability
        secret = secret.replace(" ", "")
        
        # Basic validation
        if len(secret) < 16:  # Most TOTP secrets are at least 16 chars
            return False
            
        # Use existing base32 validation
        return self._is_valid_base32(secret)
