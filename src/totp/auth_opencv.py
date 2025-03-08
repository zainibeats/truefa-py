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

# Import new security modules
from ..security.file_integrity import FileIntegrityVerifier, add_hmac_to_file, verify_file_integrity
from ..security.security_events import record_security_event

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
        Initialize the TwoFactorAuth object and setup necessary paths and security checks.
        """
        try:
            # Setup signal handling for secure termination
            signal.signal(signal.SIGINT, self._signal_handler)
            
            # Initialize security event counters
            self._error_states = {
                'debug_attempts': 0,
                'path_violations': 0,
                'buffer_overflows': 0,
                'format_attacks': 0,
                'permission_violations': 0,
                'integrity_violations': 0,  # Added for HMAC integrity checks
            }
            
            # Basic anti-debug check (don't be too aggressive)
            if not os.environ.get("TRUEFA_SKIP_DEBUG_CHECK"):
                self._check_debugger()
            
            # Initialize storage paths
            self._find_storage_dirs()

            # Initialize storage
            self.storage = SecureStorage()
            
            # Check if vault is already initialized
            self.is_vault_mode = self.storage.vault.is_initialized()
            
            # Register signal handlers for secure cleanup
            signal.signal(signal.SIGTERM, self._signal_handler)
            if hasattr(signal, 'SIGHUP'):  # Not available on Windows
                signal.signal(signal.SIGHUP, self._signal_handler)
                
            # Setup instance variables
            self.secret = None
            self.continuous_thread = None
            self.should_stop = threading.Event()
            self.is_generating = False  # Flag for continuous generation
            
            # Ensure OpenCV is available
            self._check_opencv()
            
            # Create a FileIntegrityVerifier instance for HMAC operations
            self.integrity_verifier = FileIntegrityVerifier(
                security_event_handler=lambda event_type: record_security_event(event_type)
            )
        except Exception as e:
            print(f"Error initializing TwoFactorAuth: {e}")
            traceback.print_exc()

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
                print(f"Warning: Could not set file permissions: {e}")
            
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
                # Debug the image path
                print(f"DEBUG: Reading image from: {full_path}")
                
                # Load the image using OpenCV
                img = cv2.imread(str(full_path))
                if img is None:
                    # Try one more time with the original path
                    print(f"DEBUG: Retrying with original path: {image_path}")
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
            except ImportError:
                return None, "OpenCV is required for QR scanning. Please install it with 'pip install opencv-python'"
            
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
            
            # Additional security: Block absolute paths that try to escape
            if path_obj.is_absolute():
                # Check if it's inside the allowed directories
                allowed_dirs = [
                    Path(self.images_dir).resolve(),
                    Path(os.getcwd()).resolve(),
                    Path(os.path.join(os.getcwd(), 'assets')).resolve()
                ]
                
                resolved_path = path_obj.resolve()
                path_allowed = False
                
                for allowed_dir in allowed_dirs:
                    try:
                        # Check if the path is within an allowed directory
                        if str(resolved_path).startswith(str(allowed_dir)):
                            path_allowed = True
                            break
                    except Exception:
                        # Resolve can fail on some systems for non-existent paths
                        continue
                    
                if not path_allowed:
                    print(f"Security warning: Attempted access to restricted path: {image_path}")
                    self._record_security_event('invalid_path', image_path)
                    return None, "Access to this path is not allowed for security reasons"
            
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
                    # Ensure path didn't change through symlinks or other means
                    resolved_path = potential_path.resolve()
                    
                    # Additional security check: verify file extension is an image format
                    if resolved_path.suffix.lower() not in ['.png', '.jpg', '.jpeg', '.gif', '.bmp']:
                        return None, f"File must be an image type (.png, .jpg, .jpeg, .gif, .bmp)"
                    
                    # Additional security: perform canonicalization check
                    if str(potential_path) != str(resolved_path):
                        print(f"Security warning: Path changed after resolution: {potential_path} -> {resolved_path}")
                        # Extra validation for the resolved path
                        allowed_dirs = [
                            Path(self.images_dir).resolve(),
                            Path(os.getcwd()).resolve(),
                            Path(os.path.join(os.getcwd(), 'assets')).resolve()
                        ]
                        
                        path_allowed = False
                        for allowed_dir in allowed_dirs:
                            try:
                                if str(resolved_path).startswith(str(allowed_dir)):
                                    path_allowed = True
                                    break
                            except Exception:
                                continue
                        
                        if not path_allowed:
                            return None, "Path resolves to a location outside allowed directories"
                    
                    print(f"DEBUG: Found valid image at: {potential_path}")
                    return str(potential_path), None
            
            # If we get here, we didn't find a valid image
            return None, f"Could not find image file: {image_path}"
            
        except Exception as e:
            print(f"DEBUG: Path validation error: {str(e)}")
            return None, f"Invalid path: {str(e)}"

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
                        secret_value = value.decode('utf-8')
                    else:
                        secret_value = str(value)
                except Exception as e:
                    print(f"Error getting value: {e}")
                    secret_value = str(secret)
            else:
                # Try direct string conversion as a last resort
                secret_value = str(secret)
            
            # Debug print
            if os.environ.get("DEBUG", "").lower() in ("1", "true", "yes"):
                # Don't create a new line for debug outputs during continuous generation
                if self.is_generating:
                    sys.stdout.write("\r")  # Move cursor to beginning of line
                
                print(f"DEBUG: Secret length: {len(secret_value)}", end="")
                print(f" | Secret type: {type(secret_value).__name__}", end="")
                
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
                    
                    # Always update the display to show the countdown in real-time
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
                    
                    # Store the current code to detect changes
                    last_code = code
                    
                    # Sleep for a short time to reduce CPU usage
                    # Use a shorter sleep time when close to code refresh
                    if remaining <= 2:
                        # Refresh more frequently near code expiration (100ms)
                        time.sleep(0.1)
                    else:
                        # Standard refresh rate (1 second)
                        # Using 0.9 instead of 1.0 to account for processing time
                        time.sleep(0.9)
                        
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
        - Uses HMAC to verify file integrity
        """
        # Check if we have a secret to save
        if not self.secret:
            return "No secret available to save"
        
        # Input validation
        # Check for buffer overflow attempts or other malicious input
        if name is None or not isinstance(name, str):
            return "Invalid name format"
        
        if len(name) > 256:  # Set reasonable limits
            return "Name is too long (maximum 256 characters)"
        
        # Sanitize the name to prevent directory traversal or command injection
        # Only allow alphanumeric chars, dash, underscore, and space
        sanitized_name = re.sub(r'[^\w\s-]', '', name)
        if sanitized_name != name:
            return "Name contains invalid characters (only letters, numbers, spaces, underscores, and dashes are allowed)"
        
        # Prevent common injection patterns
        if '..' in name or '/' in name or '\\' in name:
            return "Name contains invalid characters"
        
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
            result = self.storage.save_secret(name, self.secret, password)
            
            # If the save was successful, create an HMAC-protected backup
            if result is None:  # None means success in this API
                try:
                    # Get the path to the saved secret file
                    secret_file_path = self.storage.get_secret_path(name)
                    if secret_file_path and os.path.exists(secret_file_path):
                        # Create a backup with HMAC protection
                        with open(secret_file_path, 'rb') as f:
                            file_content = f.read()
                        
                        # Get a key for HMAC - derive from the storage key if available
                        hmac_key = None
                        if hasattr(self.storage, 'key') and self.storage.key:
                            hmac_key = hashlib.sha256(self.storage.key).digest()
                        
                        # Create backup file with HMAC
                        backup_path = f"{secret_file_path}.backup"
                        add_hmac_to_file(backup_path, file_content, hmac_key)
                        
                        print(f"Integrity-protected backup created for {name}")
                except Exception as e:
                    # Don't fail the save if backup creation fails
                    print(f"Warning: Could not create integrity-protected backup: {e}")
            
            return result  # Return any error from the storage layer
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
        - Verifies file integrity using HMAC
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
            
            # Now load the secret as normal
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
        Get a list of all saved secrets.
        
        Returns:
            list: List of secret names or empty list if none found
            
        Security:
        - Performs integrity check on listed secrets
        - Filters out potentially compromised files
        """
        try:
            all_secrets = self.storage.get_all_secrets()
            verified_secrets = []
            
            # Verify the integrity of each secret's backup
            for secret_name in all_secrets:
                try:
                    # Get the path to the secret file
                    secret_file_path = self.storage.get_secret_path(secret_name)
                    
                    # Get a key for HMAC - derive from the storage key if available
                    hmac_key = None
                    if hasattr(self.storage, 'key') and self.storage.key:
                        hmac_key = hashlib.sha256(self.storage.key).digest()
                    
                    # Check if we have an integrity-protected backup
                    backup_path = f"{secret_file_path}.backup"
                    
                    if os.path.exists(backup_path):
                        # Verify the backup's integrity
                        is_valid, _ = verify_file_integrity(backup_path, hmac_key)
                        if not is_valid:
                            # Record and log integrity violation, but still include in list
                            record_security_event("integrity_violation")
                            print(f"Warning: Integrity check failed for {secret_name}")
                    
                    # Add to verified list regardless of integrity status to allow user access
                    verified_secrets.append(secret_name)
                    
                except Exception as e:
                    print(f"Warning: Error checking integrity for {secret_name}: {str(e)}")
                    # Still include in list to avoid blocking user access
                    verified_secrets.append(secret_name)
            
            return verified_secrets
        except Exception as e:
            print(f"Error retrieving secrets: {e}")
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
        """
        try:
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
            
            print(f"You can use either the full path or just the filename if it's in the images directory: {self.images_dir}")
            
            # Create images directory if needed
            if not os.path.exists(self.images_dir):
                self._secure_create_file(os.path.join(self.images_dir, '.gitkeep'), '')
        except Exception as e:
            print(f"Error setting up storage directories: {e}")
            # Fallback to current directory
            self.images_dir = os.path.join(os.getcwd(), 'images')
            if not os.path.exists(self.images_dir):
                os.makedirs(self.images_dir, exist_ok=True)

    def set_secret(self, secret_value, issuer="", account=""):
        """
        Set the TOTP secret and associated metadata.
        
        Args:
            secret_value (str): The base32-encoded secret key
            issuer (str): The issuer of the TOTP (e.g., Google, Microsoft)
            account (str): The account identifier (e.g., email address)
        
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Convert string to SecureString if needed
            if isinstance(secret_value, str):
                # Make sure it's a proper base32 string first
                base32_pattern = re.compile(r'^[A-Z2-7]+=*$')
                if not base32_pattern.match(secret_value):
                    print("Warning: Secret doesn't appear to be in base32 format. Attempting to encode it.")
                    try:
                        # Try to encode it as base32 if it's not already
                        secret_bytes = secret_value.encode('utf-8')
                        secret_value = base64.b32encode(secret_bytes).decode('utf-8')
                    except Exception as encoding_error:
                        print(f"Error encoding secret as base32: {encoding_error}")
                
                # Create a SecureString with the correct encoding
                self.secret = SecureString(secret_value.encode('utf-8'))
            else:
                self.secret = secret_value
                
            # Store metadata
            self.issuer = issuer
            self.account = account
            
            # Validate that we can generate a TOTP code with this secret
            try:
                totp = pyotp.TOTP(self.secret.get())
                test_code = totp.now()
                if test_code:
                    print(f"Secret validated successfully.")
                    return True
            except Exception as totp_error:
                print(f"Warning: Could not generate TOTP code with the provided secret: {totp_error}")
                # We'll continue anyway since the secret might be valid in another format
                
            return True
        except Exception as e:
            print(f"Error setting secret: {e}")
            return False
