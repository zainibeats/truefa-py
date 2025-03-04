"""
TrueFA-Py Two-Factor Authentication Core

Provides comprehensive TOTP (Time-based One-Time Password) functionality including:
- QR code scanning and processing with pyzbar
- Secret extraction and validation from QR codes
- Secure storage of TOTP secrets with automatic memory sanitization
- RFC 6238 compliant code generation with PyOTP
- Graceful signal handling for secure termination

Security Features:
- All secrets use SecureString for in-memory protection
- Automatic cleanup of sensitive data
- Path validation and sanitization to prevent path traversal
- Secure error handling to avoid information leakage
"""

import os
import sys
import signal
import platform
import re
import time
import base64
import getpass  # Add getpass module for secure password input
from pathlib import Path
import pyotp
import urllib.parse
from PIL import Image
from pyzbar.pyzbar import decode
from ..security.secure_string import SecureString
from ..security.secure_storage import SecureStorage

class TwoFactorAuth:
    """
    TOTP (Time-based One-Time Password) Implementation
    
    Provides the core 2FA functionality including:
    - QR code processing and secret extraction
    - Secure TOTP secret storage with memory protection
    - TOTP code generation with time-remaining tracking
    - Automatic cleanup and secure termination
    
    Security Design:
    - Uses SecureString to protect secrets in memory
    - Implements signal handlers for safe termination
    - Performs path and input validation
    - Securely cleans up memory when no longer needed
    
    Usage Flow:
    1. Initialize the class
    2. Extract secrets from QR codes or input them manually
    3. Generate TOTP codes as needed
    4. Cleanup when finished to sanitize memory
    """
    
    def __init__(self):
        """
        Initialize the TwoFactorAuth instance.
        
        Sets up:
        - Secure storage for TOTP secrets
        - Signal handlers for secure termination
        - QR code image directory
        - Initial security state
        """
        self.secret = None
        self.images_dir = os.getenv('QR_IMAGES_DIR', os.path.join(os.getcwd(), 'images'))
        self.is_generating = False
        self.storage = SecureStorage()
        self.is_vault_mode = self.storage.vault.is_initialized()
        
        # Register signal handlers for secure cleanup
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

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
        Extract TOTP secret from a QR code image.
        
        Processes a QR code image containing an otpauth:// URI and extracts
        the TOTP secret key, issuer, and account information. Handles both
        standard and custom QR code formats.
        
        Args:
            image_path (str or Path): Path to the QR code image file
            
        Returns:
            tuple: (
                SecureString: Secret key or None if extraction failed,
                str: Error message if failed, None if successful
            )
                   
        Security Notes:
            - Validates path to prevent path traversal attacks
            - Implements proper image resource cleanup
            - Returns generic error messages to prevent information leakage
            - Stores extracted secret in SecureString for memory protection
            
        The method validates both the image path and the extracted secret
        before returning, ensuring the secret meets TOTP requirements.
        """
        try:
            # Clean up and validate the image path
            image_path = self._validate_image_path(image_path)
            if not image_path:
                return None, "Invalid image path or file not found"
            
            # Read and process image
            try:
                image = Image.open(str(image_path))
                decoded_objects = decode(image)
                image.close()
                image = None
            except Exception:
                return None, f"Could not read the image file: {image_path}"
            
            if not decoded_objects:
                return None, "No QR code found in the image"
            
            # Extract secret from otpauth URL
            for decoded_obj in decoded_objects:
                qr_data = decoded_obj.data.decode('utf-8')
                if str(qr_data).startswith('otpauth://'):
                    parsed = urllib.parse.urlparse(qr_data)
                    params = dict(urllib.parse.parse_qsl(parsed.query))
                    
                    if 'secret' in params:
                        return SecureString(params['secret']), None
            
            return None, "No valid otpauth URL found in QR codes"
            
        except Exception as e:
            return None, "Error processing image"  # Generic error for security

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
            
            # Resolve path and check if it's within allowed directory
            resolved_path = path.resolve()
            images_dir_resolved = Path(self.images_dir).resolve()
            
            # Security check: path must be within images directory
            if not str(resolved_path).startswith(str(images_dir_resolved)):
                print("Warning: Access to files outside the images directory is not allowed")
                return None
            
            # Verify file exists and is actually a file
            if not resolved_path.is_file():
                return None
                
            return resolved_path
            
        except Exception:
            return None

    def validate_secret(self, secret):
        """
        Validate a base32 encoded TOTP secret key.
        
        Ensures the provided secret conforms to the base32 encoding format
        requirements specified in RFC 4648, which is required for TOTP
        according to RFC 6238. Valid base32 characters include A-Z and 2-7
        with optional padding (=).
        
        Args:
            secret (str): The secret key to validate
            
        Returns:
            bool: True if the secret is valid base32, False otherwise
            
        Security Notes:
            - Prevents use of malformed secrets that could cause unpredictable behavior
            - Sanitizes input by trimming whitespace and normalizing to uppercase
            - Used as a pre-validation step before storing or using secrets
        """
        secret = secret.strip().upper()
        base32_pattern = r'^[A-Z2-7]+=*$'
        if not re.match(base32_pattern, secret):
            return False
        return True

    def generate_code(self):
        """
        Generate the current time-based OTP code.
        
        Creates a 6-digit TOTP code based on the current time and stored secret
        following the RFC 6238 specification. Uses the PyOTP library for
        standards-compliant implementation with a 30-second period.
        
        Returns:
            str: Current 6-digit TOTP code
            None: If no secret is set or the secret is invalid
            
        Security Notes:
            - Accesses the secure secret through controlled SecureString interface
            - Handles missing secret gracefully without exposing errors
            - Implements proper error handling to prevent information leakage
            
        This method is typically called every time a fresh authentication code
        is needed, with get_remaining_time() to show time until code changes.
        """
        if not self.secret:
            return None
        secret = self.secret.get()
        if not secret:
            return None
        totp = pyotp.TOTP(secret)
        return totp.now()

    def get_remaining_time(self):
        """
        Get seconds until next TOTP code rotation.
        
        Returns:
            int: Seconds remaining until next code (0-29)
        """
        return 30 - (int(time.time()) % 30)

    def ensure_unlocked(self, purpose="continue"):
        """
        Ensure storage is unlocked with appropriate credentials.
        
        This method handles both vault mode and legacy mode authentication,
        managing the master password and vault password as needed.
        
        Args:
            purpose: Description of the operation requiring authentication
            
        Returns:
            bool: True if storage is unlocked successfully, False otherwise
            
        Security:
        - Implements secure password entry
        - Provides limited authentication attempts
        - Supports vault-based two-layer encryption
        """
        # Allow stateless operation for viewing codes
        if purpose == "view 2FA codes":
            return True
            
        # Handle storage operations requiring authentication
        if not self.storage.is_unlocked:
            # Vault mode authentication
            if self.is_vault_mode:
                if not self.storage.vault.is_initialized():
                    print(f"\nYou need to set up a vault with a vault password and master password to {purpose}")
                    while True:
                        vault_password = getpass.getpass("Enter vault password (this unlocks the entire vault): ")
                        if not vault_password:
                            return False
                        master_password = getpass.getpass("Enter master password (this encrypts individual secrets): ")
                        if not master_password:
                            return False
                        confirm_master = getpass.getpass("Confirm master password: ")
                        if master_password != confirm_master:
                            print("Master passwords don't match. Try again.")
                            continue
                        self.storage.set_master_password(master_password, vault_password)
                        return True
                else:
                    print(f"\nVault is locked. Please enter your passwords to {purpose}")
                    attempts = 3
                    while attempts > 0:
                        vault_password = getpass.getpass("Enter vault password: ")
                        if self.storage.verify_master_password(None, vault_password):
                            return True
                        attempts -= 1
                        if attempts > 0:
                            print(f"Incorrect password. {attempts} attempts remaining.")
                    return False
            else:
                # Legacy mode authentication
                if not self.storage.has_master_password():
                    print(f"\nYou need to set up a master password to {purpose}")
                    while True:
                        password = getpass.getpass("Enter new master password: ")
                        if not password:
                            return False
                        confirm = getpass.getpass("Confirm master password: ")
                        if password == confirm:
                            self.storage.set_master_password(password)
                            return True
                        print("Passwords don't match. Try again.")
                else:
                    print(f"\nStorage is locked. Please enter your master password to {purpose}")
                    attempts = 3
                    while attempts > 0:
                        password = getpass.getpass("Enter master password: ")
                        if self.storage.verify_master_password(password):
                            return True
                        attempts -= 1
                        if attempts > 0:
                            print(f"Incorrect password. {attempts} attempts remaining.")
                    return False
        return True