"""
Two-Factor Authentication Core Module

This module provides the core TOTP (Time-based One-Time Password) functionality
for TrueFA, including QR code scanning, secret management, and code generation.

Key Features:
- QR code scanning using pyzbar
- Secure secret storage with automatic cleanup
- TOTP code generation with PyOTP
- Signal handling for secure termination
- Path validation and sanitization
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
from pyzbar.pyzbar import decode
import urllib.parse
from ..security.secure_string import SecureString
from ..security.secure_storage import SecureStorage

class TwoFactorAuth:
    """
    Core Two-Factor Authentication implementation.
    
    This class handles all TOTP-related operations including:
    - QR code scanning and secret extraction
    - Secure storage of TOTP secrets
    - Code generation and validation
    - Automatic cleanup of sensitive data
    - Signal handling for secure termination
    
    The class uses pyzbar for QR code scanning and PyOTP for
    TOTP code generation. All secrets are protected using the
    SecureString implementation.
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
        
        Args:
            image_path: Path to the QR code image file
            
        Returns:
            tuple: (SecureString containing the secret, or None if failed,
                   Error message string or None if successful)
                   
        Security:
        - Validates and sanitizes image path
        - Cleans up image data after processing
        - Returns generic error messages for security
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
        
        Args:
            secret: The secret key to validate
            
        Returns:
            bool: True if the secret is valid base32, False otherwise
            
        Security:
        - Validates secret format before use
        - Prevents injection of invalid secrets
        """
        secret = secret.strip().upper()
        base32_pattern = r'^[A-Z2-7]+=*$'
        if not re.match(base32_pattern, secret):
            return False
        return True

    def generate_code(self):
        """
        Generate the current TOTP code.
        
        Returns:
            str: Current TOTP code or None if no secret is set
            
        Security:
        - Safely handles secret access
        - Returns None instead of raising exceptions
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
                        vault_password = input("Enter vault password (this unlocks the entire vault): ")
                        if not vault_password:
                            return False
                        master_password = input("Enter master password (this encrypts individual secrets): ")
                        if not master_password:
                            return False
                        confirm_master = input("Confirm master password: ")
                        if master_password != confirm_master:
                            print("Master passwords don't match. Try again.")
                            continue
                        self.storage.set_master_password(master_password, vault_password)
                        return True
                else:
                    print(f"\nVault is locked. Please enter your passwords to {purpose}")
                    attempts = 3
                    while attempts > 0:
                        vault_password = input("Enter vault password: ")
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
                        password = input("Enter new master password: ")
                        if not password:
                            return False
                        confirm = input("Confirm master password: ")
                        if password == confirm:
                            self.storage.set_master_password(password)
                            return True
                        print("Passwords don't match. Try again.")
                else:
                    print(f"\nStorage is locked. Please enter your master password to {purpose}")
                    attempts = 3
                    while attempts > 0:
                        password = input("Enter master password: ")
                        if self.storage.verify_master_password(password):
                            return True
                        attempts -= 1
                        if attempts > 0:
                            print(f"Incorrect password. {attempts} attempts remaining.")
                    return False
        return True