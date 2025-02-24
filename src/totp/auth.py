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
    """Main application class for 2FA code generation"""
    
    def __init__(self):
        self.secret = None
        self.images_dir = os.getenv('QR_IMAGES_DIR', os.path.join(os.getcwd(), 'images'))
        self.is_generating = False
        self.storage = SecureStorage()  # Add storage instance
        # Register signal handlers for secure cleanup
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

    def _signal_handler(self, signum, frame):
        """Handle program termination securely"""
        if self.is_generating:
            self.is_generating = False
            return
        self.cleanup()
        print("\nExiting securely...")
        sys.exit(0)

    def cleanup(self):
        """Secure cleanup of sensitive data"""
        if self.secret:
            self.secret.clear()
            self.secret = None

    def extract_secret_from_qr(self, image_path):
        """Extract secret key from QR code image"""
        try:
            # Clean up and validate the image path
            image_path = self._validate_image_path(image_path)
            if not image_path:
                return None, "Invalid image path or file not found"
            
            # Read image using PIL
            try:
                image = Image.open(str(image_path))
            except Exception:
                return None, f"Could not read the image file: {image_path}"
            
            # Decode QR code using pyzbar
            decoded_objects = decode(image)
            
            # Clear the image data from memory
            image.close()
            image = None
            
            if not decoded_objects:
                return None, "No QR code found in the image"
            
            # Find valid otpauth URL in decoded QR codes
            for decoded_obj in decoded_objects:
                qr_data = decoded_obj.data.decode('utf-8')
                if str(qr_data).startswith('otpauth://'):
                    # Parse URL for secret
                    parsed = urllib.parse.urlparse(qr_data)
                    params = dict(urllib.parse.parse_qsl(parsed.query))
                    
                    if 'secret' in params:
                        # Wrap the secret in SecureString
                        return SecureString(params['secret']), None
            
            return None, "No valid otpauth URL found in QR codes"
            
        except Exception as e:
            return None, "Error processing image"  # Generic error message for security

    def _validate_image_path(self, image_path):
        """Validate and resolve the image path securely"""
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
            
            # Check if the path is within the allowed directory
            if not str(resolved_path).startswith(str(images_dir_resolved)):
                print("Warning: Access to files outside the images directory is not allowed")
                return None
            
            # Check if file exists and is a file
            if not resolved_path.is_file():
                return None
                
            return resolved_path
            
        except Exception:
            return None

    def validate_secret(self, secret):
        """Validate base32 encoded secret key format"""
        # Validate base32 encoded secret key format
        secret = secret.strip().upper()
        base32_pattern = r'^[A-Z2-7]+=*$'
        if not re.match(base32_pattern, secret):
            return False
        return True

    def generate_code(self):
        """Generate current TOTP code"""
        # Generate current TOTP code
        if not self.secret:
            return None
        secret = self.secret.get()
        if not secret:
            return None
        totp = pyotp.TOTP(secret)
        return totp.now()

    def get_remaining_time(self):
        """Get seconds until next code rotation"""
        # Get seconds until next code rotation
        return 30 - (int(time.time()) % 30)

    def ensure_unlocked(self, purpose="continue"):
        """Ensure storage is unlocked with master password"""
        if not self.storage.is_unlocked:
            if not self.storage.has_master_password():
                print("\nYou need to set up a master password to", purpose)
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
                print("\nStorage is locked. Please enter your master password to", purpose)
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