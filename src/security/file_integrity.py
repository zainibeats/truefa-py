"""
File Integrity Module

This module provides functionality for ensuring the integrity of files
through HMAC-based verification. It helps detect tampering with saved data
and provides mechanisms to handle integrity violations.

Key Features:
- HMAC-based file verification
- Secure handling of compromised files
- Integrity violation detection and reporting
"""

import os
import hmac
import hashlib
from datetime import datetime
import logging

# Configure logging
logger = logging.getLogger(__name__)

class FileIntegrityVerifier:
    """
    Handles file integrity verification using HMAC signatures.
    """
    
    def __init__(self, security_event_handler=None):
        """
        Initialize the verifier.
        
        Args:
            security_event_handler: Callback for security events (optional)
        """
        self.security_event_handler = security_event_handler
        
    def add_hmac_to_file(self, filepath, data, key=None):
        """
        Add an HMAC signature to a file for integrity verification.
        
        Args:
            filepath: Path to save the file with HMAC
            data: The data to protect (bytes)
            key: Secret key for HMAC generation (bytes, optional)
            
        Returns:
            bool: True if successful, False otherwise
            
        Security:
        - Allows detection of file tampering
        - Uses SHA-256 for strong integrity protection
        """
        try:
            # Use a default key if none is provided
            hmac_key = key if key else b'TrueFA-Py_static_hmac_key'
            
            # Calculate HMAC for the data
            h = hmac.new(hmac_key, data, hashlib.sha256)
            signature = h.digest()
            
            # Write the data followed by the HMAC
            with open(filepath, 'wb') as f:
                f.write(data)
                f.write(signature)
                
            logger.debug(f"Added HMAC signature to {filepath}")
            return True
            
        except Exception as e:
            logger.error(f"Error adding HMAC to file {filepath}: {str(e)}")
            return False
    
    def verify_file_integrity(self, filepath, key=None):
        """
        Verify the integrity of a file using HMAC.
        
        Args:
            filepath: Path to the file to verify
            key: Key to use for HMAC verification (optional)
            
        Returns:
            tuple: (is_valid, content), where:
                - is_valid: Boolean indicating if file integrity was verified
                - content: The file content without the HMAC if is_valid is True, None otherwise
                
        Security:
        - Returns False if file doesn't exist or is tampered with
        - Uses a default key if none is provided
        - Handles corrupted files gracefully
        """
        try:
            if not os.path.exists(filepath):
                logger.warning(f"File does not exist: {filepath}")
                return False, None
                
            # Use a default key if none is provided
            hmac_key = key if key else b'TrueFA-Py_static_hmac_key'
            
            with open(filepath, 'rb') as f:
                file_content = f.read()
                
            # HMAC size is 32 bytes for SHA-256
            if len(file_content) < 32:
                logger.warning(f"File too small to contain HMAC: {filepath}")
                if self.security_event_handler:
                    self.security_event_handler("integrity_violation")
                return False, None
                
            # Extract the stored HMAC (last 32 bytes)
            content = file_content[:-32]
            stored_hmac = file_content[-32:]
            
            # Calculate the expected HMAC
            h = hmac.new(hmac_key, content, hashlib.sha256)
            calculated_hmac = h.digest()
            
            # Check if HMACs match
            if hmac.compare_digest(calculated_hmac, stored_hmac):
                return True, content
            else:
                logger.warning(f"HMAC verification failed for {filepath}")
                if self.security_event_handler:
                    self.security_event_handler("integrity_violation")
                self.handle_integrity_violation(filepath, content)
                return False, None
                
        except Exception as e:
            logger.error(f"Error verifying file integrity: {str(e)}")
            return False, None

    def handle_integrity_violation(self, filepath, content):
        """
        Handle a detected file integrity violation.
        
        Args:
            filepath: Path to the compromised file
            content: Content of the file (without HMAC)
            
        Security:
        - Creates a backup of the compromised file for forensic analysis
        - Logs the security event
        - Does not remove the compromised file
        """
        try:
            # Create a forensic backup with timestamp
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = f"{filepath}.compromised_{timestamp}"
            
            # Save the content part without the invalid HMAC
            if content and len(content) > 0:
                with open(backup_path, 'wb') as f:
                    f.write(content)
                    
            logger.warning(f"Security alert: Integrity violation detected for {filepath}")
            logger.info(f"Forensic backup created at {backup_path}")
            print(f"Security alert: Integrity violation detected for {filepath}")
            print(f"Forensic backup created at {backup_path}")
            
        except Exception as e:
            logger.error(f"Error handling integrity violation: {str(e)}")
            print(f"Error handling integrity violation: {str(e)}")

# Convenience functions for direct use without creating an instance
def add_hmac_to_file(filepath, data, key=None):
    """Convenience function for adding HMAC to a file"""
    verifier = FileIntegrityVerifier()
    return verifier.add_hmac_to_file(filepath, data, key)

def verify_file_integrity(filepath, key=None):
    """Convenience function for verifying file integrity"""
    verifier = FileIntegrityVerifier()
    return verifier.verify_file_integrity(filepath, key) 