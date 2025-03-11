"""
Export functionality for TrueFA secrets

This module provides various export mechanisms for TrueFA secrets, including:
- Password-protected AES-256 encryption
- Future: Support for other export formats

These export mechanisms are designed to be secure and handle encoding issues
properly across different platforms.
"""

import os
import json
import platform
import base64
from ..utils.logger import debug, error, info

class SecretExporter:
    """
    Handles exporting TrueFA secrets in various formats
    """
    
    def __init__(self, exports_path):
        """
        Initialize the exporter with the path for temporary exports
        
        Args:
            exports_path: Directory to store temporary export files
        """
        self.exports_path = exports_path
    
    def export_to_gpg(self, secrets_dict, export_path, export_password):
        """
        Export secrets as an encrypted file using password-based encryption
        
        Args:
            secrets_dict: Dictionary of secrets to export
            export_path: Path to save the exported file
            export_password: Password to encrypt the export
            
        Returns:
            tuple: (success, error_message)
        """
        if not export_path:
            return False, "No export path provided"
        
        # Check if we have any secrets to export
        if not secrets_dict or len(secrets_dict) == 0:
            return False, "No secrets to export"
            
        debug(f"Preparing to export {len(secrets_dict)} secrets")
        
        # Format the secrets for export - handle any special types that might not serialize well
        export_data = {}
        for name, data in secrets_dict.items():
            # Ensure all values are serializable
            debug(f"Processing secret '{name}' for export")
            debug(f"Original data type: {type(data)}")
            if isinstance(data, dict):
                debug(f"Dictionary keys: {list(data.keys())}")
            
            export_data[name] = self._ensure_serializable(data)
            debug(f"Processed data ready for export")
            
        # Clean up the export path
        export_path = export_path.strip('"').strip("'")
        
        # Use Downloads folder for relative paths
        if not os.path.isabs(export_path):
            if platform.system() == 'Windows':
                downloads_dir = os.path.expanduser('~\\Downloads')
            else:
                downloads_dir = os.path.expanduser('~/Downloads')
            export_path = os.path.join(downloads_dir, export_path)
        
        # Ensure .enc extension instead of .gpg
        if export_path.endswith('.gpg'):
            export_path = export_path[:-4] + '.enc'
        elif not export_path.endswith('.enc'):
            export_path += '.enc'
        
        # Create export directory if it doesn't exist
        export_dir = os.path.dirname(export_path)
        os.makedirs(export_dir, exist_ok=True)
        
        # Create a direct string representation of our data
        json_content = json.dumps(export_data, indent=4)
        debug(f"Created JSON content, length: {len(json_content)}")
        
        try:
            # Use our own encryption instead of relying on external tools
            from Crypto.Cipher import AES
            from Crypto.Util.Padding import pad
            from Crypto.Random import get_random_bytes
            import hashlib
            
            # Create a key from the password
            key = hashlib.sha256(export_password.encode()).digest()
            debug(f"Generated encryption key from password")
            
            # Generate IV and create the cipher
            iv = get_random_bytes(16)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            debug(f"Created AES cipher with random IV")
            
            # Encrypt the data
            encrypted_data = cipher.encrypt(pad(json_content.encode('utf-8'), AES.block_size))
            debug(f"Encrypted data, length: {len(encrypted_data)}")
            
            # Write the file with IV and encrypted data
            with open(export_path, 'wb') as f:
                # Format: 8-byte signature, 16-byte IV, then encrypted data
                f.write(b"TRUEFA01")  # 8-byte signature/version
                f.write(iv)           # 16-byte IV
                f.write(encrypted_data)
            
            debug(f"Successfully exported secrets to {export_path}")
            return True, None
            
        except Exception as e:
            # Provide detailed error information
            error_detail = str(e)
            error_type = type(e).__name__
            
            debug(f"Export failed ({error_type}): {error_detail}")
            
            # Handle different error types
            if "Permission denied" in error_detail:
                return False, f"Permission denied writing to {export_path}. Try a different location."
            elif "No such file or directory" in error_detail:
                return False, f"Directory not found: {os.path.dirname(export_path)}. Try a different location."
            else:
                return False, f"Export error: {error_detail}"
    
    def _ensure_serializable(self, data):
        """
        Ensure all values in the data dictionary are JSON serializable
        
        Args:
            data: The data dictionary to check
            
        Returns:
            dict: A dictionary with all values serializable
        """
        if not isinstance(data, dict):
            # If it's not a dictionary, convert it to one
            return {"secret": str(data)}
            
        result = {}
        for key, value in data.items():
            if isinstance(value, dict):
                # Recursively process nested dictionaries
                result[key] = self._ensure_serializable(value)
            elif isinstance(value, bytes):
                # Convert bytes to base64
                result[key] = base64.b64encode(value).decode('utf-8')
            elif isinstance(value, (int, float, bool, str, type(None))):
                # These types are already serializable
                result[key] = value
            else:
                # Convert anything else to string
                result[key] = str(value)
                
        return result 