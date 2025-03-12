"""
Export functionality for TrueFA secrets

This module provides export mechanisms for TrueFA secrets, including:
- Encrypted JSON exports (AES-256 encryption, compatible with other apps)
- OTPAuth URI exports (for sharing individual secrets)

These export mechanisms are designed to be secure and handle encoding issues
properly across different platforms while maintaining compatibility with
other authenticator applications.
"""

import os
import json
import platform
import base64
import datetime
from ..utils.logger import debug, info, warning, error, critical

class SecretExporter:
    """
    Handles exporting TrueFA secrets in formats compatible with other applications
    """
    
    def __init__(self, exports_path):
        """
        Initialize the exporter with the path for temporary exports
        
        Args:
            exports_path: Directory to store temporary export files
        """
        self.exports_path = exports_path
    
    def export_to_encrypted_json(self, secrets_dict, export_path, export_password):
        """
        Export secrets as an encrypted JSON file using standard format
        
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
            debug("No secrets found to export")
            return False, "No secrets to export"
            
        debug(f"Preparing to export {len(secrets_dict)} secrets to encrypted JSON")
        
        # Format the secrets for export - using standard format
        export_data = {
            "version": 1,
            "application": "TrueFA-Py",
            "created": datetime.datetime.now().isoformat(),
            "secrets": []
        }
        
        # Convert our internal format to the standard format
        for name, data in secrets_dict.items():
            debug(f"Processing secret '{name}' for export")
            
            # Create standard secret entry
            secret_entry = {
                "name": name,
                "type": "totp",
                "algorithm": "SHA1",  # Default for most TOTP
                "digits": 6,          # Standard is 6 digits
                "period": 30          # Standard is 30 seconds
            }
            
            # Add the secret key (base32 encoded)
            if isinstance(data, dict) and 'secret' in data:
                secret_entry["secret"] = data.get('secret')
            elif isinstance(data, str):
                secret_entry["secret"] = data
            else:
                # Skip invalid entries
                warning(f"Invalid secret format for '{name}', skipping")
                continue
                
            # Add optional fields if available
            if isinstance(data, dict):
                if 'issuer' in data and data['issuer']:
                    secret_entry["issuer"] = data['issuer']
                if 'account' in data and data['account']:
                    secret_entry["account"] = data['account']
                
            # Add to the secrets list
            export_data["secrets"].append(secret_entry)
            debug(f"Added secret '{name}' to export data")
            
        # Clean up the export path
        export_path = export_path.strip('"').strip("'")
        
        # Check if the export path is a directory
        if os.path.isdir(export_path):
            # If it's a directory, use a default filename in that directory
            debug(f"Export path is a directory, using default filename")
            export_path = os.path.join(export_path, "TrueFA_export.json")
        
        # Use Downloads folder for relative paths
        if not os.path.isabs(export_path):
            if platform.system() == 'Windows':
                downloads_dir = os.path.expanduser('~\\Downloads')
            else:
                downloads_dir = os.path.expanduser('~/Downloads')
            export_path = os.path.join(downloads_dir, export_path)
        
        # Ensure .json extension
        if not export_path.endswith('.json'):
            export_path += '.json'
        
        # Create export directory if it doesn't exist
        export_dir = os.path.dirname(export_path)
        os.makedirs(export_dir, exist_ok=True)
        
        # Create a JSON string of our data
        json_content = json.dumps(export_data, indent=2)
        debug(f"Created JSON content, length: {len(json_content)}")
        
        try:
            # Use standard AES encryption
            from Crypto.Cipher import AES
            from Crypto.Util.Padding import pad
            from Crypto.Random import get_random_bytes
            import hashlib
            
            # Create a key from the password using standard PBKDF2
            from Crypto.Protocol.KDF import PBKDF2
            salt = get_random_bytes(16)
            key = PBKDF2(export_password, salt, dkLen=32, count=10000)
            debug(f"Generated encryption key from password using PBKDF2")
            
            # Generate IV and create the cipher
            iv = get_random_bytes(16)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            debug(f"Created AES-CBC cipher with random IV")
            
            # Encrypt the data
            encrypted_data = cipher.encrypt(pad(json_content.encode('utf-8'), AES.block_size))
            debug(f"Encrypted JSON data, length: {len(encrypted_data)}")
            
            # Create the final encrypted file format (JSON with encryption metadata)
            result = {
                "format": "AES256",
                "mode": "CBC",
                "ivBase64": base64.b64encode(iv).decode('utf-8'),
                "saltBase64": base64.b64encode(salt).decode('utf-8'),
                "iterations": 10000,
                "contentBase64": base64.b64encode(encrypted_data).decode('utf-8')
            }
            
            # Write the encrypted data to file
            with open(export_path, 'w', encoding='utf-8') as f:
                json.dump(result, f, indent=2)
            
            info(f"Successfully exported {len(export_data['secrets'])} secrets to {export_path}")
            return True, None
            
        except Exception as e:
            # Provide detailed error information
            error_detail = str(e)
            error_type = type(e).__name__
            
            error(f"Export failed ({error_type}): {error_detail}")
            
            # Handle different error types
            if "Permission denied" in error_detail:
                return False, f"Permission denied writing to {export_path}. Try a different location."
            elif "No such file or directory" in error_detail:
                return False, f"Directory not found: {os.path.dirname(export_path)}. Try a different location."
            else:
                return False, f"Export error: {error_detail}"
    
    def export_to_otpauth_uri(self, secret_data):
        """
        Convert a secret to otpauth URI format
        
        Args:
            secret_data: The secret data including name, issuer, and secret
            
        Returns:
            str: The otpauth URI
        """
        import urllib.parse
        
        # Default to empty values if not provided
        name = secret_data.get('name', '')
        secret = secret_data.get('secret', '')
        issuer = secret_data.get('issuer', '')
        account = secret_data.get('account', '')
        
        # Create the label (issuer:account)
        label = account or name
        if issuer:
            label = f"{issuer}:{label}"
        
        # Create the URI
        uri = f"otpauth://totp/{urllib.parse.quote(label)}?secret={secret}"
        if issuer:
            uri += f"&issuer={urllib.parse.quote(issuer)}"
        
        debug(f"Created OTPAuth URI for {name}")
        return uri 