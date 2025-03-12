"""
Import functionality for TrueFA secrets

This module provides import mechanisms for TrueFA secrets from:
- Encrypted JSON exports (AES-256 encryption, compatible with other apps)
- OTPAuth URI imports (for adding individual secrets)

These import mechanisms are designed to be secure and compatible with
exports from other authenticator applications.
"""

import os
import json
import base64
from ..utils.logger import debug, info, warning, error, critical

class SecretImporter:
    """
    Handles importing TrueFA secrets from various formats
    """
    
    def import_from_file(self, import_path, import_password):
        """
        Import secrets from an encrypted file
        
        Args:
            import_path: Path to the encrypted file to import
            import_password: Password to decrypt the file
            
        Returns:
            tuple: (secrets_dict, error_message)
                - secrets_dict: Dictionary of secrets or None if failed
                - error_message: Error message if failed, None if successful
        """
        if not import_path or not os.path.exists(import_path):
            error(f"Import file not found: {import_path}")
            return None, f"File not found: {import_path}"
            
        debug(f"Attempting to import from: {import_path}")
        
        try:
            # Read the file
            with open(import_path, 'rb') as f:
                file_data = f.read()
                
            # Try to detect the format
            detected_format = self._detect_format(file_data)
            debug(f"Detected format: {detected_format}")
            
            if detected_format == "standard_json":
                return self._import_from_encrypted_json(file_data, import_password)
            elif detected_format == "plaintext_json":
                return self._import_from_plaintext_json(file_data)
            elif detected_format == "otpauth_uri":
                return self._import_from_otpauth_uri(file_data.decode('utf-8', errors='replace'))
            else:
                error(f"Unsupported or unknown format: {detected_format}")
                return None, f"Unsupported format: {detected_format}"
                
        except Exception as e:
            error_detail = str(e)
            error_type = type(e).__name__
            
            error(f"Import failed ({error_type}): {error_detail}")
            return None, f"Import error: {error_detail}"
    
    def _detect_format(self, data):
        """
        Detect the format of the import data
        
        Args:
            data: Raw bytes from the import file
            
        Returns:
            str: The detected format
        """
        # Check if it's a text file
        is_text = True
        try:
            text_data = data.decode('utf-8')
        except UnicodeDecodeError:
            is_text = False
        
        if is_text:
            # Check if it's JSON format
            try:
                json_data = json.loads(text_data)
                
                # Check for our standard encrypted JSON format
                if all(k in json_data for k in ("format", "mode", "ivBase64", "saltBase64", "contentBase64")):
                    return "standard_json"
                
                # Check for plaintext JSON format with secrets array
                if "secrets" in json_data and isinstance(json_data["secrets"], list):
                    return "plaintext_json"
                
                # Check for otpauth URI
                if text_data.startswith("otpauth://"):
                    return "otpauth_uri"
                    
            except json.JSONDecodeError:
                # Not JSON, check for otpauth URI
                if text_data.startswith("otpauth://"):
                    return "otpauth_uri"
        
        # If we reached here, the format is unknown
        return "unknown"
    
    def _import_from_encrypted_json(self, data, password):
        """
        Import secrets from encrypted JSON format
        
        Args:
            data: Raw bytes from the import file
            password: Password for decryption
            
        Returns:
            tuple: (secrets_dict, error_message)
        """
        try:
            # Parse the JSON structure
            json_data = json.loads(data.decode('utf-8'))
            
            # Verify the format
            if not all(k in json_data for k in ("format", "mode", "ivBase64", "saltBase64", "contentBase64")):
                return None, "Invalid encrypted JSON format"
                
            # Get the encryption parameters
            encryption_format = json_data.get("format")
            encryption_mode = json_data.get("mode")
            iv = base64.b64decode(json_data.get("ivBase64"))
            salt = base64.b64decode(json_data.get("saltBase64"))
            iterations = int(json_data.get("iterations", 10000))
            encrypted_content = base64.b64decode(json_data.get("contentBase64"))
            
            debug(f"Decrypting content with {encryption_format} in {encryption_mode} mode")
            
            # Decrypt the content
            from Crypto.Cipher import AES
            from Crypto.Util.Padding import unpad
            from Crypto.Protocol.KDF import PBKDF2
            
            # Derive the key from password
            key = PBKDF2(password, salt, dkLen=32, count=iterations)
            
            # Create cipher and decrypt
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted_data = unpad(cipher.decrypt(encrypted_content), AES.block_size)
            
            # Parse the decrypted JSON
            decrypted_json = json.loads(decrypted_data.decode('utf-8'))
            debug(f"Successfully decrypted JSON content")
            
            # Extract the secrets
            if not "secrets" in decrypted_json or not isinstance(decrypted_json["secrets"], list):
                warning("Decrypted content does not contain expected 'secrets' array")
                return None, "Invalid content format: missing secrets array"
                
            # Convert to our internal format
            secrets_dict = {}
            for idx, secret in enumerate(decrypted_json["secrets"]):
                # Validate required fields
                if not "name" in secret or not "secret" in secret:
                    warning(f"Skipping secret at index {idx}: missing required fields")
                    continue
                    
                name = secret.get("name")
                secret_value = secret.get("secret")
                
                # Create the secret data
                secret_data = {
                    "secret": secret_value,
                    "issuer": secret.get("issuer", ""),
                    "account": secret.get("account", name)
                }
                
                # Add to dictionary with name as key
                secrets_dict[name] = secret_data
            
            info(f"Successfully imported {len(secrets_dict)} secrets")
            return secrets_dict, None
                
        except Exception as e:
            error_detail = str(e)
            error_type = type(e).__name__
            
            if "Mac check failed" in error_detail or "Incorrect padding" in error_detail:
                error(f"Decryption failed, likely incorrect password")
                return None, "Incorrect password or corrupted file"
            
            error(f"Failed to import encrypted JSON ({error_type}): {error_detail}")
            return None, f"Import error: {error_detail}"
    
    def _import_from_plaintext_json(self, data):
        """
        Import secrets from plaintext JSON format
        
        Args:
            data: Raw bytes from the import file
            
        Returns:
            tuple: (secrets_dict, error_message)
        """
        try:
            # Parse the JSON
            json_data = json.loads(data.decode('utf-8'))
            
            # Verify format
            if not "secrets" in json_data or not isinstance(json_data["secrets"], list):
                warning("JSON content does not contain expected 'secrets' array")
                return None, "Invalid content format: missing secrets array"
            
            # Convert to our internal format
            secrets_dict = {}
            for idx, secret in enumerate(json_data["secrets"]):
                # Validate required fields
                if not "name" in secret or not "secret" in secret:
                    warning(f"Skipping secret at index {idx}: missing required fields")
                    continue
                    
                name = secret.get("name")
                secret_value = secret.get("secret")
                
                # Create the secret data
                secret_data = {
                    "secret": secret_value,
                    "issuer": secret.get("issuer", ""),
                    "account": secret.get("account", name)
                }
                
                # Add to dictionary with name as key
                secrets_dict[name] = secret_data
            
            info(f"Successfully imported {len(secrets_dict)} secrets from plaintext JSON")
            if len(secrets_dict) > 0:
                warning("Imported from plaintext JSON - this format is insecure for storage")
                
            return secrets_dict, None
            
        except Exception as e:
            error_detail = str(e)
            error_type = type(e).__name__
            
            error(f"Failed to import plaintext JSON ({error_type}): {error_detail}")
            return None, f"Import error: {error_detail}"
    
    def _import_from_otpauth_uri(self, uri):
        """
        Import a secret from an otpauth URI
        
        Args:
            uri: The otpauth URI string
            
        Returns:
            tuple: (secrets_dict, error_message)
        """
        try:
            import urllib.parse
            
            # Basic validation
            if not uri.startswith("otpauth://totp/"):
                warning(f"Invalid otpauth URI format: {uri}")
                return None, "Invalid otpauth URI format"
            
            # Parse the URI
            uri_parts = uri.split('?', 1)
            if len(uri_parts) != 2:
                return None, "Invalid otpauth URI format: missing parameters"
                
            # Get the label (path part)
            label = uri_parts[0].replace("otpauth://totp/", "")
            label = urllib.parse.unquote(label)
            
            # Parse the parameters
            params = dict(urllib.parse.parse_qsl(uri_parts[1]))
            
            # Get the secret value
            if "secret" not in params:
                return None, "Invalid otpauth URI: missing secret parameter"
                
            secret_value = params.get("secret")
            
            # Try to extract issuer and account
            issuer = params.get("issuer", "")
            account = label
            
            # If the label includes an issuer prefix (issuer:account), extract it
            if ":" in label and not issuer:
                issuer, account = label.split(":", 1)
            
            # Create a unique name based on issuer and account
            name = account
            if issuer:
                name = f"{issuer}_{account}"
            
            # Create the secret data
            secret_data = {
                "secret": secret_value,
                "issuer": issuer,
                "account": account
            }
            
            # Return as a dictionary with name as key
            secrets_dict = {name: secret_data}
            
            info(f"Successfully imported secret from otpauth URI")
            return secrets_dict, None
            
        except Exception as e:
            error_detail = str(e)
            error_type = type(e).__name__
            
            error(f"Failed to import otpauth URI ({error_type}): {error_detail}")
            return None, f"Import error: {error_detail}" 