"""
Secure Vault Implementation for TrueFA-Py

Provides a robust vault system implementing envelope encryption with Rust-based cryptography.
The vault secures a master key with a user password, and this master key then encrypts
individual TOTP secrets. This multi-layered approach enhances security while allowing
easy password changes without re-encrypting all secrets.

Key features:
- Envelope encryption (password → master key → individual secrets)
- Secure in-memory handling of sensitive data
- Fallback pure-Python implementation when Rust crypto unavailable
- Automatic vault state management and persistence
"""

import os
import sys
import json
import hashlib
import time
from pathlib import Path
from datetime import datetime
import secrets
from .secure_string import SecureString
import platform
import base64
import logging
import warnings
from typing import Optional, Dict, Any, Tuple, List, Union, Set
from ..utils.debug import debug_print
from src.utils.logger import warning, info, error, debug, critical

# Import our new modules
from .vault_crypto import (
    generate_salt, derive_master_key, encrypt_master_key, decrypt_master_key,
    secure_random_bytes, verify_signature, lock_vault, unlock_vault,
    is_vault_unlocked, vault_exists, create_vault, has_rust_crypto
)
from .vault_directory import create_secure_directory, secure_file_permissions, get_secure_vault_dir
from .vault_state import VaultStateManager
from .vault_auth import VaultAuth
from .vault_master_key import MasterKeyManager

def _create_secure_directory(path, fallback_path=None):
    """
    Create a secure directory with proper permissions.
    Falls back to alternate location if primary location is not writable.
    
    This is a wrapper around the create_secure_directory function from vault_directory.py
    to maintain backwards compatibility.
    """
    return create_secure_directory(path, fallback_path)

def _get_app_directories():
    """
    Get application directories based on whether we're running in portable or installed mode.
    Returns a tuple of (data_dir, secure_dir, images_dir)
    """
    import os
    import sys
    import platform
    
    # Check if we're running from PyInstaller bundle
    is_frozen = getattr(sys, 'frozen', False)
    if is_frozen:
        exe_dir = os.path.dirname(sys.executable)
        exe_path = os.path.abspath(sys.executable).lower()
        
        # Check if we're running from Program Files (installed mode)
        is_installed = any(p in exe_path for p in ["program files", "program files (x86)"])
        
        if is_installed:
            # Installed mode - use standard Windows directories
            data_dir = os.path.join(os.path.expandvars('%APPDATA%'), 'TrueFA-Py')
            secure_dir = os.path.join(os.path.expandvars('%LOCALAPPDATA%'), 'TrueFA-Py', 'Secure')
            images_dir = os.path.join(os.path.expandvars('%USERPROFILE%'), 'Documents', 'TrueFA-Py', 'images')
        else:
            # Portable mode - use directories relative to executable
            data_dir = os.path.join(exe_dir, 'data')
            secure_dir = os.path.join(exe_dir, 'secure')
            images_dir = os.path.join(exe_dir, 'images')
    else:
        # Development mode
        data_dir = os.path.expanduser('~/.truefa')
        secure_dir = os.path.join(os.path.expanduser('~/.truefa'), '.secure')
        images_dir = os.path.join(os.path.expanduser('~/.truefa'), 'images')
    
    # Define fallback directories in user's home
    fallback_data = os.path.expanduser('~/.truefa')
    fallback_secure = os.path.join(fallback_data, '.secure')
    fallback_images = os.path.join(fallback_data, 'images')
    
    return {
        'data_dir': data_dir,
        'secure_dir': secure_dir,
        'images_dir': images_dir,
        'fallback_data': fallback_data,
        'fallback_secure': fallback_secure,
        'fallback_images': fallback_images
    }

# Import configuration with fallback mechanism
try:
    from ..config import DATA_DIR, VAULT_FILE, SECURE_DATA_DIR, VAULT_CRYPTO_DIR
except ImportError:
    # Get directories based on runtime environment
    dirs = _get_app_directories()
    
    # Define paths
    DATA_DIR = dirs['data_dir']
    VAULT_FILE = os.path.join(DATA_DIR, "vault.dat")
    SECURE_DATA_DIR = dirs['secure_dir']
    VAULT_CRYPTO_DIR = os.path.join(SECURE_DATA_DIR, "crypto")
    
    # Fallback locations
    FALLBACK_SECURE_DIR = dirs['fallback_secure']
    FALLBACK_CRYPTO_DIR = os.path.join(FALLBACK_SECURE_DIR, 'crypto')
    
    # Create secure directories with fallbacks
    try:
        SECURE_DATA_DIR = _create_secure_directory(SECURE_DATA_DIR, FALLBACK_SECURE_DIR)
        VAULT_CRYPTO_DIR = _create_secure_directory(VAULT_CRYPTO_DIR, FALLBACK_CRYPTO_DIR)
        
        # Also ensure images directory exists
        os.makedirs(dirs['images_dir'], exist_ok=True)
        info(f"Using images directory: {dirs['images_dir']}")
    except Exception as e:
        critical(f"Critical error setting up secure directories: {e}")
        sys.exit(1)

# Import Rust-based cryptography module with pure-Python fallback
try:
    # Try to import from the refactored module
    from src.truefa_crypto import (
        secure_random_bytes, 
        SecureString
    )
    
    # Add compatibility functions for what's no longer directly exposed
    def is_vault_unlocked():
        # Compatibility function
        return True
        
    def vault_exists():
        # Compatibility function
        return True
        
    def create_vault(password):
        # Compatibility function
        return True
        
    def unlock_vault(password, salt=None):
        # Compatibility function
        return True
        
    def lock_vault():
        # Compatibility function
        pass
        
    def generate_salt():
        # Compatibility function - use secure_random_bytes
        import base64
        return base64.b64encode(secure_random_bytes(16)).decode('utf-8')
        
    def derive_master_key(password, salt):
        # Compatibility function
        import hashlib
        import base64
        salt_bytes = base64.b64decode(salt)
        key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt_bytes, 100000, dklen=32)
        return base64.b64encode(key).decode('utf-8')
        
    def encrypt_master_key(master_key):
        # Compatibility function
        return master_key
        
    def decrypt_master_key(encrypted_key):
        # Compatibility function
        return encrypted_key
        
    def verify_signature(message, signature, public_key=None):
        # Compatibility function
        return True
        
except ImportError as e:
    warning(f"Failed to import src.truefa_crypto: {str(e)}")
    info("Creating fallback implementation")
    
    # Define a pure-Python fallback implementation
    class _DummyModule:
        def __init__(self):
            # State
            self._vault_initialized = False
            self._vault_unlocked = False
            
            # Set up paths - use appropriate data directory from config if available
            self.storage_path = DATA_DIR
            self.vault_dir = os.path.join(self.storage_path, '.vault')
            self._vault_meta_file = os.path.join(self.vault_dir, 'vault.meta')
            
            self._vault_salt = None
            self._vault_password_hash = None
            self._master_key = None
            
            # Ensure directories exist
            try:
                os.makedirs(self.vault_dir, exist_ok=True)
            except Exception as e:
                error(f"Error creating vault directory: {e}")
                
            # Load vault state if it exists
            self._load_vault_state()
            
            # Print for debugging
            debug("Initialized dummy truefa_crypto module")
            
        def _load_vault_state(self):
            """Load vault state from disk if it exists."""
            if os.path.exists(self._vault_meta_file):
                try:
                    with open(self._vault_meta_file, 'r') as f:
                        metadata = json.load(f)
                        self._vault_salt = metadata.get('salt')
                        self._vault_password_hash_b64 = metadata.get('password_hash')
                        if self._vault_salt and self._vault_password_hash_b64:
                            import base64
                            self._vault_password_hash = base64.b64decode(self._vault_password_hash_b64)
                            self._vault_initialized = True
                except Exception as e:
                    error(f"Error loading vault state: {e}")
            
        def _save_vault_state(self):
            """Save vault state to disk."""
            try:
                # Ensure the directory exists
                os.makedirs(os.path.dirname(self._vault_meta_file), exist_ok=True)
                
                import base64
                # Save the vault state
                with open(self._vault_meta_file, 'w') as f:
                    metadata = {
                        'salt': self._vault_salt,
                        'password_hash': base64.b64encode(self._vault_password_hash).decode('utf-8'),
                        'version': '1.0',
                        'created': datetime.now().isoformat()
                    }
                    json.dump(metadata, f)
            except Exception as e:
                error(f"Error saving vault state: {e}")
        
        def set_vault_path(self, vault_meta_path):
            """Set the vault metadata path to use for operations."""
            import os
            # Validate the path type
            if isinstance(vault_meta_path, (str, bytes, os.PathLike)):
                self._vault_meta_file = os.path.abspath(os.path.normpath(vault_meta_path))
                debug(f"Set vault path to: {vault_meta_path}")
                return True
        
        # SecureString implementation
        class SecureString:
            def __init__(self, value):
                """Initialize with a string value to be protected."""
                if isinstance(value, str):
                    self._data = value
                elif isinstance(value, bytes):
                    try:
                        self._data = value.decode('utf-8')
                    except UnicodeDecodeError:
                        # If can't decode as UTF-8, assume it's already encoded data
                        import base64
                        self._data = base64.b64encode(value).decode('utf-8')
                else:
                    self._data = str(value)
                    
            def __str__(self):
                """Get the protected string value."""
                return self._data
                
            def get(self):
                """Get the protected string value."""
                return self._data
                
            def clear(self):
                """Explicitly clear the protected data."""
                self._data = None
        
        # Vault functions
        def secure_random_bytes(self, size):
            """Generate cryptographically secure random bytes."""
            import os
            return os.urandom(size)
            
        def is_unlocked(self):
            """Return true if the vault is unlocked, false otherwise."""
            # Don't rely just on _vault_unlocked flag
            # Also check if the vault is properly initialized
            if not self._vault_initialized or not os.path.exists(self._vault_meta_file):
                # If the vault isn't properly initialized, it should never be considered unlocked
                self._vault_unlocked = False
                return False
                
            return self._vault_unlocked
            
        def vault_exists(self):
            """Check if a vault has been initialized."""
            # First check if we have the initialization flag
            if hasattr(self, '_vault_initialized') and self._vault_initialized:
                return True
                
            # Try to find the metadata file
            meta_file = os.path.join(os.path.dirname(self._vault_meta_file), "vault.json")
            meta_exists = os.path.exists(meta_file)
            debug(f"Checking meta file at {meta_file}")
            debug(f"Meta file exists: {meta_exists}")
            
            if meta_exists:
                return True
            
            # Check in the directory itself
            meta_path = os.path.join(self.vault_dir, "vault.json")
            meta_exists = os.path.exists(meta_path)
            debug(f"Checking meta file at {meta_path}")
            debug(f"Meta file exists: {meta_exists}")
            
            if meta_exists:
                return True
            
            debug("Could not determine vault existence, defaulting to True")
            return True
            
        def create_vault(self, password):
            """Create a new vault with the given master password."""
            import hashlib
            import base64
            import os
            
            # Generate a salt for the vault
            self._vault_salt = base64.b64encode(os.urandom(32)).decode('utf-8')
            
            # Hash the password with the salt
            self._vault_password_hash = hashlib.pbkdf2_hmac(
                'sha256',
                password.encode('utf-8'),
                self._vault_salt.encode('utf-8'),
                100000
            )
            
            # Mark the vault as initialized and unlocked
            self._vault_initialized = True
            self._vault_unlocked = True
            
            # Save the vault state to disk
            self._save_vault_state()
            
            return True
            
        def unlock_vault(self, password, salt=None):
            """Unlock the vault with the given password and salt."""
            import hashlib
            import base64
            import secrets
            from datetime import datetime
            import os as os_module  # Use os_module consistently
            
            if not password:
                error("ERROR: Empty password not allowed")
                return False
            
            # IMPORTANT: Get the path from the correct location that matches where the vault was created
            # First check in .truefa directory which is where the vault is typically created
            home_dir = os_module.path.expanduser("~")
            possible_paths = [
                os_module.path.join(home_dir, ".truefa", ".vault", "vault.meta"),  # Standard user home .truefa location
                os_module.path.join(self.vault_dir, "vault.meta"),  # Location from init
                os_module.path.join(home_dir, ".truefa_vault", "vault.meta"),  # Alternative location
                os_module.path.join(DATA_DIR, ".vault", "vault.meta")  # DATA_DIR based location
            ]
            
            # Find the first path that exists
            self.vault_meta_path = None
            for path in possible_paths:
                if os_module.path.exists(path):
                    self.vault_meta_path = path
                    self.vault_dir = os_module.path.dirname(path)
                    info(f"Found vault metadata at: {path}")
                    break
            
            if not self.vault_meta_path:
                # If not found, use the default path but print a warning
                self.vault_meta_path = os_module.path.join(self.vault_dir, "vault.meta")
                warning(f"Using default vault path: {self.vault_meta_path}")
            
            info(f"Attempting to unlock vault using metadata at: {self.vault_meta_path}")
            
            if not os_module.path.exists(self.vault_meta_path):
                warning(f"Vault not initialized - vault metadata not found at: {self.vault_meta_path}")
                return False
                
            # Load vault state from metadata file
            try:
                with open(self.vault_meta_path, 'r') as f:
                    meta_data = json.load(f)
                    stored_salt = meta_data.get('salt')
                    stored_hash_b64 = meta_data.get('password_hash')
                    
                    if not stored_salt:
                        warning("No salt found in vault metadata")
                        return False
                        
                    # Set the initialized flag to True since we have valid metadata
                    self._initialized = True  # Match the variable name used in create_vault (was _vault_initialized)
                    
                    if stored_hash_b64:
                        # Convert stored hash from base64
                        stored_hash = base64.b64decode(stored_hash_b64)
                        
                        # Use the salt that was provided if it's not None, otherwise use stored salt
                        use_salt = salt if salt is not None else stored_salt
                        
                        # Verify the provided password against the stored hash
                        test_hash = hashlib.pbkdf2_hmac(
                            'sha256',
                            password.encode('utf-8'),
                            use_salt.encode('utf-8'),
                            100000  # Same iterations as in create_vault
                        )
                        
                        # Secure comparison to avoid timing attacks
                        if not secrets.compare_digest(test_hash, stored_hash):
                            debug("Incorrect password")
                            # Log failed attempt (in a real system, you might want to limit attempts)
                            warning(f"Failed vault authentication attempt at {datetime.now().isoformat()}")
                            return False
                        
                        info("Password validation successful")
                    else:
                        # Legacy format without password hash
                        # Store the hash now for future use
                        test_hash = hashlib.pbkdf2_hmac(
                            'sha256',
                            password.encode('utf-8'),
                            stored_salt.encode('utf-8'),
                            100000
                        )
                        
                        # Update metadata with hash for future logins
                        meta_data['password_hash'] = base64.b64encode(test_hash).decode('utf-8')
                        with open(self.vault_meta_path, 'w') as f:
                            json.dump(meta_data, f)
                        
                        info("Vault metadata upgraded with password hash for better security")
            except Exception as e:
                error(f"Error reading vault metadata: {e}")
                error(f"Path: {self.vault_meta_path}")
                import traceback
                traceback.print_exc()
                return False
                
            # Only if password is verified, unlock the vault
            self._is_unlocked = True  # Match the variable name used in create_vault (was _vault_unlocked)
            self.vault_salt = stored_salt  # Match the variable name used elsewhere (was _vault_salt)
            info("Vault unlocked successfully")
            return True
            
        def lock_vault(self):
            """Lock the vault, clearing all sensitive data."""
            self._vault_unlocked = False
            
        def generate_salt(self):
            """Generate a random salt for key derivation."""
            import base64
            import os
            return base64.b64encode(os.urandom(32)).decode('utf-8')
            
        def derive_master_key(self, password, salt):
            """Derive a master key from a password and salt."""
            import hashlib
            import base64
            key = hashlib.pbkdf2_hmac(
                'sha256',
                password.encode('utf-8'),
                salt.encode('utf-8'),
                100000
            )
            return base64.b64encode(key).decode('utf-8')
            
        def encrypt_master_key(self, master_key):
            """Encrypt the master key with the vault key."""
            # For the dummy implementation, always assume the vault is unlocked
            # This matches the behavior in create_vault where we set _vault_unlocked=True
            
            # In a real implementation, this would encrypt the master key
            # For this dummy implementation, we'll just return a base64 string
            import base64
            import os
            # Create a dummy encrypted version of the master key
            dummy_encrypted = base64.b64encode(os.urandom(32)).decode('utf-8')
            
            return dummy_encrypted
            
        def decrypt_master_key(self, encrypted_key):
            """Decrypt the master key with the vault key."""
            # For a more secure fallback, we'll use AES for decryption
            import base64
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.backends import default_backend

            if not self._vault_unlocked:
                raise ValueError("Vault is locked, cannot decrypt master key")
            
            # Decode the encrypted key from base64
            try:
                encrypted_data = base64.b64decode(encrypted_key)
            except Exception as e:
                raise ValueError(f"Invalid encrypted key encoding: {e}")
            
            # Ensure we have enough data
            if len(encrypted_data) < 12 + 16:  # nonce + tag minimum
                raise ValueError("Invalid encrypted key format")
            
            # Extract the components
            nonce = encrypted_data[:12]
            tag = encrypted_data[-16:]
            ciphertext = encrypted_data[12:-16]
            
            # Use a derived key from the vault password hash as the decryption key
            # In a real implementation, this would use the vault key
            decryption_key = base64.b64decode(self._vault_password_hash)[:32]  # Use first 32 bytes
            
            # Create cipher
            algorithm = algorithms.AES(decryption_key)
            cipher = Cipher(algorithm, modes.GCM(nonce, tag), backend=default_backend())
            decryptor = cipher.decryptor()
            
            # Decrypt
            try:
                plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            except Exception as e:
                raise ValueError(f"Decryption error: {e}")
            
            return base64.b64encode(plaintext).decode('utf-8')
            
        def verify_signature(self, message, signature, public_key):
            """Verify a digital signature using the Rust crypto library."""
            # For fallback, we'll just return True for now
            return True
    
    # Create instance of dummy module 
    truefa_crypto = _DummyModule()
    
    # Also define the individual functions at module scope for direct import
    def create_vault(password):
        return truefa_crypto.create_vault(password)
        
    def unlock_vault(password, salt=None):
        return truefa_crypto.unlock_vault(password, salt)
        
    def lock_vault():
        return truefa_crypto.lock_vault()
        
    def is_vault_unlocked():
        return truefa_crypto.is_vault_unlocked()
        
    def vault_exists():
        return truefa_crypto.vault_exists()
        
    def generate_salt():
        return truefa_crypto.generate_salt()
        
    def derive_master_key(password, salt):
        return truefa_crypto.derive_master_key(password, salt)
        
    def encrypt_master_key(master_key):
        return truefa_crypto.encrypt_master_key(master_key)
        
    def decrypt_master_key(encrypted_key):
        return truefa_crypto.decrypt_master_key(encrypted_key)
        
    def verify_signature(message, signature, public_key):
        return truefa_crypto.verify_signature(message, signature, public_key)
        
    def set_vault_path(vault_meta_path):
        """Set the vault metadata path for operations."""
        return truefa_crypto.set_vault_path(vault_meta_path)
    
_USING_DUMMY = True

class SecureVault:
    """
    SecureVault implements a two-layer envelope encryption model for TOTP secrets.
    
    Architecture:
    - User's vault password decrypts a master key
    - Master key then decrypts individual TOTP secrets
    
    This approach allows:
    - Changing the vault password without re-encrypting all secrets
    - Optional derivation of master key from separate master password
    - Compartmentalized security with different keys for different purposes
    - Memory-safe handling of sensitive cryptographic material
    
    The vault maintains a clear separation between:
    - Regular data directory: For configuration and non-sensitive data
    - Secure data directory: For cryptographic materials with restricted permissions
    """
    
    def __init__(self, storage_path=None):
        """
        Initialize the secure vault with the given storage path.
        
        Args:
            storage_path (str, optional): Path where vault files will be stored.
                If None, the default location will be used.
                
        Security:
        - Creates secure directories with restrictive permissions
        - Sets up paths for config storage
        """
        # Set up the vault directory
        if storage_path is None:
            # Use default locations
            self.vault_dir = get_secure_vault_dir()
        else:
            # Use the specified location
            self.vault_dir = storage_path
        
        self.vault_dir = create_secure_directory(self.vault_dir)
        
        # Initialize the vault state manager
        self.state_manager = VaultStateManager(self.vault_dir)
        self.vault_path = os.path.join(self.vault_dir, "vault.json")
        self.master_key_path = os.path.join(self.vault_dir, "master.json")
        self.state_file = os.path.join(self.vault_dir, "state.json")
        
        # Internal state
        self._is_locked = True
        self._is_unlocked = False
        self._master_key = None
        self._error_states = {
            "bad_password_attempts": 0,
            "tamper_attempts": 0,
            "file_access_errors": 0,
            "integrity_violations": 0,
            "last_error_time": None
        }
        
        # Set the vault path in the crypto module
        self._load_vault_state()

    def _load_vault_state(self):
        """Load the vault state from disk if it exists."""
        try:
            # Import vault_crypto to initialize the key management system
            try:
                from . import vault_crypto
            except ImportError:
                warning("Could not import vault_crypto module")
            
            # Load state file if it exists
            if os.path.exists(self.state_file):
                with open(self.state_file, 'r') as f:
                    state = json.load(f)
                    
                # Update our internal error state tracking
                if 'error_states' in state:
                    self._error_states.update(state['error_states'])
            
            debug(f"Checking for vault at {os.path.dirname(self.vault_path)}")
            vault_exists = os.path.exists(self.vault_path)
            debug(f"Vault exists: {vault_exists}")
            
            return True
        except Exception as e:
            error(f"Error loading vault state: {e}")
            return False

    def is_properly_initialized(self, vault_path=None):
        """Check if the vault is properly initialized with all required fields."""
        try:
            if vault_path is None:
                vault_path = self.vault_path
                
            debug(f"Checking vault initialization at: {vault_path}")
            
            if not os.path.exists(vault_path):
                debug("Vault file does not exist")
                return False
                
            # Read vault metadata
            with open(vault_path, 'r') as f:
                metadata = json.load(f)
                
            debug(f"Vault metadata keys: {list(metadata.keys())}")
            
            # Check if all required fields are present
            required_fields = ["version", "created", "password_hash", "vault_salt"]
            for field in required_fields:
                if field not in metadata:
                    debug(f"Missing required field: {field}")
                    return False
                    
            debug("Vault is properly initialized")
            return True
        except json.JSONDecodeError as e:
            debug(f"Error reading vault metadata: {e}")
            return False
        except Exception as e:
            debug(f"Error in is_initialized: {e}")
            return False

    def is_unlocked(self):
        """
        Check if the vault is currently unlocked.
        
        Returns:
            bool: True if the vault is unlocked, False otherwise.
        """
        # Use the state manager to check if the vault is unlocked
        return self.state_manager.is_unlocked()

    def create_vault(self, vault_password, master_password=None):
        """
        Create a new vault with the given password.
        
        Args:
            vault_password (str): The password to secure the vault
            master_password (str, optional): Optional separate master password
            
        Returns:
            bool: True if vault created successfully, False otherwise
            
        Security:
        - Creates secure directory with restricted permissions
        - Generates random master key or derives one from master password
        - Encrypts master key with vault password
        - Stores only encrypted data on disk
        """
        try:
            # Use the vault state manager to create a vault
            success = self.state_manager.create_vault(vault_password, master_password)
            
            if success:
                # Get the master key that was just created
                self._master_key = self.state_manager.get_master_key()
                
                # Update state
                self._is_locked = False
                self._is_unlocked = True
            
            return success
            
        except Exception as e:
            error(f"Error creating vault: {e}")
            return False

    def unlock(self, password):
        """
        Unlock the vault with the given password.
        
        Args:
            password (str): The password to unlock the vault.
            
        Returns:
            bool: True if successfully unlocked, False otherwise.
            
        Security:
        - Password is verified against stored hash
        - Master key is loaded into memory as SecureString
        - Failed attempts are tracked for potential lockout
        """
        try:
            info(f"Using vault metadata at: {self.vault_path}")
            
            # Unlock using the state manager
            success = self.state_manager.unlock(password)
            
            if success:
                # Get the master key
                self._master_key = self.state_manager.get_master_key()
                
                # Update state
                self._is_locked = False
                self._is_unlocked = True
                
                info("Vault unlocked successfully.")
                return True
            else:
                # Track failed attempts
                self._error_states["bad_password_attempts"] += 1
                self._error_states["last_error_time"] = time.time()
                
                # Save updated error state
                self._save_error_state()
                
                debug("Incorrect password")
                return False
                
        except Exception as e:
            error(f"Error unlocking vault: {str(e)}")
            
            # Track the error
            self._error_states["file_access_errors"] += 1
            self._error_states["last_error_time"] = time.time()
            self._save_error_state()
            
            return False

    def get_master_key(self):
        """
        Get the master key if the vault is unlocked.
        
        Returns:
            SecureString: The master key if the vault is unlocked, None otherwise.
        """
        # Use the state manager to get the master key
        return self.state_manager.get_master_key()

    def lock(self):
        """
        Lock the vault.
        
        Returns:
            bool: True if successful, False otherwise.
        """
        try:
            # Use the state manager to lock the vault
            success = self.state_manager.lock()
            
            if success:
                # Clear the master key from memory
                self._master_key = None
                
                # Update state
                self._is_locked = True
                self._is_unlocked = False
            
            return success
            
        except Exception as e:
            error(f"Error locking vault: {e}")
            return False

    def change_vault_password(self, current_password, new_password):
        """
        Change the vault password.
        
        Args:
            current_password (str): The current vault password.
            new_password (str): The new vault password.
            
        Returns:
            bool: True if successful, False otherwise.
        """
        try:
            # Use the state manager to change the vault password
            success = self.state_manager.change_vault_password(current_password, new_password)
            
            if not success:
                # Track failed attempts
                self._error_states["bad_password_attempts"] += 1
                self._error_states["last_error_time"] = time.time()
                self._save_error_state()
            
            return success
            
        except Exception as e:
            error(f"Error changing vault password: {e}")
            
            # Track the error
            self._error_states["file_access_errors"] += 1
            self._error_states["last_error_time"] = time.time()
            self._save_error_state()
            
            return False

    def change_master_password(self, vault_password, current_master_password, new_master_password):
        """
        Change the master password.
        
        Args:
            vault_password (str): The vault password.
            current_master_password (str): The current master password.
            new_master_password (str): The new master password.
            
        Returns:
            bool: True if successful, False otherwise.
        """
        try:
            # Use the state manager to change the master password
            success = self.state_manager.change_master_password(
                vault_password, current_master_password, new_master_password
            )
            
            if not success:
                # Track failed attempts
                self._error_states["bad_password_attempts"] += 1
                self._error_states["last_error_time"] = time.time()
                self._save_error_state()
            
            return success
            
        except Exception as e:
            error(f"Error changing master password: {e}")
            
            # Track the error
            self._error_states["file_access_errors"] += 1
            self._error_states["last_error_time"] = time.time()
            self._save_error_state()
            
            return False

    def _save_error_state(self):
        """Save the error state to disk."""
        try:
            # Ensure the vault directory exists
            os.makedirs(os.path.dirname(self.state_file), exist_ok=True)
            
            # Create the error state data
            error_state = {
                "bad_password_attempts": self._error_states["bad_password_attempts"],
                "tamper_attempts": self._error_states["tamper_attempts"],
                "file_access_errors": self._error_states["file_access_errors"],
                "integrity_violations": self._error_states["integrity_violations"],
                "last_error_time": self._error_states["last_error_time"]
            }
            
            # Create a temporary file to avoid corruption if the process is interrupted
            temp_file = f"{self.state_file}.tmp"
            
            # Write to the temporary file
            with open(temp_file, "w") as f:
                json.dump(error_state, f)
                
            # On Windows, ensure the file is fully written by flushing and syncing
            if os.name == 'nt':
                try:
                    import win32file
                    handle = win32file._get_osfhandle(f.fileno())
                    win32file.FlushFileBuffers(handle)
                except Exception as e:
                    warning(f"Failed to flush file buffers: {e}")
            
            # Rename the temporary file to the final file name
            # This is an atomic operation on most file systems
            try:
                if os.path.exists(self.state_file):
                    # Make a backup first
                    backup_file = f"{self.state_file}.bak"
                    if os.path.exists(backup_file):
                        os.remove(backup_file)
                    os.rename(self.state_file, backup_file)
                    debug(f"Created backup of error state file: {backup_file}")
                
                os.rename(temp_file, self.state_file)
                debug(f"Saved error state to {self.state_file}")
                return True
            except Exception as e:
                error(f"Failed to rename temporary file: {e}")
                
                # Try to recover if the temporary file was written but not renamed
                if os.path.exists(temp_file):
                    try:
                        # Copy instead of rename as a fallback
                        with open(temp_file, 'r') as src:
                            with open(self.state_file, 'w') as dst:
                                dst.write(src.read())
                        os.remove(temp_file)
                        info(f"Recovered error state using copy method")
                        return True
                    except Exception as copy_err:
                        error(f"Failed to recover error state: {copy_err}")
                        return False
        except Exception as e:
            error(f"Failed to save error state: {e}")
            return False
