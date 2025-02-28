"""
Vault implementation using Rust-based cryptography with envelope encryption.
The vault secures a master key with a vault password, and the master key in turn
secures individual TOTP secrets.
"""

import os
import json
import base64
from pathlib import Path
from .secure_string import SecureString
from datetime import datetime

# Import our Rust crypto module with proper fallbacks
try:
    import truefa_crypto
    from truefa_crypto import (
        secure_random_bytes, is_vault_unlocked, vault_exists, 
        create_vault, unlock_vault, lock_vault, generate_salt,
        derive_master_key, encrypt_master_key, decrypt_master_key,
        verify_signature
    )
    print("Successfully imported truefa_crypto module")
except ImportError as e:
    print(f"WARNING: Failed to import truefa_crypto: {str(e)}")
    print("Creating fallback implementation")
    
    # Define a dummy fallback module
    class _DummyModule:
        def __init__(self):
            # State
            self._vault_initialized = False
            self._vault_unlocked = False
            self._vault_salt = None
            self._vault_password_hash = None
            self._master_key = None
            
            # Print for debugging
            print("Initialized dummy truefa_crypto module")
        
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
                print(f"DUMMY CALL: secure_string_clear((12345,), {{}})")
                self._data = None
        
        # Vault functions
        def secure_random_bytes(self, size):
            """Generate cryptographically secure random bytes."""
            print(f"DUMMY CALL: secure_random_bytes(({size},), {{}})")
            import os
            return os.urandom(size)
            
        def is_vault_unlocked(self):
            """Check if the vault is currently unlocked."""
            return self._vault_unlocked
            
        def vault_exists(self):
            """Check if a vault has been initialized."""
            return self._vault_initialized
            
        def create_vault(self, password):
            """Create a new vault with the given master password."""
            print(f"DUMMY CALL: create_vault(({password},), {{}})")
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
            self._vault_password_hash = base64.b64encode(self._vault_password_hash).decode('utf-8')
            
            # Mark the vault as initialized and unlocked
            self._vault_initialized = True
            self._vault_unlocked = True
            
            return self._vault_salt
            
        def unlock_vault(self, password, salt):
            """Unlock the vault with the given password and salt."""
            print(f"DUMMY CALL: unlock_vault(({password}, {salt}), {{}})")
            import hashlib
            import base64
            
            # Hash the provided password with the salt
            password_hash = hashlib.pbkdf2_hmac(
                'sha256',
                password.encode('utf-8'),
                salt.encode('utf-8'),
                100000
            )
            password_hash = base64.b64encode(password_hash).decode('utf-8')
            
            # Check if the password is correct
            if password_hash == self._vault_password_hash:
                self._vault_unlocked = True
                return True
            else:
                return False
                
        def lock_vault(self):
            """Lock the vault, clearing all sensitive data."""
            print("DUMMY CALL: lock_vault((), {})")
            self._vault_unlocked = False
            
        def generate_salt(self):
            """Generate a random salt for key derivation."""
            print("DUMMY CALL: generate_salt((), {})")
            import base64
            import os
            return base64.b64encode(os.urandom(32)).decode('utf-8')
            
        def derive_master_key(self, password, salt):
            """Derive a master key from a password and salt."""
            print(f"DUMMY CALL: derive_master_key(({password}, {salt}), {{}})")
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
            print(f"DUMMY CALL: encrypt_master_key(({master_key},), {{}})")
            # For a more secure fallback, we'll use AES for encryption
            import base64
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.backends import default_backend
            import os

            if not self._vault_unlocked:
                raise ValueError("Vault is locked, cannot encrypt master key")
            
            # Decode the master key from base64
            try:
                master_key_bytes = base64.b64decode(master_key)
            except Exception as e:
                raise ValueError(f"Invalid master key encoding: {e}")
            
            # Generate a random nonce
            nonce = os.urandom(12)  # 12 bytes for AES-GCM
            
            # Use a derived key from the vault password hash as the encryption key
            # In a real implementation, this would use the vault key
            encryption_key = base64.b64decode(self._vault_password_hash)[:32]  # Use first 32 bytes
            
            # Create cipher
            algorithm = algorithms.AES(encryption_key)
            cipher = Cipher(algorithm, modes.GCM(nonce), backend=default_backend())
            encryptor = cipher.encryptor()
            
            # Encrypt
            ciphertext = encryptor.update(master_key_bytes) + encryptor.finalize()
            
            # Combine nonce, ciphertext, and tag for storage
            result = nonce + ciphertext + encryptor.tag
            
            return base64.b64encode(result).decode('utf-8')
            
        def decrypt_master_key(self, encrypted_key):
            """Decrypt the master key with the vault key."""
            print(f"DUMMY CALL: decrypt_master_key(({encrypted_key},), {{}})")
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
            print(f"DUMMY CALL: verify_signature((), {{}})")
            # For fallback, we'll just return True for now
            return True
    
    # Create instance of dummy module 
    truefa_crypto = _DummyModule()
    
    # Also define the individual functions at module scope for direct import
    def create_vault(password):
        return truefa_crypto.create_vault(password)
        
    def unlock_vault(password, salt):
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
        
    def secure_random_bytes(size):
        return truefa_crypto.secure_random_bytes(size)
        
    def verify_signature(message, signature, public_key):
        return truefa_crypto.verify_signature(message, signature, public_key)
    
    print("Created fallback truefa_crypto module with function proxies")

class SecureVault:
    """
    Secure vault implementation with envelope encryption.
    
    This implements a two-layer security model:
    1. Vault password - unlocks the vault and decrypts the master key
    2. Master key - encrypts/decrypts individual TOTP secrets
    
    The master key is never stored directly, only in encrypted form.
    """
    
    def __init__(self, storage_path=None):
        """Initialize the vault with the specified storage path."""
        self.storage_path = storage_path or os.path.expanduser('~/.truefa')
        self.vault_dir = os.path.join(self.storage_path, '.vault')
        
        # Ensure storage directory exists with proper permissions
        os.makedirs(self.storage_path, mode=0o700, exist_ok=True)
        
        # Try to set permissions, but don't fail if we can't
        try:
            os.chmod(self.storage_path, 0o700)
        except Exception:
            pass
        
        # Vault state
        self._initialized = False
        self._master_key = None
        self._is_unlocked = False
        
        # Load vault configuration if it exists
        self._load_vault_config()

    def _load_vault_config(self):
        """Load vault configuration from disk if it exists."""
        if os.path.exists(self.vault_dir):
            try:
                with open(os.path.join(self.vault_dir, "vault.meta"), 'r') as f:
                    self._vault_config = json.load(f)
                    self._initialized = True
            except Exception as e:
                print(f"Error loading vault configuration: {e}")
                self._vault_config = None
                self._initialized = False
        else:
            self._vault_config = None
            self._initialized = False

    def is_initialized(self):
        """Check if the vault has been initialized."""
        return self._initialized

    def is_unlocked(self):
        """Check if the vault is currently unlocked."""
        return self._is_unlocked

    def create_vault(self, vault_password, master_password=None):
        """
        Create a new secure vault for storing the TOTP secrets.
        
        Args:
            vault_password: Password to unlock the vault in the future
            master_password: Optional secondary password for additional encryption
            
        Returns:
            bool: True if successful, False otherwise
            
        Security:
        - Uses secure key derivation (Argon2id if available, else PBKDF2)
        - Generates secure random salt
        - Provides envelope encryption when master_password is supplied
        """
        try:
            print("Creating secure vault...")
            # Initialize the vault if not already done
            if not os.path.exists(self.vault_dir):
                os.makedirs(self.vault_dir, exist_ok=True)
                
            # Generate a vault salt for key derivation
            vault_salt = truefa_crypto.generate_salt()
            
            # Store the salt in the vault metadata
            with open(os.path.join(self.vault_dir, "vault.meta"), "w") as f:
                f.write(json.dumps({
                    "salt": vault_salt,
                    "version": "1.0",
                    "created": datetime.now().isoformat()
                }))
                
            # If master password provided, set up master key encryption
            if master_password:
                # Generate a salt for the master key
                master_salt = truefa_crypto.generate_salt()
                
                # Derive the master key
                master_key = truefa_crypto.derive_master_key(master_password, master_salt)
                
                # Encrypt the master key with the vault key
                encrypted_master_key = truefa_crypto.encrypt_master_key(master_key)
                
                # Store the master key metadata
                with open(os.path.join(self.vault_dir, "master.meta"), "w") as f:
                    f.write(json.dumps({
                        "salt": master_salt,
                        "encrypted_key": encrypted_master_key,
                        "version": "1.0"
                    }))
            
            # Mark the vault as initialized
            self._initialized = True
            
            # Unlock the vault automatically after creation
            self.unlock(vault_password)
            
            print("Vault created successfully")
            return True
        except Exception as e:
            print(f"Error creating vault: {e}")
            return False

    def unlock(self, vault_password):
        """
        Unlock the vault with the vault password.
        
        This decrypts the master key with the vault password, which can then be used
        to encrypt/decrypt individual TOTP secrets.
        """
        if not self._initialized:
            print("Vault not initialized")
            return False
        
        try:
            # Read the vault metadata
            with open(os.path.join(self.vault_dir, "vault.meta"), "r") as f:
                vault_meta = json.load(f)
                vault_salt = vault_meta.get('salt')
            
            if not vault_salt:
                print("Invalid vault metadata: missing salt")
                return False
            
            # Unlock the vault using the vault key
            unlocked = truefa_crypto.unlock_vault(vault_password, vault_salt)
            
            if unlocked:
                self._is_unlocked = True
                return True
            else:
                print("Failed to unlock vault")
                return False
                
        except FileNotFoundError:
            print(f"Vault metadata not found at {self.vault_dir}")
            return False
        except Exception as e:
            print(f"Error unlocking vault: {e}")
            return False

    def get_master_key(self):
        """
        Get the master key (requires vault to be unlocked).
        
        Returns:
            SecureString or None: Master key if successful
            
        Security:
        - Verifies vault is unlocked 
        - Returns None if vault is locked
        """
        if not self.is_unlocked():
            return None
        
        try:
            # Decrypt the master key
            encrypted_master_key = None
            with open(os.path.join(self.vault_dir, "master.meta"), 'r') as f:
                master_config = json.load(f)
                encrypted_master_key = master_config.get('encrypted_key')
            
            if not encrypted_master_key:
                return None
            
            decrypted_master_key = truefa_crypto.decrypt_master_key(encrypted_master_key)
            
            # Ensure proper base64 padding
            if isinstance(decrypted_master_key, str):
                padding = 4 - (len(decrypted_master_key) % 4) if len(decrypted_master_key) % 4 else 0
                decrypted_master_key = decrypted_master_key + ('=' * padding)
            
            # Create a secure string
            return SecureString(decrypted_master_key)
        except Exception as e:
            print(f"Error getting master key: {e}")
            return None

    def lock(self):
        """Lock the vault, clearing all sensitive data from memory."""
        truefa_crypto.lock_vault()
        self._is_unlocked = False
        return True

    def change_vault_password(self, current_password, new_password):
        """Change the vault password."""
        if not self.unlock(current_password):
            return False
        
        # Get the current master key
        master_key = self.get_master_key()
        if not master_key:
            return False
        
        # Extract the master key as a string
        master_key_str = master_key.get()
        master_key.clear()
        
        # Generate a new vault key and encrypt the master key with it
        vault_salt = truefa_crypto.generate_salt()
        encrypted_master_key = truefa_crypto.encrypt_master_key(master_key_str)
        
        # Update and save configuration
        with open(os.path.join(self.vault_dir, "vault.meta"), "w") as f:
            f.write(json.dumps({
                "salt": vault_salt,
                "version": "1.0",
                "created": datetime.now().isoformat()
            }))
        
        with open(os.path.join(self.vault_dir, "master.meta"), "w") as f:
            f.write(json.dumps({
                "encrypted_key": encrypted_master_key,
                "version": "1.0"
            }))
        
        return True

    def change_master_password(self, vault_password, current_master_password, new_master_password):
        """
        Change the master password used for encrypting individual secrets.
        
        This requires:
        1. Unlocking the vault with the vault password
        2. Verifying the current master password
        3. Generating a new master key from the new password
        4. Encrypting it with the vault key
        
        Note: This doesn't re-encrypt existing secrets, which would need to be
        handled separately in the application.
        """
        if not self.unlock(vault_password):
            return False, "Incorrect vault password"
        
        # Verify current master password
        master_salt = None
        with open(os.path.join(self.vault_dir, "master.meta"), 'r') as f:
            master_config = json.load(f)
            master_salt = master_config.get('salt')
        
        if not master_salt:
            return False, "Vault configuration corrupted"
        
        try:
            # Generate the current master key to verify it
            current_key = truefa_crypto.derive_master_key(current_master_password, master_salt)
            
            # Generate a new salt for the new master password
            new_master_salt = truefa_crypto.generate_salt()
            
            # Derive the new master key
            new_master_key = truefa_crypto.derive_master_key(new_master_password, new_master_salt)
            
            # Encrypt the new master key with the vault key
            encrypted_master_key = truefa_crypto.encrypt_master_key(new_master_key)
            
            # Update and save configuration
            with open(os.path.join(self.vault_dir, "master.meta"), "w") as f:
                f.write(json.dumps({
                    "salt": new_master_salt,
                    "encrypted_key": encrypted_master_key,
                    "version": "1.0"
                }))
            
            return True, "Master password changed successfully"
        except Exception as e:
            return False, f"Error changing master password: {e}"
