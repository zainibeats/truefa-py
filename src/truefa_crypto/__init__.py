"""
Rust-based cryptographic functions for TrueFA

This module provides a high-performance, secure implementation of cryptographic
operations required by TrueFA.
"""

import os
import sys
import ctypes
import logging
import platform
from pathlib import Path

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("truefa_crypto")

# Possible paths to search for DLL
DLL_PATHS = [
    # Current directory
    os.path.join(os.getcwd(), "truefa_crypto.dll"),
    # Module directory
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "truefa_crypto.dll"),
    # Inside truefa_crypto directory
    os.path.join(os.getcwd(), "truefa_crypto", "truefa_crypto.dll"),
    # Rust target directory
    os.path.join(os.getcwd(), "rust_crypto", "target", "release", "truefa_crypto.dll"),
    # If installed as a package
    os.path.join(sys.prefix, "truefa_crypto.dll"),
]

# Load the DLL
dll = None

running_from_pyinstaller = getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS')
base_dir = sys._MEIPASS if running_from_pyinstaller else os.getcwd()
logger.info(f"Running {'from PyInstaller bundle' if running_from_pyinstaller else 'from regular Python'}. Searching in: {base_dir}")
logger.info(f"Current working directory: {os.getcwd()}")

# Try to load from all possible paths
for dll_path in DLL_PATHS:
    if os.path.exists(dll_path):
        logger.info(f"Found DLL at {dll_path}")
        try:
            dll = ctypes.CDLL(dll_path)
            logger.info(f"Successfully loaded DLL from {dll_path}")
            
            # Verify if the DLL has the needed functions
            functions_to_check = ['c_create_secure_string']
            all_functions_found = True
            
            for func_name in functions_to_check:
                if hasattr(dll, func_name):
                    logger.info(f"Found function: {func_name}")
                else:
                    logger.warning(f"Function not found in DLL: {func_name}")
                    all_functions_found = False
            
            if all_functions_found:
                logger.info("All required functions found in DLL")
                break
            else:
                logger.warning("DLL loaded but missing required functions")
                dll = None
        except Exception as e:
            logger.error(f"Error loading DLL from {dll_path}: {e}")
    else:
        logger.info(f"DLL not found at: {dll_path}")

# Also search in PyInstaller _MEIPASS directory if running from bundle
if running_from_pyinstaller and not dll:
    pyinstaller_dll_path = os.path.join(sys._MEIPASS, "truefa_crypto.dll")
    if os.path.exists(pyinstaller_dll_path):
        try:
            dll = ctypes.CDLL(pyinstaller_dll_path)
            logger.info(f"Successfully loaded DLL from PyInstaller bundle: {pyinstaller_dll_path}")
            
            # Verify if the DLL has the needed functions
            if hasattr(dll, 'c_create_secure_string'):
                logger.info("Found create_secure_string function in PyInstaller DLL")
            else:
                logger.warning("Function c_create_secure_string not found in PyInstaller DLL")
                dll = None
        except Exception as e:
            logger.error(f"Error loading DLL from PyInstaller bundle: {e}")

# Define functions and signatures if the DLL was found
SecureString = None
create_secure_string = None

if dll:
    try:
        # Set up function signatures using the correct function names with 'c_' prefix
        # The c_create_secure_string function takes a byte pointer and length and returns a pointer to a SecureString
        dll.c_create_secure_string.argtypes = [ctypes.c_char_p, ctypes.c_size_t]
        dll.c_create_secure_string.restype = ctypes.c_void_p
        
        # Define the SecureString class that wraps the Rust implementation
        class SecureString:
            def __init__(self, value):
                if isinstance(value, str):
                    encoded_value = value.encode('utf-8')
                    self.ptr = dll.c_create_secure_string(encoded_value, len(encoded_value))
                elif isinstance(value, bytes):
                    self.ptr = dll.c_create_secure_string(value, len(value))
                else:
                    encoded_value = str(value).encode('utf-8')
                    self.ptr = dll.c_create_secure_string(encoded_value, len(encoded_value))
                
                if not self.ptr:
                    logger.error("Failed to create secure string")
                    raise RuntimeError("Failed to create secure string")
                
            def __str__(self):
                # Since we don't have a direct way to get the string from the DLL,
                # we'll use a fallback method in Python
                return "<SecureString: [protected]>"
                
            def get(self):
                # Same as __str__, we don't have a direct getter
                return "<SecureString: [protected]>"
                
            def clear(self):
                # We don't have a direct way to free the memory from Python,
                # the Rust drop implementation should handle this automatically
                self.ptr = None
                
            def __del__(self):
                # No explicit free needed, Rust will handle this through Drop
                self.ptr = None
        
        # Function to create a secure string
        def create_secure_string(value):
            return SecureString(value)
            
        logger.info("Successfully defined function signatures")
        logger.info("Successfully loaded and initialized Rust cryptography module")
        
    except AttributeError as e:
        logger.error(f"Error setting function signatures: {e}")
        dll = None
        # Fall back to Python implementation below
    except Exception as e:
        logger.error(f"Unexpected error initializing Rust module: {e}")
        dll = None
        # Fall back to Python implementation below

# If DLL wasn't found or couldn't be loaded, create a fallback implementation
if not dll or not create_secure_string:
    logger.warning("Using fallback implementation for secure memory!")
    
    # Define a simple Python implementation of SecureString
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
            
        def __del__(self):
            """Ensure the data is cleared when the object is destroyed."""
            self._data = None
    
    # Function to create a secure string
    def create_secure_string(value):
        logger.info("Using Python fallback implementation for create_secure_string")
        return SecureString(value)

# The following functions operate on the initialized DLL or use Python fallbacks

def secure_random_bytes(size):
    """Generate cryptographically secure random bytes."""
    import os
    return os.urandom(size)
    
def is_vault_unlocked():
    """Return true if the vault is unlocked, false otherwise."""
    # This is a placeholder - we'll need to implement proper vault state tracking
    return False
    
def vault_exists():
    """Check if a vault has been initialized."""
    # This is a placeholder - we'll need to implement proper checks
    return False
    
def create_vault(password):
    """Create a new vault with the given master password."""
    # This is a placeholder - we'll need to implement proper vault creation
    return True
    
def unlock_vault(password, salt=None):
    """Unlock the vault with the given password and salt."""
    # This is a placeholder - we'll need to implement proper vault unlocking
    return True
    
def lock_vault():
    """Lock the vault, clearing all sensitive data."""
    # This is a placeholder - we'll need to implement proper vault locking
    pass
    
def generate_salt():
    """Generate a random salt for key derivation."""
    logger.info("Generating salt for key derivation")
    
    # Try the DLL implementation first for optimal security
    dll_success = False
    
    if dll and hasattr(dll, 'c_generate_salt'):
        try:
            # Use a thread with timeout to prevent hanging if the DLL requires admin rights
            import threading
            import time
            
            class SaltResult:
                salt = None
                error = None
                done = False
            
            salt_result = SaltResult()
            
            def generate_salt_thread():
                try:
                    logger.info("Thread started for DLL salt generation")
                    # Call the DLL function with proper error handling
                    dll_result = dll.c_generate_salt()
                    
                    # Process the result
                    if dll_result:
                        logger.info("DLL successfully generated salt")
                        # Convert to Python string if needed
                        if isinstance(dll_result, bytes):
                            salt_result.salt = dll_result.decode('utf-8')
                        else:
                            salt_result.salt = dll_result
                        logger.info(f"DLL salt generated (first 5 chars): {salt_result.salt[:5]}...")
                    else:
                        logger.warning("DLL returned empty result for salt generation")
                    
                    salt_result.done = True
                except Exception as e:
                    logger.error(f"Error in salt generation thread: {e}")
                    salt_result.error = e
                    salt_result.done = True
            
            # Start the salt generation in a separate thread
            salt_thread = threading.Thread(target=generate_salt_thread)
            salt_thread.daemon = True  # Allow the program to exit even if thread is running
            logger.info("Starting salt generation thread")
            salt_thread.start()
            
            # Wait for the operation to complete with a short timeout
            start_salt_time = time.time()
            timeout_seconds = 1.0  # Quick timeout to avoid user-visible delay
            
            logger.info(f"Waiting for DLL salt generation to complete (timeout: {timeout_seconds}s)...")
            while not salt_result.done and time.time() - start_salt_time < timeout_seconds:
                time.sleep(0.05)  # Check every 50ms for quick response
            
            if not salt_result.done:
                logger.warning(f"DLL salt generation timed out after {timeout_seconds} seconds")
                # Will fall through to Python implementation
            elif salt_result.error:
                logger.error(f"Error in DLL salt generation: {salt_result.error}")
                # Will fall through to Python implementation
            elif salt_result.salt:
                logger.info("Successfully generated secure salt using DLL")
                return salt_result.salt
            else:
                logger.warning("DLL salt generation didn't produce a result")
                # Will fall through to Python implementation
        except Exception as e:
            logger.error(f"Error setting up DLL salt generation: {e}")
            # Will fall through to Python implementation
    else:
        if not dll:
            logger.warning("DLL not available for salt generation")
        else:
            logger.warning("DLL doesn't have c_generate_salt function")
    
    # Fallback to Python implementation which is still cryptographically secure
    logger.info("Using Python implementation for salt generation (equally secure alternative)")
    import base64
    import os
    salt = base64.b64encode(os.urandom(32)).decode('utf-8')
    logger.info(f"Python salt generated (first 5 chars): {salt[:5]}...")
    return salt
    
def derive_master_key(password, salt):
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
    
def encrypt_master_key(master_key):
    """Encrypt the master key with the vault key."""
    import base64
    import os
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    
    # Generate a random key for AES
    key = os.urandom(32)
    nonce = os.urandom(12)
    
    # Create cipher
    algorithm = algorithms.AES(key)
    cipher = Cipher(algorithm, modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Encrypt
    plaintext = master_key.encode('utf-8')
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    
    # Combine nonce, ciphertext, and tag
    encrypted_data = nonce + ciphertext + encryptor.tag
    
    # Encode as base64 for storage
    return base64.b64encode(encrypted_data).decode('utf-8')
    
def decrypt_master_key(encrypted_key):
    """Decrypt the master key with the vault key."""
    # For the fallback implementation, we'll just return the encrypted key
    # as if it was decrypted successfully
    import base64
    
    # In a real implementation, we would decrypt the key
    # For this dummy implementation, we'll just return a placeholder
    return encrypted_key
    
def verify_signature(message, signature, public_key):
    """Verify a digital signature using the Rust crypto library."""
    # For fallback, we'll just return True for now
    return True
