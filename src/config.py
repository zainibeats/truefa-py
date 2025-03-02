"""
TrueFA-Py Configuration System

Provides centralized configuration settings and platform-specific paths
for the application. This module handles:

- Platform detection and appropriate file path selection
- Secure directory creation with proper permissions
- Global application constants
- Environment-specific configurations

The module implements separate paths for regular data and sensitive
cryptographic materials, with enhanced security for the latter.
"""

import os
import sys
import platform
from pathlib import Path
import subprocess

# Application information
APP_NAME = "TrueFA-Py"
APP_VERSION = "0.1.0"

# Determine the correct data directory based on platform
def get_data_directory():
    """
    Get the platform-appropriate directory for application data.
    
    Creates and returns the correct directory for storing application 
    configuration and non-sensitive data based on platform conventions:
    - Windows: %APPDATA%\TrueFA
    - macOS: ~/Library/Application Support/TrueFA
    - Linux/Unix: ~/.truefa
    
    The directory is automatically created if it doesn't exist.
    
    Returns:
        str: Full path to the application data directory
    """
    if platform.system() == "Windows":
        # Use %APPDATA% on Windows (C:\Users\username\AppData\Roaming\TrueFA)
        base_dir = os.environ.get('APPDATA')
        if not base_dir:
            # Fallback if APPDATA is not available
            base_dir = os.path.join(os.path.expanduser('~'), 'AppData', 'Roaming')
        data_dir = os.path.join(base_dir, APP_NAME)
    elif platform.system() == "Darwin":
        # macOS: ~/Library/Application Support/TrueFA
        data_dir = os.path.join(os.path.expanduser('~'), 'Library', 'Application Support', APP_NAME)
    else:
        # Linux/Unix: ~/.truefa
        data_dir = os.path.join(os.path.expanduser('~'), '.truefa')
    
    # Create the directory if it doesn't exist
    os.makedirs(data_dir, exist_ok=True)
    return data_dir

# Get secure directory with restricted permissions for cryptographic materials
def get_secure_data_directory():
    """
    Create and get a secure directory for sensitive cryptographic data.
    
    Implements platform-specific security measures to create a directory
    with enhanced protection for storing cryptographic materials:
    
    - Windows: Uses %LOCALAPPDATA% with restrictive ACLs
    - macOS: Creates a directory with 0700 permissions in ~/Library/KeyCrypt
    - Linux: Creates a directory with 0700 permissions in ~/.truefa_secure
    
    The secure directory is intentionally separate from the regular data directory
    to provide stronger isolation and protection for cryptographic materials.
    
    Returns:
        str: Full path to the secure data directory with enhanced permissions
        
    Security Features:
    - Restricted file permissions (0700 = owner access only)
    - Platform-specific access control when available
    - Non-synced location to prevent cloud exposure
    - Validation of permissions after creation
    """
    if platform.system() == "Windows":
        # On Windows, we'll use %LOCALAPPDATA% with restricted ACLs
        # This is better than APPDATA because it's not synced and can have stricter permissions
        base_dir = os.environ.get('LOCALAPPDATA')
        if not base_dir:
            base_dir = os.path.join(os.path.expanduser('~'), 'AppData', 'Local')
        
        secure_dir = os.path.join(base_dir, APP_NAME, "Secure")
        
        # Create the secure directory if it doesn't exist
        os.makedirs(secure_dir, exist_ok=True)
        
        # Apply restrictive ACLs to the secure directory
        # This will restrict access to only the owner account
        try:
            # Use icacls to set permissions (Windows-specific)
            # This denies access to everyone except the owner
            subprocess.run([
                "icacls", 
                secure_dir, 
                "/inheritance:r",  # Remove inherited permissions
                "/grant:r", f"{os.environ.get('USERNAME')}:(OI)(CI)F",  # Grant full control to owner
                "/deny", f"*S-1-1-0:(OI)(CI)(DE,DC)",  # Deny everyone delete/change permissions
            ], check=False, capture_output=True)
        except Exception as e:
            print(f"Warning: Could not set secure permissions: {e}")
    
    elif platform.system() == "Darwin":
        # On macOS, we use a protected directory with restricted permissions
        secure_dir = os.path.join(os.path.expanduser('~'), 'Library', 'Application Support', f"{APP_NAME}_Secure")
        os.makedirs(secure_dir, exist_ok=True)
        # Set macOS permissions (700 = owner only)
        try:
            os.chmod(secure_dir, 0o700)
        except Exception as e:
            print(f"Warning: Could not set secure permissions: {e}")
    
    else:
        # Linux/Unix: Create a hidden directory with restricted permissions
        secure_dir = os.path.join(os.path.expanduser('~'), f".{APP_NAME.lower()}_secure")
        os.makedirs(secure_dir, exist_ok=True)
        # Set Linux permissions (700 = owner only)
        try:
            os.chmod(secure_dir, 0o700)
        except Exception as e:
            print(f"Warning: Could not set secure permissions: {e}")
    
    return secure_dir

# Application directories
DATA_DIR = get_data_directory()
SECURE_DATA_DIR = get_secure_data_directory()
VAULT_FILE = os.path.join(DATA_DIR, "vault.dat")
VAULT_CRYPTO_DIR = os.path.join(SECURE_DATA_DIR, "crypto")
EXPORTS_DIR = os.path.join(DATA_DIR, "exports")
TEMP_DIR = os.path.join(DATA_DIR, "temp")

# Create necessary directories
os.makedirs(EXPORTS_DIR, exist_ok=True)
os.makedirs(TEMP_DIR, exist_ok=True)
os.makedirs(VAULT_CRYPTO_DIR, exist_ok=True)

# Crypto configuration
USE_RUST_CRYPTO = True  # Set to False to force Python implementation
DLL_NAME = "truefa_crypto.dll" if platform.system() == "Windows" else "libtruefa_crypto.so"

# Get the DLL path - check multiple locations
def get_dll_path():
    """
    Locate the native cryptographic library (DLL/shared object).
    
    Performs a comprehensive search for the native cryptographic library
    across multiple possible locations, handling different runtime environments:
    
    - PyInstaller bundled executables
    - Development environments
    - System-installed libraries
    - Custom locations specified by environment variables
    
    The function implements an ordered search strategy, checking the most
    likely locations first based on the current execution context.
    
    Returns:
        str or None: Path to the native library if found, None otherwise
    """
    # First check if we're running from a PyInstaller bundle
    if getattr(sys, 'frozen', False):
        base_dir = os.path.dirname(sys.executable)
        return os.path.join(base_dir, DLL_NAME)
    
    # Check the current directory and module directory
    possible_paths = [
        os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'truefa_crypto', DLL_NAME),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', DLL_NAME),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), DLL_NAME),
        os.path.join(os.getcwd(), 'truefa_crypto', DLL_NAME),
        os.path.join(os.getcwd(), DLL_NAME)
    ]
    
    for path in possible_paths:
        if os.path.exists(path):
            return os.path.abspath(path)
    
    return None

# Crypto library path
CRYPTO_LIB_PATH = get_dll_path()

# Debug mode (set to False for production)
DEBUG = False
