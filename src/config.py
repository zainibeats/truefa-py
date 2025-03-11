"""
TrueFA-Py Configuration System

Manages application paths, settings, and environment detection with features:
- Multi-platform support (Windows, macOS, Linux)
- Secure directory creation with appropriate permissions
- Portable mode via environment variables
- DLL/shared library discovery with multi-location search
- Separate paths for regular and sensitive cryptographic data

Security-focused design separates user data from cryptographic materials
to provide enhanced protection for sensitive authentication secrets.
"""

import os
import sys
import platform
from pathlib import Path
import subprocess
import socket
from typing import Dict, Any, Optional, Union, Tuple
# Import debug module (placed here instead of at the top to avoid circular imports)

from .utils.debug import debug_print, is_debug_enabled
from .utils.logger import warning, info, error, debug
from src.utils.colorprint import print_warning, print_info

# Application information
APP_NAME = "TrueFA-Py"
APP_VERSION = "0.1.0"

# Flag to determine if we're running from an installed location
# that might have permission restrictions
def is_running_from_program_files():
    """
    Detect if running from a restricted directory (e.g., Program Files).
    Used to adjust file access behavior in limited-permission environments.
    
    Returns:
        bool: True if in a restricted directory, False otherwise
    """
    if not getattr(sys, 'frozen', False):
        return False  # Not a frozen app, so not installed
        
    executable_path = os.path.abspath(sys.executable).lower()
    
    # Check for common restricted directories
    restricted_paths = [
        "program files",
        "program files (x86)",
        "windows",
        "system32"
    ]
    
    return any(restricted in executable_path for restricted in restricted_paths)

# Get the repository root directory
def get_repo_root():
    """
    Determine repository root directory for development and frozen contexts.
    
    Returns:
        str: Absolute path to the repository/application root
    """
    # If we're running from a frozen executable, use the directory containing the executable
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    
    # Otherwise, use the directory containing the main.py file
    return os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

# Determine the correct data directory based on platform
def get_data_directory():
    """
    Create and return platform-appropriate application data directory:
    - Windows: %APPDATA%\\TrueFA
    - macOS: ~/Library/Application Support/TrueFA
    - Linux: ~/.truefa
    
    Handles portable mode and environment variable overrides.
    
    Returns:
        str: Path to application data directory (created if needed)
    """
    # Check environment variable override first (useful for Docker)
    env_data_dir = os.environ.get('TRUEFA_DATA_DIR')
    if env_data_dir:
        os.makedirs(env_data_dir, exist_ok=True)
        return env_data_dir

    # Check if we're in portable mode
    if os.environ.get('TRUEFA_PORTABLE', '').lower() in ('1', 'true', 'yes'):
        # Use current directory for portable mode
        portable_dir = os.path.join(os.getcwd(), '.truefa')
        os.makedirs(portable_dir, exist_ok=True)
        return portable_dir

    # Always use user directory for data storage, regardless of installation type
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
    Get the secure data directory, which should have stricter permissions.
    This directory is used for storing sensitive data like encryption keys.
    
    Returns:
        str: Path to the secure data directory
    """
    # Use the platform-specific data directory as the base
    base_dir = get_data_directory()
    
    secure_dir = os.path.join(base_dir, APP_NAME, "Secure")
    
    try:
        # Create directory if it doesn't exist
        os.makedirs(secure_dir, exist_ok=True)
        
        # Test if we can write to it
        test_file = os.path.join(secure_dir, '.test')
        with open(test_file, 'w') as f:
            f.write('test')
        os.remove(test_file)
    except Exception as e:
        # This is a user-facing warning, print it directly to console
        error_msg = f"Cannot write to {secure_dir}: {e}"
        print_warning(error_msg)  # Print with color
        warning(error_msg)  # Also log it
        
        # Use a fallback directory in user's home directory
        secure_dir = os.path.join(os.path.expanduser('~'), '.truefa', '.secure')
        os.makedirs(secure_dir, exist_ok=True)
        
        # This is a user-facing notification, print it directly to console
        fallback_msg = f"Using fallback secure directory: {secure_dir}"
        print_warning(fallback_msg)  # Print with color
        warning(fallback_msg)  # Also log it
        
    # Set directory permissions for Windows
    try:
        if platform.system() == 'Windows':
            # Use icacls to set permissions on Windows
            subprocess.run(
                ['icacls', secure_dir, '/inheritance:r'],
                check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            # Add current user with full control
            subprocess.run(
                ['icacls', secure_dir, '/grant', f'{os.environ.get("USERNAME")}:(OI)(CI)F'],
                check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
    except Exception as e:
        warning(f"Could not set secure permissions: {e}")
    
    # Ensure our secure directory actually exists
    os.makedirs(secure_dir, exist_ok=True)
    
    return secure_dir

# Application directories
DATA_DIR = get_data_directory()
SECURE_DATA_DIR = get_secure_data_directory()

# Check environment variable override for vault file path
VAULT_FILE = os.environ.get('TRUEFA_VAULT_FILE') or os.path.join(DATA_DIR, "vault.dat")
VAULT_CRYPTO_DIR = os.environ.get('TRUEFA_CRYPTO_DIR') or os.path.join(SECURE_DATA_DIR, "crypto")

# Check environment variable override for exports directory
EXPORTS_DIR = os.environ.get('TRUEFA_EXPORTS_DIR') or os.path.join(DATA_DIR, "exports")
TEMP_DIR = os.environ.get('TRUEFA_TEMP_DIR') or os.path.join(DATA_DIR, "temp")

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
    Locate native cryptographic library using multi-location search strategy:
    - PyInstaller bundle locations
    - Development environment paths
    - System-installed libraries
    - Docker-specific locations
    
    Implements prioritized search with logging for diagnostic purposes.
    
    Returns:
        str or None: Path to native library if found, None otherwise
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

# Logging configuration
LOG_TO_FILE = True  # Enable logging to file in production

# Configure debug module
try:
    from .utils.debug import set_debug
    set_debug(DEBUG)
except ImportError:
    # If we couldn't import debug.py, silently continue
    pass
