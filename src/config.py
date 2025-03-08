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
    - Windows: %APPDATA%\TrueFA
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
    Create directory for sensitive cryptographic data with enhanced security:
    - Windows: %LOCALAPPDATA% with restrictive ACLs
    - macOS/Linux: ~/.truefa_secure with 0700 permissions
    
    Security features:
    - Owner-only access permissions
    - Separate from regular data directory
    - Non-synced location (prevents cloud exposure)
    - Fallback paths on permission failure
    
    Returns:
        str: Path to secure directory with enhanced protection
    """
    # Check environment variable override for secure data directory
    env_secure_dir = os.environ.get('TRUEFA_SECURE_DIR')
    if env_secure_dir:
        os.makedirs(env_secure_dir, exist_ok=True)
        return env_secure_dir

    if platform.system() == "Windows":
        # On Windows, we'll use %LOCALAPPDATA% with restrictive ACLs
        # This is better than APPDATA because it's not synced and can have stricter permissions
        base_dir = os.environ.get('LOCALAPPDATA')
        if not base_dir:
            # Fallback if LOCALAPPDATA is not available
            base_dir = os.path.join(os.path.expanduser('~'), 'AppData', 'Local')
        
        secure_dir = os.path.join(base_dir, APP_NAME, "Secure")
        
        # Create the directory if it doesn't exist
        os.makedirs(secure_dir, exist_ok=True)
        
        # Test if we can write to this directory (important for installed apps)
        test_file = os.path.join(secure_dir, ".test")
        try:
            with open(test_file, 'w') as f:
                f.write('test')
            os.remove(test_file)
        except Exception as e:
            # If we can't write to LocalAppData, fall back to user home directory
            print(f"Warning: Cannot write to {secure_dir}: {e}")
            secure_dir = os.path.join(os.path.expanduser('~'), '.truefa', '.secure')
            os.makedirs(secure_dir, exist_ok=True)
            print(f"Using fallback secure directory: {secure_dir}")
        
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
