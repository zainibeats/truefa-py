import os
import sys
import platform
from pathlib import Path

# Application information
APP_NAME = "TrueFA"
APP_VERSION = "1.0.0"

# Determine the correct data directory based on platform
def get_data_directory():
    """Get the appropriate directory for storing application data"""
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

# Application directories
DATA_DIR = get_data_directory()
VAULT_FILE = os.path.join(DATA_DIR, "vault.dat")
EXPORTS_DIR = os.path.join(DATA_DIR, "exports")
TEMP_DIR = os.path.join(DATA_DIR, "temp")

# Create necessary directories
os.makedirs(EXPORTS_DIR, exist_ok=True)
os.makedirs(TEMP_DIR, exist_ok=True)

# Crypto configuration
USE_RUST_CRYPTO = True  # Set to False to force Python implementation
DLL_NAME = "truefa_crypto.dll" if platform.system() == "Windows" else "libtruefa_crypto.so"

# Get the DLL path - check multiple locations
def get_dll_path():
    """Get the path to the crypto DLL/shared library"""
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