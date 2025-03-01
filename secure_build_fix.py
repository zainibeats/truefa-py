#!/usr/bin/env python
"""
Enhanced TrueFA Build Script with Cryptographic Module Verification

This script builds the TrueFA executable with the following security enhancements:
1. Verifies and validates the Rust cryptographic DLL
2. Automatically configures fallback to Python implementation if needed
3. Creates a secure executable with appropriate dependencies
"""

import os
import sys
import shutil
import subprocess
from pathlib import Path
import ctypes
import platform
import importlib.util

# Configuration
APP_NAME = "TrueFA"
APP_VERSION = "1.0.0"
CONSOLE_MODE = True
ICON_PATH = None  # Set to path of icon file if available

def check_pyinstaller():
    """Check if PyInstaller is installed and get its path."""
    try:
        # Try to import PyInstaller
        spec = importlib.util.find_spec("PyInstaller")
        if spec is None:
            print("ERROR: PyInstaller not found in Python environment")
            print("Please install it with 'pip install pyinstaller'")
            return False, None
        
        # Get PyInstaller path
        pyinstaller_pkg_path = os.path.dirname(spec.origin)
        print(f"PyInstaller found at: {pyinstaller_pkg_path}")
        
        # Find the actual executable
        python_path = sys.executable
        python_dir = os.path.dirname(python_path)
        
        possible_locations = [
            os.path.join(python_dir, "pyinstaller.exe"),  # Windows
            os.path.join(python_dir, "Scripts", "pyinstaller.exe"),  # Windows with Scripts dir
            os.path.join(python_dir, "pyinstaller"),  # Unix-like
            os.path.join(python_dir, "bin", "pyinstaller"),  # Unix-like with bin dir
        ]
        
        for loc in possible_locations:
            if os.path.exists(loc):
                print(f"PyInstaller executable found at: {loc}")
                return True, loc
        
        # If we can't find the executable but the package exists,
        # we'll use python -m PyInstaller instead
        print("PyInstaller package found, but executable not found in expected locations")
        print("Will use 'python -m PyInstaller' instead")
        return True, None
        
    except Exception as e:
        print(f"ERROR checking for PyInstaller: {e}")
        return False, None

def check_rust_dll():
    """Check if the Rust DLL exists and has the required exports."""
    possible_dll_locations = [
        # Current directory
        os.path.join(os.getcwd(), "truefa_crypto.dll"),
        # Direct path
        os.path.join("truefa_crypto", "truefa_crypto.dll"), 
        # Source directory
        os.path.join("src", "truefa_crypto", "truefa_crypto.dll"),
        # Build directory
        os.path.join("rust_crypto", "target", "release", "truefa_crypto.dll"),
    ]
    
    # Try each potential location
    for dll_path in possible_dll_locations:
        print(f"Checking for DLL at {dll_path}")
        if os.path.exists(dll_path):
            print(f"Found DLL at {dll_path}")
            try:
                # Load the DLL
                lib = ctypes.CDLL(dll_path)
                
                # Define the list of required functions
                required_functions = [
                    'c_secure_random_bytes',
                    'c_is_vault_unlocked',
                    'c_vault_exists',
                    'c_create_vault',
                    'c_unlock_vault',
                    'c_lock_vault',
                    'c_generate_salt',
                    'c_derive_master_key',
                    'c_encrypt_master_key',
                    'c_decrypt_master_key',
                    'c_verify_signature',
                    'c_create_secure_string'
                ]
                
                # Check all required functions
                missing_functions = []
                for func_name in required_functions:
                    if not hasattr(lib, func_name):
                        missing_functions.append(func_name)
                
                if missing_functions:
                    print(f"WARNING: The following functions are missing in the DLL: {', '.join(missing_functions)}")
                    return False, dll_path, missing_functions
                else:
                    print("All required functions found in the DLL!")
                    
                    # Ensure DLL is in both root truefa_crypto and src/truefa_crypto
                    src_dll_path = os.path.join("src", "truefa_crypto", "truefa_crypto.dll")
                    if os.path.abspath(dll_path) != os.path.abspath(src_dll_path):
                        print(f"Copying DLL to {src_dll_path}")
                        os.makedirs(os.path.dirname(src_dll_path), exist_ok=True)
                        shutil.copy2(dll_path, src_dll_path)
                    
                    root_dll_path = os.path.join("truefa_crypto", "truefa_crypto.dll")
                    if os.path.abspath(dll_path) != os.path.abspath(root_dll_path):
                        print(f"Copying DLL to {root_dll_path}")
                        os.makedirs(os.path.dirname(root_dll_path), exist_ok=True)
                        shutil.copy2(dll_path, root_dll_path)
                    
                    return True, dll_path, []
                    
            except Exception as e:
                print(f"Error loading DLL: {e}")
    
    print("No valid DLL found")
    return False, None, ["DLL not found"]

def setup_environment(use_fallback):
    """Set up environment variables for the build."""
    if use_fallback:
        print("Configuring build to use Python fallback implementation")
        os.environ["TRUEFA_USE_FALLBACK"] = "true"
        
        # Create or update .env file
        with open(".env", "w") as f:
            f.write("TRUEFA_USE_FALLBACK=true\n")
            
        print("Created .env file with fallback configuration")
    else:
        print("Configuring build to use Rust crypto implementation")
        os.environ["TRUEFA_USE_FALLBACK"] = "false"
        
        # Update .env file
        with open(".env", "w") as f:
            f.write("TRUEFA_USE_FALLBACK=false\n")
        
        print("Updated .env file to use Rust implementation")

def build_executable(dll_path=None, pyinstaller_path=None):
    """Build the executable using PyInstaller."""
    
    # Basic command
    if pyinstaller_path:
        cmd = [
            pyinstaller_path,
            "--onefile",
            "--name", APP_NAME,
            "--clean",
        ]
    else:
        # Use the module version if no direct executable
        cmd = [
            sys.executable,
            "-m", "PyInstaller",
            "--onefile",
            "--name", APP_NAME,
            "--clean",
        ]
    
    # Add console or windowed mode
    if CONSOLE_MODE:
        cmd.append("--console")
    else:
        cmd.append("--windowed")
    
    # Add icon if specified
    if ICON_PATH and os.path.exists(ICON_PATH):
        cmd.extend(["--icon", ICON_PATH])
    
    # Add DLL if available
    if dll_path and os.path.exists(dll_path):
        # Add the DLL as a binary
        cmd.extend(["--add-binary", f"{dll_path};."])
    
    # Add the main script
    cmd.append("main.py")
    
    # Run PyInstaller
    print("Running PyInstaller with command:", " ".join(cmd))
    result = subprocess.run(cmd, check=False)
    
    if result.returncode != 0:
        print(f"ERROR: PyInstaller failed with return code {result.returncode}")
        return False
    else:
        print("PyInstaller completed successfully")
        return True

def main():
    """Main build process with Rust DLL verification."""
    print("=" * 80)
    print(f"TrueFA Secure Build Process - v{APP_VERSION}")
    print("=" * 80)
    
    # Check if PyInstaller is installed
    pyinstaller_installed, pyinstaller_path = check_pyinstaller()
    if not pyinstaller_installed:
        return 1
    
    # Check for Rust DLL
    dll_valid, dll_path, missing_functions = check_rust_dll()
    
    if dll_valid:
        print("✅ Rust DLL validation passed")
        use_fallback = False
    else:
        if dll_path:
            print(f"⚠️ Rust DLL validation failed: Missing functions {missing_functions}")
        else:
            print("⚠️ Rust DLL not found")
        
        print("Will use Python fallback implementation")
        use_fallback = True
    
    # Ask for confirmation
    if use_fallback:
        print("\n" + "!" * 80)
        print("WARNING: Building with Python fallback implementation")
        print("This may have performance and security implications")
        print("!" * 80 + "\n")
        
        response = input("Proceed with fallback implementation? (y/n): ").lower()
        if response != 'y':
            print("Build aborted by user")
            return 1
    
    # Setup environment
    setup_environment(use_fallback)
    
    # Build executable
    print("\nBuilding executable...")
    if build_executable(None if use_fallback else dll_path, pyinstaller_path):
        print("\n" + "=" * 80)
        print("✅ Build completed successfully!")
        print(f"Executable created: dist/{APP_NAME}.exe")
        print("=" * 80)
        
        if use_fallback:
            print("\n⚠️ NOTE: Using Python fallback implementation for cryptography")
            print("    For optimal security, rebuild the Rust crypto library")
        
        return 0
    else:
        print("\n" + "=" * 80)
        print("❌ Build failed")
        print("=" * 80)
        return 1

if __name__ == "__main__":
    sys.exit(main())
