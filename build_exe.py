#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Build script for TrueFA terminal application.
This script creates a standalone executable using PyInstaller.

Requirements:
- PyInstaller
- A successfully built Rust crypto module
"""

import os
import subprocess
import sys
from pathlib import Path
import importlib.util

def check_requirements():
    """Check if all requirements for building the executable are met."""
    
    # Check if PyInstaller is installed
    if not is_pyinstaller_installed():
        print("Installing PyInstaller...")
        try:
            subprocess.run(
                [sys.executable, "-m", "pip", "install", "pyinstaller"],
                check=True
            )
            print("PyInstaller installed successfully")
        except subprocess.SubprocessError:
            print("Error: Failed to install PyInstaller")
            return False
    
    # Check if the Rust module was built
    module_path = Path("truefa_crypto")
    dll_path = Path("truefa_crypto") / "truefa_crypto.dll" if os.name == "nt" else Path("truefa_crypto") / "truefa_crypto.so"
    pyd_path = Path("truefa_crypto") / "truefa_crypto.pyd"
    
    if not module_path.exists():
        print("Error: truefa_crypto module directory not found")
        return False
        
    if not (dll_path.exists() or pyd_path.exists()):
        print("Error: Rust module binaries not found")
        print("Please run build_rust.py first to build the Rust module")
        return False
    
    return True

def is_pyinstaller_installed():
    """Check if PyInstaller is installed."""
    return importlib.util.find_spec("PyInstaller") is not None

def build_executable():
    """
    Build the executable using PyInstaller.
    """
    try:
        # Check if PyInstaller is available
        import PyInstaller
    except ImportError:
        print("PyInstaller is required to build the executable. Please install it with 'pip install pyinstaller'.")
        return False

    from pathlib import Path
    import os
    import shutil
    import tempfile
    
    # Ensure build directory exists
    build_dir = Path("build/truefa")
    build_dir.mkdir(parents=True, exist_ok=True)
    
    # First, find our Rust DLL
    rust_dll_path = None
    possible_dll_paths = [
        Path("truefa_crypto/truefa_crypto.dll"),
        Path("rust_crypto/target/release/truefa_crypto.dll"),
    ]
    
    for path in possible_dll_paths:
        if path.exists():
            rust_dll_path = path
            print(f"Found Rust DLL at: {rust_dll_path}")
            break
    
    if not rust_dll_path:
        print("ERROR: Rust DLL not found! Run build_rust.py first.")
        return False
            
    # Create the PyInstaller command
    pyinstaller_cmd = [
        'main.py',  # The main script to be converted to an executable
        '--name=truefa',  # Name of the output executable
        '--onefile',  # Create a single executable
        # '--windowed',  # Removed to show the console window
        '--clean',  # Clean PyInstaller cache before building
        '--log-level=WARN',  # Set log level to reduce output noise
    ]
    
    # Add necessary hidden imports
    pyinstaller_cmd.extend([
        '--hidden-import=cryptography',
        '--hidden-import=pyotp',
        '--hidden-import=opencv-python',
        '--hidden-import=PIL',  # Pillow
        '--hidden-import=PIL._imagingtk',
        '--hidden-import=PIL._tkinter_finder',
    ])
    
    # Add Rust DLL and other data files
    pyinstaller_cmd.extend([
        f'--add-data={rust_dll_path}{os.pathsep}.',  # Add Rust DLL to the executable
        f'--add-data=images{os.pathsep}images',  # Add images directory 
    ])
    
    # Create the dist directory and images folder if they don't exist
    dist_dir = Path("dist")
    dist_dir.mkdir(exist_ok=True)
    
    images_dir = dist_dir / "images"
    images_dir.mkdir(exist_ok=True)
    
    # Run PyInstaller using the subprocess module
    print("Building TrueFA executable...")
    try:
        # Use subprocess.run with capture_output to get detailed error messages
        result = subprocess.run(
            [sys.executable, "-m", "PyInstaller"] + pyinstaller_cmd, 
            check=False,
            capture_output=True,
            text=True
        )
        
        if result.returncode == 0:
            print("Executable built successfully: dist/truefa.exe")
            print("Build completed successfully")
        else:
            print(f"Error building executable: {result.returncode}")
            print("STDOUT:")
            print(result.stdout)
            print("STDERR:")
            print(result.stderr)
            print("Build failed")
            
    except Exception as e:
        print(f"Exception during build: {str(e)}")
        print("Build failed")
    return True

if __name__ == "__main__":
    if check_requirements():
        if build_executable():
            print("Build completed successfully")
        else:
            print("Build failed")
            sys.exit(1)
    else:
        print("Build failed: Requirements not met")
        sys.exit(1)
