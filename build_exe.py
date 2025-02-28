#!/usr/bin/env python3
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

def check_requirements():
    """Check if all requirements for building the executable are met."""
    
    # Check if PyInstaller is installed
    try:
        import pyinstaller
        print("PyInstaller is installed")
    except ImportError:
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

def build_executable():
    """Build the executable using PyInstaller."""
    
    print("Building TrueFA executable...")
    
    # Find all the necessary Rust DLL files
    rust_dll = None
    rust_dll_paths = [
        Path("truefa_crypto") / "truefa_crypto.dll",
        Path("rust_crypto") / "target" / "release" / "truefa_crypto.dll"
    ]
    
    for path in rust_dll_paths:
        if path.exists():
            rust_dll = path
            break
    
    if not rust_dll:
        print("Error: Rust library DLL not found")
        return False
    
    print(f"Found Rust DLL at: {rust_dll}")
    
    # Define PyInstaller command with explicit binary includes
    pyinstaller_cmd = [
        sys.executable, "-m", "pyinstaller",
        "--onefile",  # Create a single executable
        "--name", "truefa",
        # Add the compiled Rust library explicitly
        "--add-binary", f"{rust_dll}{os.pathsep}.",
        # Add data files
        "--add-data", f"truefa_crypto{os.pathsep}truefa_crypto",
        # Hidden imports to ensure all dependencies are included
        "--hidden-import", "cryptography",
        "main.py"  # Main script to execute
    ]
    
    # Run PyInstaller
    try:
        subprocess.run(pyinstaller_cmd, check=True)
        print(f"Executable built successfully: {os.path.join('dist', 'truefa.exe' if os.name == 'nt' else 'truefa')}")
        return True
    except subprocess.SubprocessError as e:
        print(f"Error: Failed to build executable: {e}")
        return False

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
