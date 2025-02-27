#!/usr/bin/env python3
"""
Build script for the Rust crypto module.

This script handles the compilation of the Rust cryptographic module and sets up
the necessary Python bindings. It performs the following steps:
1. Verifies Rust toolchain is installed
2. Builds the Rust library in release mode
3. Sets up proper Python module structure for the compiled library

Note: This script is for development only and is not needed in production.
"""

import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

def check_rust_installed():
    """
    Check if Rust toolchain is installed and available.
    
    Returns:
        bool: True if Rust is installed, False otherwise
    """
    try:
        subprocess.run(["rustc", "--version"], check=True, capture_output=True)
        return True
    except (subprocess.SubprocessError, FileNotFoundError):
        return False

def build_rust_module():
    """
    Build the Rust crypto module and set up Python bindings.
    
    This function:
    1. Verifies Rust installation
    2. Builds the Rust library in release mode
    3. Calls build_module.py to create proper Python bindings
    
    Returns:
        bool: True if build succeeds, False otherwise
    """
    # Get the directory of this script
    script_dir = Path(__file__).parent
    rust_dir = script_dir / "rust_crypto"
    
    # Check if Rust is installed
    if not check_rust_installed():
        print("Error: Rust is not installed. Please install Rust from https://rustup.rs/")
        return False
    
    # Build the Rust library
    print("Building Rust crypto module...")
    os.chdir(rust_dir)
    
    result = subprocess.run(["cargo", "build", "--release"], check=False)
    if result.returncode != 0:
        print("Error: Failed to build Rust crypto module")
        return False
    
    print("Rust module built successfully")
    
    # Make sure the build_module.py script exists
    if not (script_dir / "build_module.py").exists():
        print("Error: build_module.py not found")
        return False
    
    # Run the build_module.py script to create a proper Python module
    os.chdir(script_dir)
    result = subprocess.run([sys.executable, "build_module.py"], check=False)
    if result.returncode != 0:
        print("Error: Failed to create Python module")
        return False
    
    print("Python module created successfully")
    return True

if __name__ == "__main__":
    if build_rust_module():
        print("Build successful")
    else:
        print("Build failed")
        sys.exit(1)
