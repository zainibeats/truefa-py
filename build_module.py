#!/usr/bin/env python3
"""
Python module builder for the Rust crypto library.

This script creates a proper Python module structure for the compiled Rust library.
It handles platform-specific details and sets up the necessary bindings.

Note: This script is for development only and is not needed in production.
It is called by build_rust.py after the Rust library is compiled.

The script performs the following:
1. Creates a Python package directory
2. Copies the compiled Rust library to the package
3. Creates an __init__.py with proper ctypes bindings
4. Sets up the Python path for the module
"""

import os
import shutil
import sys
from pathlib import Path

def build_module():
    """
    Build the Python module structure for the compiled Rust library.
    
    This function:
    1. Creates the module directory structure
    2. Copies the platform-specific library file
    3. Creates the __init__.py with proper bindings
    4. Sets up the Python path
    
    Returns:
        bool: True if module creation succeeds, False otherwise
    """
    # Set up paths
    source_dir = Path(__file__).parent
    module_dir = source_dir / "truefa_crypto"
    
    # Create module directory
    module_dir.mkdir(exist_ok=True)
    
    # Set up __init__.py path
    init_file = module_dir / "__init__.py"
    
    # Locate the Rust library
    rust_lib_path = source_dir / "rust_crypto" / "target" / "release"
    
    # Handle platform-specific library names
    if os.name == "nt":  # Windows
        lib_file = rust_lib_path / "truefa_crypto.dll"
        if not lib_file.exists():
            print(f"Error: {lib_file} not found")
            return False
        target_file = module_dir / "truefa_crypto.dll"
    else:  # Unix-like
        lib_file = rust_lib_path / "libtruefa_crypto.so"
        if not lib_file.exists():
            print(f"Error: {lib_file} not found")
            return False
        target_file = module_dir / "libtruefa_crypto.so"
    
    # Copy the library to the module directory
    shutil.copy2(lib_file, target_file)
    
    # Create the __init__.py file with platform-specific imports
    with init_file.open("w") as f:
        if os.name == "nt":  # Windows
            f.write('import os, sys\n')
            f.write('import ctypes\n')
            f.write('_dir = os.path.dirname(os.path.abspath(__file__))\n')
            f.write('_lib = ctypes.CDLL(os.path.join(_dir, "truefa_crypto.dll"))\n')
            f.write('# Import all symbols from the rust module\n')
            f.write('from truefa_crypto import *\n')
        else:  # Unix-like
            f.write('import os, sys\n')
            f.write('import ctypes\n')
            f.write('_dir = os.path.dirname(os.path.abspath(__file__))\n')
            f.write('_lib = ctypes.CDLL(os.path.join(_dir, "libtruefa_crypto.so"))\n')
            f.write('# Import all symbols from the rust module\n')
            f.write('from truefa_crypto import *\n')
    
    print(f"Module built at {module_dir}")
    return True

if __name__ == "__main__":
    if build_module():
        print("Build successful")
    else:
        print("Build failed")
        sys.exit(1)
