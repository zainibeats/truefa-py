"""
TrueFA Setup Script

This script handles the installation and setup of TrueFA, including:
- Building the Rust crypto library
- Installing Python dependencies
- Setting up the correct DLL paths
- Creating necessary directories
"""

import os
import sys
import shutil
import subprocess
from pathlib import Path
import platform

def build_rust_lib():
    """Build the Rust crypto library"""
    print("Building Rust crypto library...")
    rust_dir = Path("rust_crypto")
    
    if not rust_dir.exists():
        print("Error: rust_crypto directory not found!")
        return False
        
    try:
        # Build the Rust library
        result = subprocess.run(
            ["cargo", "build", "--release"],
            cwd=rust_dir,
            capture_output=True,
            text=True
        )
        
        if result.returncode != 0:
            print(f"Error building Rust library:\n{result.stderr}")
            return False
            
        print("Rust library built successfully")
        return True
    except Exception as e:
        print(f"Error building Rust library: {e}")
        return False

def install_python_deps():
    """Install required Python packages"""
    print("Installing Python dependencies...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        print("Python dependencies installed successfully")
        return True
    except Exception as e:
        print(f"Error installing Python dependencies: {e}")
        return False

def setup_dll():
    """Set up the DLL in the correct location"""
    print("Setting up DLL...")
    
    # Source DLL path
    if platform.system() == "Windows":
        dll_name = "truefa_crypto.dll"
        source_dll = Path("rust_crypto/target/release") / dll_name
    else:
        dll_name = "libtruefa_crypto.so"
        source_dll = Path("rust_crypto/target/release") / dll_name
    
    if not source_dll.exists():
        print(f"Error: DLL not found at {source_dll}")
        return False
    
    # Create directories if they don't exist
    dll_dirs = [
        Path("dist"),
        Path("src/truefa_crypto"),
    ]
    
    for dll_dir in dll_dirs:
        dll_dir.mkdir(parents=True, exist_ok=True)
        try:
            shutil.copy2(source_dll, dll_dir / dll_name)
        except Exception as e:
            print(f"Error copying DLL to {dll_dir}: {e}")
            return False
    
    print("DLL setup completed successfully")
    return True

def create_directories():
    """Create necessary directories"""
    print("Creating required directories...")
    dirs = [
        Path("images"),
        Path("dist"),
        Path(".truefa"),
    ]
    
    for directory in dirs:
        directory.mkdir(exist_ok=True)
        print(f"Created directory: {directory}")

def main():
    """Main setup function"""
    print("Starting TrueFA setup...")
    
    # Create necessary directories
    create_directories()
    
    # Build Rust library
    if not build_rust_lib():
        print("Failed to build Rust library")
        return False
    
    # Install Python dependencies
    if not install_python_deps():
        print("Failed to install Python dependencies")
        return False
    
    # Set up DLL
    if not setup_dll():
        print("Failed to set up DLL")
        return False
    
    print("\nTrueFA setup completed successfully!")
    print("\nYou can now:")
    print("1. Run the program directly with: python src/main_opencv.py")
    print("2. Build the executable with: pyinstaller TrueFA.spec")
    return True

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1) 