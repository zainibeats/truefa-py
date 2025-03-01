# TrueFA Build Instructions

This document provides detailed instructions for building the TrueFA application.

## Prerequisites

Before building TrueFA, ensure you have the following software installed:

1. **Python 3.10 or later**
   - Download from [python.org](https://www.python.org/downloads/)
   - Ensure Python is added to your PATH during installation

2. **Rust** (Optional, for Rust cryptography backend)
   - Install using [rustup](https://rustup.rs/)
   - Follow the installation instructions for your platform

3. **NSIS** (Optional, for creating Windows installers)
   - Download from [NSIS website](https://nsis.sourceforge.io/Download)
   - Install with default options

## Build Tools

TrueFA includes several build tools to help you compile and package the application:

### 1. PowerShell Build Script (Recommended)

The `build.ps1` script provides a convenient way to build TrueFA with various options:

```powershell
# Basic usage (builds both portable EXE and installer)
.\build.ps1

# Build only portable EXE
.\build.ps1 -Portable

# Build only installer
.\build.ps1 -Installer

# Build with console window (for debugging)
.\build.ps1 -Console

# Force use of Python fallback implementation
.\build.ps1 -Fallback

# Build Rust cryptography backend first
.\build.ps1 -BuildRust

# Clean build artifacts before building
.\build.ps1 -Clean

# Combine options as needed
.\build.ps1 -Portable -Console -BuildRust -Clean
```

### 2. Python Build Package Script

For more control, you can use the Python build script directly:

```powershell
# Build both portable EXE and installer
python build_package.py

# Build only portable EXE
python build_package.py --portable

# Build only installer
python build_package.py --installer

# Build with console window
python build_package.py --console

# Force use of Python fallback implementation
python build_package.py --fallback
```

### 3. Rust Cryptography Backend

To build only the Rust cryptography backend:

```powershell
python secure_build_fix.py
```

This script will:
1. Build the Rust library in release mode
2. Copy the generated DLL to the appropriate locations
3. Verify that all required functions are exported

## Development Environment

For development, you can use the included batch file:

```powershell
# Run TrueFA in development mode
.\run_dev.bat
```

This script will:
1. Create a virtual environment if it doesn't exist
2. Install required dependencies
3. Set development environment variables
4. Run the application in development mode

## Build Output

After a successful build, you will find the following files in the `dist` directory:

- **Portable EXE**: `dist\TrueFA.exe` (or `dist\TrueFA_console.exe` if built with console)
- **Installer**: `dist\TrueFA_Setup_1.0.0.exe`

## Troubleshooting

If you encounter build issues:

1. **Missing DLL Functions**
   - Run `python secure_build_fix.py` to rebuild the Rust cryptography DLL
   - Check the console output for specific function names that are missing

2. **PyInstaller Errors**
   - Make sure PyInstaller is installed: `pip install pyinstaller`
   - Try clearing the PyInstaller cache: `python -m PyInstaller --clean`

3. **NSIS Errors**
   - Verify NSIS is installed and in your PATH
   - Check if the `makensis.exe` file exists in one of these locations:
     - `C:\Program Files (x86)\NSIS\makensis.exe`
     - `C:\Program Files\NSIS\makensis.exe`

4. **Rust Build Errors**
   - Ensure Rust is installed and up to date: `rustup update`
   - Check that your Rust installation is working: `rustc --version`
   - Try rebuilding with verbose output: `cargo build --release -vv`

5. **Icon Not Found**
   - Verify the icon exists at `assets\truefa2.ico`
   - Try providing an alternate icon with the `-icon` parameter 