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

4. **Visual C++ Redistributable 2015-2022** (Required for Windows)
   - Download from [Microsoft](https://aka.ms/vs/17/release/vc_redist.x64.exe)
   - Required for using the Rust cryptography module

## Build Tools

TrueFA includes several build tools located in the `dev-tools` directory to help you compile and package the application:

### 1. PowerShell Build Script (Recommended)

The PowerShell build script provides a convenient way to build TrueFA with various options:

```powershell
# Basic usage (builds both portable EXE and installer)
.\dev-tools\build.ps1

# Build only portable EXE
.\dev-tools\build.ps1 -Portable

# Build only installer
.\dev-tools\build.ps1 -Installer

# Build with console window (for debugging)
.\dev-tools\build.ps1 -Console

# Force use of Python fallback implementation
.\dev-tools\build.ps1 -Fallback

# Build Rust cryptography backend first
.\dev-tools\build.ps1 -BuildRust

# Clean build artifacts before building
.\dev-tools\build.ps1 -Clean

# Combine options as needed
.\dev-tools\build.ps1 -Portable -Console -BuildRust -Clean
```

### 2. Python Build Package Script

For more control, you can use the Python build script directly:

```powershell
# Build both portable EXE and installer
python dev-tools\build_package.py

# Build only portable EXE
python dev-tools\build_package.py --portable

# Build only installer
python dev-tools\build_package.py --installer

# Build with console window
python dev-tools\build_package.py --console

# Force use of Python fallback implementation
python dev-tools\build_package.py --fallback
```

### 3. Rust Cryptography Backend

To build only the Rust cryptography backend:

```powershell
python dev-tools\build_rust.py
```

To build and validate the cryptography backend:

```powershell
python dev-tools\secure_build_fix.py
```

This script will:
1. Build the Rust library in release mode
2. Copy the generated DLL to the appropriate locations
3. Verify that all required functions are exported

## Windows Distribution Package

To create a Windows distribution package with all dependencies included:

```powershell
# Run the Windows package creator script
.\create_windows_package.ps1
```

This script will:
1. Create a self-contained directory with the application and all dependencies
2. Include the Visual C++ Redistributable installer
3. Add a launcher script that configures the environment correctly
4. Package everything into a ZIP file for distribution

The resulting package can be distributed to Windows users, who can simply:
1. Extract the ZIP file
2. Run `setup.bat` to install dependencies
3. Use `TrueFA-Py.bat` to launch the application

## Compatibility Testing

To test the application on a fresh Windows installation, use:

```powershell
# Run the Windows compatibility checker
.\windows_compatibility_check.ps1
```

This script will:
1. Check for required dependencies
2. Verify that critical DLLs are available
3. Test running the executable
4. Provide guidance for resolving any issues

## Development Environment

For initial setup, use the setup script:

```powershell
# Set up development environment
python dev-tools\setup.py
```

This script will:
1. Create necessary directories
2. Build the Rust crypto library
3. Install required dependencies
4. Set up DLL paths

## Release Process

To create a release version with proper versioning:

```powershell
# Run release with PowerShell script (recommended)
powershell -ExecutionPolicy Bypass -File ".\ez-release1\release.ps1" -VersionType [major|minor|patch|none]
```

## Build Output

After a successful build, you will find the following files in the `dist` directory:

- **Portable EXE**: `dist\TrueFA-Py.exe` (or `dist\TrueFA-Py_console.exe` if built with console)
- **Installer**: `dist\TrueFA-Py_Setup_{version}.exe`

## Troubleshooting

If you encounter build issues:

1. **Missing DLL Functions**
   - Run `python dev-tools\secure_build_fix.py` to rebuild the Rust cryptography DLL
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