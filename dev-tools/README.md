# TrueFA-Py Development Tools

This directory contains various build scripts and development utilities for the TrueFA-Py project. These tools are used during development and are not required for running the application.

## Directory Structure

The development tools are organized into the following directories:

- `build-tools/`: Scripts and files related to building the application
- `docker-tests/`: Docker configuration and test scripts 
- `vm-testing/`: Scripts for testing in virtual machine environments
- Root directory: Core development utilities and test scripts

## Build Tools (`/build-tools`)

### PyInstaller Specification Files
- `TrueFA-Py.spec`: PyInstaller spec for the windowed application
- `TrueFA-Py_console.spec`: PyInstaller spec for the console application

### Build and Packaging Scripts
- `cleanup.ps1`: Cleans build artifacts and temporary files
- `create_windows_package.ps1`: Creates a Windows distribution package
- `ez-release.ps1`: Handles the release process with versioning
- `file_version_info.txt`: Windows version information for the executable
- `installer.nsi`: NSIS installer script

## Core Build Scripts

### build_package.py
A comprehensive build script for creating both portable executables and installers. This script:
- Builds the application with PyInstaller
- Creates a Windows executable with proper version information
- Optionally generates an installer using NSIS
- Validates the Rust crypto DLL

```powershell
python dev-tools/build_package.py --portable      # Build portable version only
python dev-tools/build_package.py --installer     # Build installer version only
python dev-tools/build_package.py --console       # Include console window
python dev-tools/build_package.py --fallback      # Use Python crypto implementation
```

### build_rust.py
Handles compilation of the Rust cryptographic module and sets up the necessary Python bindings:
1. Verifies Rust toolchain is installed
2. Builds the Rust library in release mode
3. Sets up proper Python module structure for the compiled library

```powershell
python dev-tools/build_rust.py
```

### build.ps1
PowerShell build script that offers a convenient wrapper for various build options:

```powershell
./dev-tools/build.ps1 -Portable      # Build portable version
./dev-tools/build.ps1 -Installer     # Build installer version
./dev-tools/build.ps1 -Console       # Include console window
./dev-tools/build.ps1 -BuildRust     # Rebuild Rust components
./dev-tools/build.ps1 -Clean         # Clean build artifacts
```

### secure_build_fix.py
Enhanced build script with cryptographic module verification:
1. Verifies and validates the Rust cryptographic DLL
2. Automatically configures fallback to Python implementation if needed
3. Creates a secure executable with appropriate dependencies

```powershell
python dev-tools/secure_build_fix.py
```

### setup.py / truefa_setup.py
Set up script for development environment:
- Builds the Rust crypto library
- Installs Python dependencies
- Sets up the correct DLL paths
- Creates necessary directories

```powershell
python dev-tools/setup.py
```

## Test Scripts

The repository contains various test scripts to ensure the application works correctly in different environments:

- `test_crypto_loading.py`: Tests loading of the cryptographic module
- `test_exe_compatibility.py`: Tests executable compatibility
- `test_fixes.py`: Tests fixes for various issues
- `test_secure_dirs.py`: Tests secure directory handling
- `test_secure_storage.py`: Tests secure storage functionality
- `test_secure_string.py`: Tests secure string handling
- `test_vault_creation.py`: Tests vault creation and management
- `vault_test.py`: Tests vault functionality

## Development Workflow

1. **Initial Setup**: Use `setup.py` to prepare your development environment
2. **Rust Development**: After modifying Rust code, use `build_rust.py` to rebuild the crypto library
3. **Building for Testing**: Use `build.ps1` with appropriate options for quick development builds
4. **Final Builds**: Use `build_package.py` for creating optimized release builds
5. **Testing**: Use appropriate test scripts based on your test environment (Docker, VM, local)

## Notes

- For contributions or questions about these tools, please contact the project maintainers