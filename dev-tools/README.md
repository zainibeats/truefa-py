# TrueFA-Py Development Tools

This directory contains various build scripts and development utilities for the TrueFA-Py project. These tools are used during development and are not required for running the application.

## Directory Structure

The development tools are organized into the following directories:

- `build-tools/`: Scripts and files related to building the application
- `tests/`: All test-related scripts and utilities
- Root directory: Core development utilities and build scripts

Docker-related files are located in a separate directory:

- `docker/`: Docker configuration files and scripts
  - `docker/windows/`: Windows-specific Docker files

## Build Tools (`build-tools/`)

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

### dev-requirements.txt
Development dependencies for TrueFA-Py:
- Includes all core dependencies from the main requirements.txt
- Adds build and packaging tools (pyinstaller, pefile, setuptools)
- Adds testing tools (pytest, pytest-cov)

```powershell
# Install development dependencies
pip install -r dev-tools/dev-requirements.txt
```

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

### setup.py
Set up script for development environment:
- Builds the Rust crypto library
- Installs Python dependencies
- Sets up the correct DLL paths
- Creates necessary directories

```powershell
python dev-tools/setup.py
```

### clean_truefa.py
Utility script for removing all TrueFA data directories:
- Cleans up vault data, configuration files, and cached secrets
- Useful for testing or completely resetting the application
- Handles permission issues by attempting multiple removal strategies

```powershell
python dev-tools/clean_truefa.py
```

### reset_and_test.py
Testing preparation script that:
- Uses clean_truefa.py to clean up all existing vault files
- Creates test instructions for manual testing
- Prepares the environment for testing with a clean state

```powershell
python dev-tools/reset_and_test.py
```

## Test Scripts (`tests/`)

The `tests` directory contains testing scripts and utilities:

- `verify_dll_exports.py`: Specifically verifies that all required C functions are properly exported from the DLL
- `verify_rust_crypto.py`: Comprehensive verification of Rust crypto functionality
- `test_vault_creation.py`: Tests vault creation and management
- `test_vault_persistence.py`: Tests vault persistence across sessions
- `docker-crypto-init.py`: Initializes crypto module for Docker tests
- `create_test_qr.py`: Creates test QR codes for testing

To run the verification scripts:

```powershell
# Run the DLL export verification
python dev-tools/tests/verify_dll_exports.py

# Run the comprehensive crypto verification
python dev-tools/tests/verify_rust_crypto.py
```

The `verify_dll_exports.py` script is particularly important after making changes to the Rust code or build configuration, as it ensures all required FFI functions are properly exported from the DLL. This script:

- Searches for the DLL in multiple locations
- Verifies all required functions are exported
- Tests basic function calls to confirm functionality
- Checks if the Python module can properly use the DLL
- Provides clear pass/fail status with detailed error messages

Additional needed test areas:
- Cryptographic module loading under various conditions
- Executable compatibility across Windows versions
- Secure directory handling for sensitive data
- Secure storage functionality and encryption/decryption

## Docker Configuration

Docker-related files are located in the `docker` directory:

- `docker/Dockerfile`: Main Dockerfile for Linux containers
- `docker/docker-entrypoint.sh`: Container entry point script
- `docker/run_docker.ps1`: Script to run Docker container with local mounts
- `docker/run_docker_persistent.ps1`: Script to run container with persistent storage

Windows testing files:

- `docker/windows/Dockerfile.windows`: Windows container configuration for testing
- `docker/windows/windows_docker_test.ps1`: Script to run tests in Windows containers

## Development Workflow

1. **Initial Setup**: Use `setup.py` to prepare your development environment
   ```bash
   # Install development dependencies
   pip install -r dev-tools/dev-requirements.txt
   
   # Set up the development environment
   python dev-tools/setup.py
   ```
   
2. **Rust Development**: After modifying Rust code, use `build_rust.py` to rebuild the crypto library
3. **Building for Testing**: Use `build.ps1` with appropriate options for quick development builds
4. **Final Builds**: Use `build_package.py` for creating optimized release builds
5. **Testing**: Use appropriate test scripts from the `dev-tools/tests` directory

## Notes

- For contributions or questions about these tools, please contact the project maintainers