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

## Test Scripts (`tests/`)

The `tests` directory contains testing scripts and utilities:

- `create_test_qr.py`: Creates test QR codes for testing
- `test_vault_creation.py`: Tests vault creation and management
- `docker-crypto-init.py`: Initializes crypto module for Docker tests

Additional tests mentioned in documentation but not yet implemented:

- Tests for cryptographic module loading
- Tests for executable compatibility
- Tests for secure directory handling
- Tests for secure storage functionality

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
2. **Rust Development**: After modifying Rust code, use `build_rust.py` to rebuild the crypto library
3. **Building for Testing**: Use `build.ps1` with appropriate options for quick development builds
4. **Final Builds**: Use `build_package.py` for creating optimized release builds
5. **Testing**: Use appropriate test scripts from the `dev-tools/tests` directory

## Notes

- For contributions or questions about these tools, please contact the project maintainers