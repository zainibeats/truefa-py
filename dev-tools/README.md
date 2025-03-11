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
Development dependencies for TrueFA-Py.
```powershell
# Install development dependencies
pip install -r dev-tools/dev-requirements.txt
```

### build_package.py
A comprehensive build script for creating both portable executables and installers.

### build_rust.py
Handles compilation of the Rust cryptographic module and sets up the necessary Python bindings.

### build.ps1
PowerShell build script that offers a convenient wrapper for various build options.

### setup.py
Set up script for development environment.

### clean_truefa.py
Utility script for removing all TrueFA data directories.

### reset_and_test.py
Testing preparation script that cleans up vault files and creates test instructions.

## Test Scripts (`tests/`)

The `tests` directory contains testing scripts and utilities:

- `verify_dll_exports.py`: Verifies that all required C functions are exported from the DLL
- `verify_rust_crypto.py`: Comprehensive verification of Rust crypto functionality
- `test_vault_creation.py`: Tests vault creation and management
- `test_vault_persistence.py`: Tests vault persistence across sessions

## Development Workflow

1. **Initial Setup**: Use `setup.py` to prepare your development environment
2. **Rust Development**: Use `build_rust.py` to rebuild the crypto library
3. **Building for Testing**: Use `build.ps1` with appropriate options
4. **Final Builds**: Use `build_package.py` for creating optimized release builds
5. **Testing**: Use appropriate test scripts from the `dev-tools/tests` directory

## Related Documentation

- [Developer Guide](../docs/DEVELOPER_GUIDE.md) - Comprehensive development documentation
- [Security Documentation](../docs/SECURITY.md) - Security architecture and implementation details
- [Development Status](../docs/DEVELOPMENT_STATUS.md) - Current project state and recent improvements
- [Documentation Index](../docs/README.md) - Overview of all available documentation

## Additional Information

For detailed development documentation, including how to use the logging system during development, refer to the [Developer Guide](../docs/DEVELOPER_GUIDE.md).

## Notes

For contributions or questions about these tools, please contact the project maintainers.