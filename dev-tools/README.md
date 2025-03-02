# TrueFA-Py Development Tools

This directory contains various build scripts and development utilities for the TrueFA-Py project. These tools are used during development and are not required for running the application.

## Build Scripts

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

## Release Tools

The release tools have been moved to the `ez-release1` directory and are managed separately. Please refer to the PowerShell release scripts in that directory for handling the release process.

## Development Workflow

1. **Initial Setup**: Use `setup.py` to prepare your development environment
2. **Rust Development**: After modifying Rust code, use `build_rust.py` to rebuild the crypto library
3. **Building for Testing**: Use `build.ps1` with appropriate options for quick development builds
4. **Final Builds**: Use `build_package.py` for creating optimized release builds
5. **Release Process**: Use the PowerShell scripts in `ez-release1` to create versioned releases

## Notes

- For contributions or questions about these tools, please contact the project maintainers 