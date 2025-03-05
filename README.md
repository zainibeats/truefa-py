# TrueFA-Py - Secure TOTP Authenticator

TrueFA-Py is a secure, offline Two-Factor Authentication (2FA) application built with Python and Rust. It provides a robust command-line interface for managing TOTP (Time-based One-Time Password) authentication codes while keeping your security tokens encrypted and stored locally in a secure vault.

## Features

- 🔑 Encrypted local vault with master password
- 📷 QR code scanning from image files
- 🔐 Two-layer security architecture with envelope encryption
- 🛡️ Native Rust crypto module with Python fallback mechanisms
- 🖥️ Portable executable with no installation required
- 🔄 Robust error handling and path validation
- 🔍 Multiple vault location detection capabilities
- 📥 Save and retrieve TOTP secrets
- 🔢 Generate time-based authentication codes

## Windows Compatibility

TrueFA-Py is designed to work on most Windows systems. For optimal compatibility:

- Windows 10 or higher is recommended
- Visual C++ Redistributable 2015-2022 must be installed 
  - Automatically installed by our setup script
  - Can be downloaded from [Microsoft](https://aka.ms/vs/17/release/vc_redist.x64.exe)
- Use the bundled launcher script that properly configures the environment

### Quick Start for Windows Users

1. Download the latest `TrueFA-Py-Windows` package from the releases page
2. Extract the ZIP file to your preferred location
3. Run `setup.bat` to install required dependencies
4. Use `TrueFA-Py.bat` to launch the application

If you experience any issues, run the included `windows_compatibility_check.ps1` script to diagnose common problems.

## Documentation

Comprehensive documentation is available in the `docs` directory:

- [Build Guide](docs/BUILD_GUIDE.md) - Instructions for building TrueFA-Py
- [Security Guide](docs/SECURITY_GUIDE.md) - Security model and implementation details
- [Testing Guide](docs/TESTING_GUIDE.md) - Testing infrastructure and results

## TrueFA Improvements Summary

### Recent Fixes and Enhancements

#### DLL Loading and Cryptographic Operations
- Added robust fallback mechanism when the Rust DLL can't be loaded
- Improved DLL path searching across various potential locations 
- Fixed Windows path escape sequences for proper directory resolution
- Implemented timeout handling for potentially hanging salt generation
- Created marker files to track when DLL operations fail
- Enhanced error diagnostics for missing DLL functions

#### Security and Vault Management
- Improved secure directory creation with fallback mechanisms
- Enhanced error handling for permission issues
- Implemented atomic file operations with backup creation
- Added secure file flushing on Windows to prevent data corruption
- Created alternative path detection for vault files
- Added recovery from backup files when corruption is detected
- Enhanced version tracking in vault metadata

#### Robustness Improvements
- Implemented fallback paths when default directories can't be written to
- Added diagnostic markers for tracking various failure conditions
- Enhanced logging throughout the codebase for better troubleshooting
- Improved tests with better handling of common failure scenarios
- Made the library more resilient to OS-specific issues

### Known Issues
- Some Windows installations may still experience permission issues in certain directories
- The Rust DLL may fail to load on systems without the Visual C++ Redistributable
- Only the Python fallback implementation is supported in Docker containers

### Upcoming Improvements
- Implement proper clean-up of secure strings in the Python fallback implementation
- Add auto-detection and installation of required dependencies
- Improve compatibility with different Python versions

## Development

### Project Structure

```
truefa-py/
├── assets/                  # Application assets (icons, etc.)
├── dev-tools/               # Development tools
│   ├── build-tools/         # Build and packaging scripts
│   ├── docker-tests/        # Docker testing configurations
│   ├── vm-testing/          # VM testing tools
│   └── ...                  # Core dev tools
├── docs/                    # Documentation
├── rust_crypto/             # Rust cryptography module
├── src/                     # Python source code
├── truefa_crypto/           # Cryptography module with fallbacks
├── main.py                  # Application entry point
├── requirements.txt         # Python dependencies
└── README.md                # Project overview
```

### Setting up the Environment

```powershell
# Clone the repository
git clone https://github.com/zainibeats/truefa-py.git
cd truefa-py

# Create a virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt
```

### Building the Rust Cryptography Backend

```powershell
# Check Rust installation
rustc --version

# Build the Rust module
python dev-tools\secure_build_fix.py
```

### Building the Application

```powershell
# Simple build
python -m PyInstaller dev-tools\build-tools\TrueFA-Py.spec

# Complete package build
python dev-tools\build_package.py
```

## Technical Architecture

### Hybrid Crypto Implementation
TrueFA-Py uses a hybrid approach to cryptographic operations:

1. **Primary: Rust Native Module**
   - High-performance, memory-safe cryptographic operations
   - Bindings to Python via FFI (Foreign Function Interface)
   - Secure memory management techniques
   - Optimized for desktop environments

2. **Fallback: Pure Python Implementation**
   - Automatic fallback when native module is unavailable
   - Compatible with all platforms
   - Maintains security principles while sacrificing some performance
   - Ensures application functionality in all environments

### Vault Implementation
The secure vault uses a two-layer security model:
1. **Vault Password** - Unlocks the vault and decrypts the master key
2. **Master Key** - Encrypts/decrypts individual TOTP secrets

This envelope encryption approach ensures that even if one layer is compromised, your secrets remain protected by the other layer.

## User Guide

### First-Time Setup
1. Launch TrueFA-Py
2. When prompted, create a strong master password
3. This password will be required for all future access to your vault

### Adding Accounts
1. Select option 1 or 2 from the main menu to add an account
   - Option 1: Load QR code from image
   - Option 2: Enter secret key manually
2. Follow the prompts to enter account details
3. Use option 3 to save the account to your secure vault

### Viewing Accounts and Codes
1. Select option 4 from the main menu
2. Enter your master password when prompted
3. Choose from the list of available accounts
4. The current TOTP code will be displayed

### Managing Accounts
- Use option 5 to export your secrets
- Use option 6 to clear the screen
- Use option 7 to exit the application

## Installation

### Portable Version
Simply download and run `TrueFA-Py.exe`. No installation required. The application will store its data in the `.truefa` directory in your user folder.

### Installer Version
Run `TrueFA-Py_Setup.exe` and follow the installation wizard. This will:
- Install TrueFA-Py to the Program Files directory
- Create start menu shortcuts
- Add an uninstaller
- Register the application with Windows

## Testing in Docker

We've included a Docker-based testing environment to help diagnose issues in a clean Windows installation:

```batch
# Run the Docker test script
.\dev-tools\docker\test_docker.bat
```

This creates a `truefa-py-docker-test` image and runs a container that tests the application in a clean Windows environment.

## Troubleshooting

If you encounter issues:

1. Check the `.truefa` directory in your user home folder for marker files (like `.dll_crash`) that indicate specific issues.
2. Ensure the application has permission to write to your home directory.
3. Try running with administrator privileges if you encounter permission errors.
4. Delete the `.truefa` directory to reset the application state if needed.

## License

This project is licensed under the MIT License. See the LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
