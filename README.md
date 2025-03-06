# TrueFA-Py - Secure TOTP Authenticator

TrueFA-Py is a secure, offline Two-Factor Authentication (2FA) application built with Python and Rust. It provides a robust command-line interface for managing TOTP (Time-based One-Time Password) authentication codes while keeping your security tokens encrypted and stored locally in a secure vault.

## Features

- 🔑 Encrypted local vault with master password
- 📷 QR code scanning from image files
- 🔐 Two-layer security architecture with envelope encryption
- 🛡️ Optimized Rust crypto module with robust fallback mechanisms
- 🖥️ Portable executable with no installation required
- 🔄 Intelligent error handling and automatic recovery
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
4. Use `TrueFA-Py-Launcher.bat` to launch the application

If you experience any issues, run the included `windows_compatibility_check.ps1` script to diagnose common problems.

## Documentation

Comprehensive documentation is available in the `docs` directory:

- [User Guide](docs/USER_GUIDE.md) - Complete instructions for installing, configuring, and using TrueFA-Py
- [Developer Guide](docs/DEVELOPER_GUIDE.md) - Development setup, project structure, building, testing, and security details
- [Frequently Asked Questions](docs/FAQ.md) - Answers to common questions about usage, security, and troubleshooting

See the [documentation index](docs/README.md) for a complete overview of available guides.

## TrueFA Improvements Summary

### Recent Fixes and Enhancements

#### Optimized Rust Cryptography Integration
- Completely redesigned the Rust `c_generate_salt` function to:
  - Eliminate hanging issues on Windows systems
  - Avoid potential deadlocks with Python's GIL by using direct Rust implementation
  - Properly handle base64 encoding within Rust
  - Implement proper memory safety and error handling
- Added comprehensive timeout protection for all cryptographic functions
- Enhanced error detection with diagnostic marker files
- Implemented intelligent fallback to Python implementations when needed

#### Enhanced DLL Integration
- Improved DLL path detection with better searching logic
- Fixed Windows path escape sequences for proper directory resolution
- Added marker files to track cryptographic function failures
- Enhanced error diagnostics for DLL operations
- Created predictive detection of potential issues for improved startup time

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
│   └── docker/              # Docker testing configurations
├── docs/                    # Documentation
│   ├── USER_GUIDE.md        # End-user guide with installation and usage
│   ├── DEVELOPER_GUIDE.md   # Technical guide for developers
│   ├── FAQ.md               # Frequently asked questions
│   └── README.md            # Documentation index
├── rust_crypto/             # Rust cryptography module
├── src/                     # Python source code
│   ├── totp/                # TOTP implementation
│   │   ├── auth.py          # Core TOTP functionality (pyzbar)
│   │   └── auth_opencv.py   # Alternative implementation (OpenCV)
│   ├── truefa_crypto/       # Cryptography module with fallbacks
│   └── vault/               # Secure vault implementation
├── TrueFA-Py-Launcher.bat   # Windows launcher script with environment setup
├── main.py                  # Application entry point
└── requirements.txt         # Python dependencies
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

# Setup development environment
python dev-tools\setup.py
```

### Building the Rust Cryptography Backend

```powershell
# Check Rust installation
rustc --version

# Build the Rust module with the latest fixes
python dev-tools\build_rust.py
```

### Building the Application

```powershell
# Simple build
python -m PyInstaller dev-tools\build-tools\TrueFA-Py.spec

# Complete package build (recommended)
python dev-tools\build_package.py

# Build with latest Rust DLL fixes (recommended)
.\dev-tools\build.ps1 -BuildRust -Clean -Portable
```

## Technical Architecture

### Hybrid Crypto Implementation
TrueFA-Py uses a hybrid approach to cryptographic operations:

1. **Primary: Rust Native Module**
   - High-performance, memory-safe cryptographic operations
   - Bindings to Python via FFI (Foreign Function Interface)
   - Secure memory management techniques
   - Optimized for desktop environments
   - Redesigned `c_generate_salt` function that avoids GIL issues
   - Timeout protection for all cryptographic functions

2. **Fallback: Pure Python Implementation**
   - Automatic fallback when native module is unavailable or encounters issues
   - Compatible with all platforms
   - Maintains security principles while sacrificing some performance
   - Ensures application functionality in all environments
   - Automatically activated if Rust functions time out or return errors

### Vault Implementation
The secure vault uses a two-layer security model:
1. **Vault Password** - Unlocks the vault and decrypts the master key
2. **Master Key** - Encrypts/decrypts individual TOTP secrets

This envelope encryption approach ensures that even if one layer is compromised, your secrets remain protected by the other layer.

## User Guide

For complete usage instructions, please refer to the [User Guide](docs/USER_GUIDE.md). Below is a quick overview:

### First-Time Setup
1. Launch TrueFA-Py using the provided launcher script
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
1. Download the latest release package
2. Extract to your preferred location
3. Run `TrueFA-Py-Launcher.bat` to start the application

The application will store its data in the `.truefa` directory in your user folder, or in the application directory if running in portable mode.

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
5. Use the latest version of the application which includes the optimized Rust implementation with proper timeout protection.
6. If the application appears to hang, try setting the `TRUEFA_USE_FALLBACK=1` environment variable to force using the Python implementation.
7. For detailed troubleshooting steps, refer to the [FAQ](docs/FAQ.md) document.

## License

This project is licensed under the MIT License. See the LICENSE file for details.

## Contributing

Contributions are welcome! Please refer to the [Developer Guide](docs/DEVELOPER_GUIDE.md) for setup instructions and contribution guidelines.
