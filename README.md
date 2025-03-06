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
- The Docker container uses the Python fallback implementation for enhanced compatibility and security
- Docker builds require Linux containers mode in Docker Desktop for Windows

### Upcoming Improvements
- Implement proper clean-up of secure strings in the Python fallback implementation
- Add auto-detection and installation of required dependencies
- Improve compatibility with different Python versions

## Quick Start Guide

### Installation Options

#### Portable Version (Recommended for Windows)
1. Download the latest release package
2. Extract to your preferred location
3. Run `setup.bat` to install required dependencies 
4. Run `TrueFA-Py-Launcher.bat` to start the application

The application will store its data in the `.truefa` directory in your user folder, or in the application directory if running in portable mode.

#### Installer Version (Windows)
Run `TrueFA-Py_Setup.exe` and follow the installation wizard. This will:
- Install TrueFA-Py to the Program Files directory
- Create start menu shortcuts
- Add an uninstaller
- Register the application with Windows

#### Docker Installation (Enhanced Security)
Docker provides an isolated, secure environment for running TrueFA-Py with proper dependencies and permissions:

```bash
# IMPORTANT: Switch Docker to Linux containers mode first
# Right-click Docker Desktop icon in system tray -> Switch to Linux containers...

# Build the Docker image using the Dockerfile in the project root
docker build -t truefa-py .

# Run TrueFA-Py in a container
docker run -it --rm truefa-py
```

Benefits of using Docker:
- Complete isolation from your host system
- Pre-configured secure environment with non-root user
- Consistent dependencies across different platforms
- Automatic setup of all required libraries and tools
- Enhanced privacy through containerization

For persistent storage of your vault data, you can mount a volume:

```bash
docker run -it --rm -v /path/to/local/storage:/home/truefa/.truefa truefa-py
```

> **Note**: Our Docker setup uses Linux containers, not Windows containers. Make sure Docker Desktop is switched to Linux containers mode before building or running the image. Use the Dockerfile in the root directory for installation.

### First-Time Setup

When you first launch TrueFA-Py:
1. You'll be prompted to create a master password
2. Enter a strong password when prompted - this will be used to secure your vault
3. This password cannot be recovered if lost, so remember it

### Using TrueFA-Py

TrueFA-Py provides the following options in its menu:

| Option | Purpose |
|--------|---------|
| 1 | Load QR code from image file |
| 2 | Enter secret key manually |
| 3 | Save current token to your vault |
| 4 | View saved tokens and generate codes |
| 5 | Export vault backup |
| 6 | Clear screen |
| 7 | Exit application |

#### Adding Authentication Tokens

**Via QR Code:**
1. Select option 1
2. Enter the path to the QR code image file
3. The application will extract the secret

**Manually:**
1. Select option 2
2. Enter the secret key (usually a base32-encoded string)
3. Enter a name for this token

**Saving Tokens:**
1. After adding a token, select option 3
2. Enter a name for the token if prompted
3. Enter your vault master password

#### Generating TOTP Codes

1. Select option 4
2. Enter your vault master password
3. Select the token from the list
4. The current TOTP code will be displayed with a countdown timer

## Troubleshooting

If you encounter issues:

1. Check the `.truefa` directory in your user home folder for marker files (like `.dll_crash`) that indicate specific issues.
2. Ensure the application has permission to write to your home directory.
3. Try running with administrator privileges if you encounter permission errors.
4. Delete the `.truefa` directory to reset the application state if needed.
5. Use the latest version of the application which includes the optimized Rust implementation with proper timeout protection.
6. If the application appears to hang, try setting the `TRUEFA_USE_FALLBACK=1` environment variable to force using the Python implementation.
7. For detailed troubleshooting steps, refer to the [FAQ](docs/FAQ.md) document.

### Environment Variables

| Variable | Purpose |
|----------|---------|
| `TRUEFA_PORTABLE=1` | Run in portable mode (store vault in app directory) |
| `TRUEFA_USE_FALLBACK=1` | Force using Python crypto implementation |

## Development

### Project Structure

```
truefa-py/
├── assets/                  # Application assets (icons, etc.)
├── dev-tools/               # Development tools
│   ├── build-tools/         # Build and packaging scripts
│   │   ├── cleanup.ps1      # Clean build artifacts
│   │   └── ez-release.ps1   # Create signed release packages
├── docs/                    # Documentation
│   ├── DEVELOPER_GUIDE.md   # Technical guide for developers
│   ├── FAQ.md               # Frequently asked questions
│   └── README.md            # Documentation index
├── rust_crypto/             # Rust cryptography module
├── src/                     # Python source code
│   ├── totp/                # TOTP implementation
│   │   └── auth_opencv.py   # TOTP implementation with OpenCV for QR scanning
│   ├── truefa_crypto/       # Cryptography module with fallbacks
│   └── vault/               # Secure vault implementation
├── TrueFA-Py-Launcher.bat   # Windows launcher script with environment setup
├── main.py                  # Application entry point
├── Dockerfile               # Main Dockerfile for secure Linux container installation
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

## License

This project is licensed under the MIT License. See the LICENSE file for details.

## Contributing

Contributions are welcome! Please refer to the [Developer Guide](docs/DEVELOPER_GUIDE.md) for setup instructions and contribution guidelines.
