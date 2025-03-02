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

## Prerequisites

To build TrueFA-Py from source, you need:

- Python 3.10 or later
- Rust (latest stable version)
- PyInstaller for building executables
- NSIS (for building Windows installer)

## Development

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
python secure_build_fix.py
```

### Building the Application

```powershell
# Simple build
python -m PyInstaller TrueFA_simple.spec

# Complete package build
python build_package.py
```

### Project Structure

```
truefa-py/
├── rust_crypto/           # Rust native crypto module
│   ├── src/               # Rust source code
│   ├── Cargo.toml         # Rust dependencies
│   └── build.py           # Build script
├── src/                   # Python application source
│   ├── config/            # Application configuration
│   ├── security/          # Security implementation
│   │   ├── vault.py       # Secure vault implementation
│   │   └── secure_string.py # Secure string handling
│   ├── truefa_crypto/     # Crypto module with fallbacks
│   │   ├── __init__.py    # Module initialization
│   │   └── fallback.py    # Python fallback implementations
│   ├── ui/                # User interface components
│   └── totp/              # TOTP implementation
├── main.py                # Application entry point
├── TrueFA_Py.spec     # PyInstaller specification
└── build_package.py       # Package build script
```

## Security Features

### Enhanced Crypto Architecture
- Native Rust crypto module for high-performance security operations
- Automatic fallback to Python implementation when native module unavailable
- Memory-safe implementation with Rust's security guarantees
- Envelope encryption for enhanced security

### Vault Storage and Security
- **Primary Vault Location**: `C:\Users\<username>\.truefa\.vault\`
- **Cryptographic Materials**: `C:\Users\<username>\.truefa\.crypto\`
- **Vault Metadata**: Stored in `vault.meta` with salt and password verification hash
- **Fallback Locations**: Multiple path resolution for reliability

### Encryption and Storage
- AES-256-GCM authenticated encryption (when available)
- PBKDF2 key derivation with 100,000 iterations and SHA-256
- Unique salt generation for each vault
- Secure password verification with constant-time comparison
- Two-layer security model for enhanced protection

### Path Resolution
The application will automatically search for your vault in various locations when unlocking:
1. `C:\Users\<username>\.truefa\.vault\`
2. `C:\Users\<username>\.truefa_vault\`
3. `C:\Users\<username>\.truefa_secure\`
4. Application data directories

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

## Troubleshooting

If you encounter issues with vault access:

1. **Vault Not Found**: The application will look in multiple locations for your vault. If you've moved your vault, try pointing to the new location.
2. **Password Problems**: If you've forgotten your password, there is no recovery mechanism - this is a security feature.
3. **Permission Issues**: If you see permissions warnings, make sure you have write access to the `.truefa` directory in your user folder.

## License

This project is licensed under the MIT License. See the LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. 

