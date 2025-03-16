# TrueFA-Py - Secure TOTP Authenticator

TrueFA-Py is a secure, offline Two-Factor Authentication (2FA) application built with Python and Rust. It provides a robust command-line interface for managing TOTP authentication codes while keeping your security tokens encrypted and stored locally in a secure vault.

**[View Recent Development Status and Progress](docs/DEVELOPMENT_STATUS.md)**

## Features

- 🔑 Encrypted local vault with master password
- 📷 QR code scanning from image files
- 🔐 Two-layer security architecture with envelope encryption
- 🛡️ High-performance Rust crypto with memory protection and automatic fallback
- 📥 Save and retrieve TOTP secrets with robust encryption
- 📤 Import and export functionality with encrypted JSON format
- 🔄 Interoperability with other authenticator applications
- 🔍 Intelligent vault location detection with permission handling
- 🐳 Docker compatibility for containerized environments

## Security

TrueFA-Py implements a comprehensive security model to protect your authentication secrets:

- Two-layer encryption with PBKDF2 and AES-GCM
- Secure memory handling with automatic zeroing
- Rust implementation of critical cryptographic functions
- No network transmission of sensitive data

For detailed information about the security implementation, please refer to the [Security Documentation](docs/SECURITY.md).

## Installation & Usage

### Windows

#### Prerequisites
- **Visual C++ Redistributable 2015-2022** - Required for the Rust cryptography module
  - Download from [Microsoft](https://aka.ms/vs/17/release/vc_redist.x64.exe)
  - This is required for both the portable executable and installed versions

#### Pre-built Releases

**Version 0.1.0 Now Available!**

- **Windows Installer**: Setup wizard for easy installation with all dependencies
  - Note: The installed version creates an images directory at `C:\Users\<USERNAME>\Documents\images` for QR code scanning
- **Portable Version**: Standalone executable that can run without installation
  - Uses the local directory structure for more flexibility

[Download the latest release](https://github.com/zainibeats/truefa-py/releases/tag/v0.1.0)

#### From Source
```bash
git clone https://github.com/zainibeats/truefa-py.git && cd truefa-py
python -m venv venv && .\venv\Scripts\Activate.ps1
pip install -r requirements.txt
python main.py
```

#### Building the Application
```powershell
# Build the portable executable with Rust crypto
.\dev-tools\build.ps1 -BuildRust -Clean -Portable

# Build with installer
.\dev-tools\build.ps1 -BuildRust -Clean -Installer

# Build with both portable and installer
.\dev-tools\build.ps1 -BuildRust -Clean -Portable -Installer
```

### Docker (Recommended)

#### Quick Run (Non-Persistent)
```powershell
# Basic run with temporary volumes (PowerShell)
.\docker\run_docker.ps1
```

#### Persistent Storage Run
```powershell
# First-time run - builds image and creates persistent storage
.\docker\run_docker_persistent.ps1

# Subsequent runs - reuse existing Docker image without rebuilding
docker run -it --rm `
    -v "${PWD}/images:/app/images" `
    -v "${PWD}/vault_data:/home/truefa/.truefa" `
    -e "TRUEFA_PORTABLE=1" `
    -e "TRUEFA_DATA_DIR=/home/truefa/.truefa" `
    truefa-py
```

#### Docker Container Features
- **Persistent Storage**: Vault data and exports are stored in the host system's `vault_data` directory
- **QR Code Support**: Place images in the local `images` folder for scanning inside the container
- **Secure Export**: Exports are saved to the `vault_data/exports` directory on the host system
- **Environment Configuration**: Uses `TRUEFA_DATA_DIR` for consistent vault location between runs
- **Cross-Platform**: Works on Windows, macOS and Linux host systems

#### Manual Configuration
```bash
# Build the Docker image
docker build -t truefa-py -f docker/Dockerfile .

# Run with persistent storage
docker run -it --rm \
  -v "$(pwd)/vault_data:/home/truefa/.truefa" \
  -v "$(pwd)/images:/app/images" \
  -e "TRUEFA_PORTABLE=1" \
  -e "TRUEFA_DATA_DIR=/home/truefa/.truefa" \
  truefa-py
```

> **Note**: The Windows Docker container in `docker/windows` is for development testing only and not intended for end users.

## Cross-Platform Compatibility

TrueFA-Py is designed with robust cross-platform compatibility:

- **Rust Cryptography Module**: Provides high-performance, memory-safe cryptographic operations on Windows
- **Python Fallback Implementation**: Automatically activates when the Rust module cannot be loaded
- **Intelligent Detection**: Seamlessly switches between implementations based on your environment

This dual-implementation approach ensures the application works flawlessly across different systems and environments.

## Documentation

- [Development Status](docs/DEVELOPMENT_STATUS.md) - Recent improvements and current state
- [Developer Guide](docs/DEVELOPER_GUIDE.md) - Development setup, testing, and technical details
- [Documentation Index](docs/README.md) - Overview of all available documentation

## Basic Usage

```bash
# Start the application
python main.py

# Show version information
python main.py --version

# Enable debugging / Disable logs (combine as needed)
python main.py --debug --no-log
```

This will start the command-line interface with the following options:
1. Load QR code from image
2. Enter secret key manually
3. Save current secret
4. View saved secrets
5. Export secrets
6. Import secrets
7. Clear screen
8. Delete vault
9. Exit

For details on all command-line options, logging configuration, and development information, please refer to the [Developer Guide](docs/DEVELOPER_GUIDE.md).

## License

This project is licensed under the MIT License.
