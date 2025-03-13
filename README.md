# TrueFA-Py - Secure TOTP Authenticator

TrueFA-Py is a secure, offline Two-Factor Authentication (2FA) application built with Python and Rust. It provides a robust command-line interface for managing TOTP (Time-based One-Time Password) authentication codes while keeping your security tokens encrypted and stored locally.

**[View Recent Development Status and Progress](docs/DEVELOPMENT_STATUS.md)**

## Features

- 🔑 Encrypted local vault with master password protection
- 📷 QR code scanning from image files
- 🔐 Strong encryption for your authentication secrets
- 📥 Save and retrieve TOTP secrets securely
- 📤 Import and export functionality with encrypted JSON format
- 🔄 Interoperability with other authenticator applications
- 🐳 Docker compatibility for containerized environments

## Security

TrueFA-Py implements a comprehensive security model to protect your authentication secrets:

- Strong encryption with multiple protection layers
- Secure memory handling
- No network transmission of sensitive data

For detailed information, see the [Security Documentation](docs/SECURITY.md).

## Quick Start

### Windows

#### Prerequisites
- **Visual C++ Redistributable 2015-2022** - [Download from Microsoft](https://aka.ms/vs/17/release/vc_redist.x64.exe)

#### From Source
```bash
git clone https://github.com/zainibeats/truefa-py.git && cd truefa-py
python -m venv venv && .\venv\Scripts\Activate.ps1
pip install -r requirements.txt
python main.py
```

### Docker

```powershell
# Quick run with temporary storage
.\docker\run_docker.ps1

# Run with persistent vault data
.\docker\run_docker_persistent.ps1
```

## Basic Usage

```bash
# Start the application
python main.py

# Show version information
python main.py --version

# Enable debug output
python main.py --debug

# Disable logging to file
python main.py --no-log
```

The command-line interface provides these options:
1. Load QR code from image
2. Enter secret key manually
3. Save current secret
4. View saved secrets
5. Export secrets (encrypted JSON format)
6. Import secrets (from encrypted JSON)
7. Clear screen
8. Delete vault
9. Exit

## Documentation

- [User Guide](docs/README.md) - Overview of all available documentation

## License

This project is licensed under the MIT License.
