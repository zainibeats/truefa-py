# TrueFA-Py - Secure TOTP Authenticator

TrueFA-Py is a secure, offline Two-Factor Authentication (2FA) application built with Python and Rust. It provides a robust command-line interface for managing TOTP (Time-based One-Time Password) authentication codes while keeping your security tokens encrypted and stored locally in a secure vault.

**[View Recent Development Status and Progress](docs/DEVELOPMENT_STATUS.md)**

## Features

- 🔑 Encrypted local vault with master password
- 📷 QR code scanning from image files
- 🔐 Two-layer security architecture with envelope encryption
- 🛡️ High-performance Rust crypto with memory protection and automatic fallback
- 🔄 Session persistence with password caching for convenience
- 📥 Save and retrieve TOTP secrets with robust encryption
- 🔍 Intelligent vault location detection with permission handling
- 📊 Flexible logging system with independent console and file logging control
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

#### From Source (Current Method)
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

### Docker

#### Quick Run (Non-Persistent)
```bash
# Basic run with temporary volumes (PowerShell)
.\docker\run_docker.ps1
```

#### Persistent Storage Run
```bash
# Run with persistent vault data and local images folder (PowerShell)
.\docker\run_docker_persistent.ps1
```

#### Manual Configuration
```bash
# Build the Docker image
docker build -t truefa-py -f docker/Dockerfile .

# Run with persistent storage
docker run -it --rm \
  -v "truefa-vault:/home/truefa/.truefa" \
  -v "./images:/app/images" \
  -e "TRUEFA_USE_FALLBACK=1" \
  -e "TRUEFA_PORTABLE=1" \
  truefa-py
```

**Notes for Docker Usage:**
- The `/app/images` directory in the container is mapped to a local `images` folder
- Place your QR code images in the local `images` folder
- Vault data is stored in a Docker volume for persistence

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

# Enable debug output
python main.py --debug

# Disable logging to file
python main.py --no-log
```

This will start the command-line interface with the following options:
1. Load QR code from image
2. Enter secret key manually
3. Save current secret
4. View saved secrets
5. Export secrets
6. Clear screen
7. Exit

For details on all command-line options, logging configuration, and development information, please refer to the [Developer Guide](docs/DEVELOPER_GUIDE.md).

## Security Architecture

TrueFA-Py uses a hybrid approach with a Rust cryptography module for performance and security, with a Python fallback implementation. The secure vault employs envelope encryption:

1. **Vault Password** - Unlocks the vault and decrypts the master key
2. **Master Key** - Encrypts/decrypts individual TOTP secrets

Key security features include:
- Memory protection with automatic zeroing of sensitive data
- AES-256-CBC authenticated encryption
- Session state management to minimize password entry
- Envelope encryption to protect master keys and individual secrets

## License

This project is licensed under the MIT License.

## Contributing

Contributions are welcome! Please refer to the [Developer Guide](docs/DEVELOPER_GUIDE.md) for contribution guidelines.

