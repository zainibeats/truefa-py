# TrueFA-Py - Secure TOTP Authenticator

TrueFA-Py is a secure, offline Two-Factor Authentication (2FA) application built with Python and Rust. It provides a robust command-line interface for managing TOTP (Time-based One-Time Password) authentication codes while keeping your security tokens encrypted and stored locally in a secure vault.

**[View Recent Development Status and Progress](docs/DEVELOPMENT_STATUS.md)**

## Features

- 🔑 Encrypted local vault with master password
- 📷 QR code scanning from image files
- 🔐 Two-layer security architecture with envelope encryption
- 🛡️ Optimized Rust crypto module with robust fallback mechanisms
- 🖥️ Portable executable with no installation required
- 🔍 Multiple vault location detection capabilities
- 📥 Save and retrieve TOTP secrets
- 🐳 Optional docker installation

## Installation & Usage

### Windows

TrueFA-Py provides two deployment options for Windows systems:

#### Quick Install (Recommended)
- Download the latest `TrueFA-Py_Setup.exe` from the [releases page](https://github.com/zainibeats/truefa-py/releases)
- Run the installer and follow the instructions
- Launch from the Start Menu or Desktop shortcut

#### Portable Version
- Download `TrueFA-Py-Portable.zip` from the [releases page](https://github.com/zainibeats/truefa-py/releases)
- Extract and run `TrueFA-Py.exe`

#### System Requirements
- Windows 10 or higher is recommended
- Visual C++ Redistributable 2015-2022 must be installed 
  - Automatically installed by the setup script
  - Can be downloaded from [Microsoft](https://aka.ms/vs/17/release/vc_redist.x64.exe)

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

### From Source
```bash
git clone https://github.com/zainibeats/truefa-py.git && cd truefa-py
python -m venv venv && .\venv\Scripts\Activate.ps1
pip install -r requirements.txt
python main.py
```

## Cross-Platform Compatibility

TrueFA-Py is designed with robust cross-platform compatibility:

- **Rust Cryptography DLL**: Provides high-performance, memory-safe cryptographic operations on Windows
- **Python Fallback Implementation**: Automatically activates when the Rust DLL cannot be loaded
- **Intelligent Detection**: Seamlessly switches to the appropriate implementation based on your environment

This dual-implementation approach ensures the application works flawlessly across different Windows systems and other platforms.

## Documentation

- [User Guide](docs/USER_GUIDE.md) - Installation, configuration, and usage
- [Developer Guide](docs/DEVELOPER_GUIDE.md) - Development setup and technical details
- [FAQ](docs/FAQ.md) - Common questions and troubleshooting
- [Windows Testing](docs/WINDOWS_TESTING.md) - Details on Windows compatibility testing
- [Development Status](docs/DEVELOPMENT_STATUS.md) - Recent improvements and upcoming features

## Development Setup

```bash
git clone https://github.com/zainibeats/truefa-py.git && cd truefa-py
python -m venv venv && .\venv\Scripts\Activate.ps1  # On Windows
pip install -r requirements.txt

# For Rust crypto development
cd rust_crypto
cargo build --release
cd ..
```

## Usage

```bash
python main.py
```

This will start the command-line interface with the following options:
1. Load QR code from image
2. Enter secret key manually
3. Save current secret
4. View saved secrets
5. Export secrets
6. Clear screen
7. Exit

## License

This project is licensed under the MIT License.

## Contributing

Contributions are welcome! Please refer to the [Developer Guide](docs/DEVELOPER_GUIDE.md) for contribution guidelines.

## Security Architecture

TrueFA-Py uses a hybrid approach with a Rust cryptography module for performance and security, with a Python fallback implementation. The secure vault employs envelope encryption:

1. **Vault Password** - Unlocks the vault and decrypts the master key
2. **Master Key** - Encrypts/decrypts individual TOTP secrets

## Contact

For issues or questions, please contact the project maintainer.
