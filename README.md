# TrueFA-Py - Secure TOTP Authenticator

TrueFA-Py is a secure, offline Two-Factor Authentication (2FA) application built with Python and Rust. It provides a robust command-line interface for managing TOTP (Time-based One-Time Password) authentication codes while keeping your security tokens encrypted and stored locally in a secure vault.

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

- Windows 10 or higher is recommended
- Visual C++ Redistributable 2015-2022 must be installed 
  - Automatically installed by the setup script
  - Can be downloaded from [Microsoft](https://aka.ms/vs/17/release/vc_redist.x64.exe)
- Use the bundled launcher script that properly configures the environment

#### Quick Install
- Download the latest `TrueFA-Py_Setup.exe` from the [releases page](https://github.com/zainibeats/truefa-py/releases)
- Run the installer and follow the instructions
- Launch from the Start Menu or Desktop shortcut

#### Portable Version
- Download `TrueFA-Py-Portable.zip` from the [releases page](https://github.com/zainibeats/truefa-py/releases)
- Extract and run `TrueFA-Py.exe`

### Docker

#### Quick Run (Non-Persistent)
```bash
# Basic run with temporary volumes (PowerShell)
.\run_docker.ps1
```

#### Persistent Storage Run
```bash
# Run with persistent vault data and local images folder (PowerShell)
.\run_docker_persistent.ps1
```

#### Manual Configuration
```bash
# Build the Docker image
docker build -t truefa-py .

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
- Use the Python fallback implementation in Docker for better compatibility

### From Source
```bash
git clone https://github.com/zainibeats/truefa-py.git && cd truefa-py
python -m venv venv && .\venv\Scripts\Activate.ps1
pip install -r requirements.txt
python main.py
```

## Development

See the [Developer Guide](docs/DEVELOPER_GUIDE.md) for complete development setup, building instructions, and architecture details.

### Quick Build
```powershell
# Complete package build (portable and installer)
.\dev-tools\build.ps1 -BuildRust -Clean -Portable -Installer
```

## Documentation

- [User Guide](docs/USER_GUIDE.md) - Installation, configuration, and usage
- [Developer Guide](docs/DEVELOPER_GUIDE.md) - Development setup and technical details
- [FAQ](docs/FAQ.md) - Common questions and troubleshooting

## Security Architecture

TrueFA-Py uses a hybrid approach with a Rust cryptography module for performance and security, with a Python fallback implementation. The secure vault employs envelope encryption:

1. **Vault Password** - Unlocks the vault and decrypts the master key
2. **Master Key** - Encrypts/decrypts individual TOTP secrets

## License

This project is licensed under the MIT License. See the LICENSE file for details.

## Contributing

Contributions are welcome! Please refer to the [Developer Guide](docs/DEVELOPER_GUIDE.md) for contribution guidelines.
