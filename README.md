# TrueFA

A secure two-factor authentication code generator with support for QR code scanning and encrypted storage.

## Features

- **Enhanced Security with Rust Cryptography** - Critical security operations handled by Rust
- **Vault-Based Envelope Encryption** - Two-layer encryption for maximum protection
- Secure memory handling for sensitive data
- QR code scanning support
- Encrypted storage of TOTP secrets
- Stateless operation mode (no master password required for viewing codes on fresh install)
- Cross-platform support

## Installation

### Option 1: Docker (Recommended)

1. Clone the repository:
```bash
git clone https://github.com/zainibeats/truefa.git
cd truefa
```

2. Build and run with Docker:
```bash
# Build the Docker image
docker build -t truefa .

# Run the container
docker run -it --name truefa \
  -v "${PWD}/images:/app/images" \
  -v "${PWD}/.truefa:/app/.truefa" \
  -v "$HOME/Downloads:/home/truefa/Downloads" \
  truefa

# On Windows PowerShell, use:
docker run -it --name truefa `
  -v "${PWD}\images:/app/images" `
  -v "${PWD}\.truefa:/app/.truefa" `
  -v "$HOME\Downloads:/home/truefa/Downloads" `
  truefa

# For subsequent runs:
docker start -ai truefa
```

### Option 2: Direct Installation

**Prerequisites:**
- Python 3.8+
- [Rust and Cargo](https://rustup.rs/)
- ZBar (for QR code scanning)
- GPG (for export functionality)

#### Windows Prerequisites

1. Install ZBar: [ZBar Windows Binaries](https://sourceforge.net/projects/zbar/files/zbar/0.10/zbar-0.10-setup.exe/download)
2. Install GPG: [GPG4Win](https://www.gpg4win.org/download.html)

#### Linux/macOS Prerequisites

- Ubuntu/Debian: `sudo apt-get install libzbar0 zbar-tools gpg`
- macOS: `brew install zbar gpg`

#### Installation Steps

1. Clone the repository and install dependencies:
```bash
git clone https://github.com/zainibeats/truefa.git
cd truefa
pip install -r requirements.txt
```

2. Build the Rust crypto module and run:
```bash
python build_rust.py
python -m src.main
```

## Usage

### Basic Usage

1. Place QR code images in the `images` directory
2. Run the application (via Docker or directly)
3. Use the interactive menu to:
   - Load QR codes from images
   - Enter TOTP secrets manually
   - Save/load secrets securely
   - Export secrets (saved to Downloads folder)

### Stateless Operation

By default, TrueFA operates in stateless mode:
- Scan QR codes or enter secrets without setting a master password
- No data is saved unless explicitly chosen
- Saved secrets are encrypted with your master password

## Security Architecture

TrueFA implements a high-security architecture:

- **Envelope Encryption** - Two-layer encryption with vault password (outer) and master key (inner)
- **Rust-Based Memory Safety** - Critical cryptographic operations implemented in Rust
- **AES-GCM encryption** with Scrypt key derivation
- **Secure memory handling** with page locking and memory zeroization

## Project Structure

```
truefa/
├── src/               # Core application code
│   ├── security/      # Security-related modules
│   ├── totp/          # TOTP-related functionality
│   ├── utils/         # Utility functions
│   └── main.py        # Main application entry point
├── images/            # Directory for QR code images
├── .truefa/           # Secure storage directory
├── Dockerfile         # Docker configuration
├── requirements.txt   # Python dependencies
├── build_rust.py      # Rust module build script
├── build_module.py    # Python module build script
└── README.md          # This file
```

## License

This project is licensed under the MIT License. See the LICENSE file for details.
