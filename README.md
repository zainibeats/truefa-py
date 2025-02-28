# TrueFA

A secure two-factor authentication code generator with support for QR code scanning and encrypted storage.

A secure two-factor authentication code generator with Rust-powered cryptography, QR code scanning, and encrypted storage.

## Key Features

- **Rust-Based Security**: Critical cryptographic operations in Rust
- **Secure Memory Handling**: Protected memory with automatic cleanup
- **Vault Encryption**: Two-layer envelope encryption for TOTP secrets
- **QR Code Support**: OpenCV-based QR code scanning
- **Flexible Operation**: Use with or without persistent storage
- **Cross-Platform**: Windows, Linux, and macOS support

## Installation & Usage

Choose one of these three methods to run TrueFA:

### 1. Windows Executable (Recommended for Windows Users)
Download the latest release from our [releases page](https://github.com/zainibeats/truefa-py/releases) and run `TrueFA.exe`.

### 2. Docker Container (Recommended for Linux/macOS)
```bash
# Build and run with Docker
docker build -t truefa .
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

### 3. From Source
Prerequisites:
- Python 3.8+
- Rust and Cargo
- GPG (optional, for secret export)

```bash
# Clone and setup
git clone https://github.com/zainibeats/truefa-py.git
cd truefa-py
pip install -r requirements.txt
python build_rust.py

# Run on Windows
run_truefa.bat           # Main launcher (recommended)
run_direct_simple.bat    # Without QR scanning
run_opencv.bat          # With QR scanning

# Run on Linux/macOS
python -m src.main
```

## Basic Usage

1. Launch TrueFA using your chosen installation method
2. Choose your operation mode:
   - Scan QR codes from images
   - Enter TOTP secrets manually
   - Save/load encrypted secrets
   - Export secrets (requires GPG)

## Security Features

- **Envelope Encryption**: Dual-layer protection with vault and master keys
- **Memory Safety**: Rust-based secure memory handling
- **Zero Trust**: Stateless operation by default
- **Secure Storage**: AES-GCM encryption with Scrypt key derivation

## Documentation

- [QR Code Guide](QR_CODE_GUIDE.md)
- [Runner Scripts](README_RUNNERS.md)

## Contributing

This project is under active development. Issues and pull requests are welcome.

## License

MIT License - See [LICENSE](LICENSE) for details.
