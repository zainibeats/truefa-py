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

## Recent Improvements

### Enhanced Security Architecture
- **Robust Fallback Design**: The application now gracefully falls back to Python implementations when the Rust library cannot be loaded or when specific functions are missing.
- **Advanced Vault System**: Implemented a secure storage vault with proper envelope encryption for additional security.
- **Improved Error Handling**: Better error messages and debugging output throughout the application.
- **Hardened Vault Authentication**: Enhanced password verification using PBKDF2 with constant-time comparison to prevent timing attacks.
- **Security State Consistency**: Multiple validation layers ensure vault unlock state is correctly tracked to prevent unauthorized access.
- **Password Hash Storage**: Vault metadata now stores password hashes with secure salting for robust authentication.
- **Automatic Vault Upgrade**: Legacy vaults are automatically upgraded to include password hashes for better security.

### Security Model
- **Two-Layer Authentication**: 
  - Vault password unlocks the vault and verifies against stored hash
  - Master key is used for encrypting/decrypting individual TOTP secrets
- **Defense-in-Depth**: Multiple security checks ensure critical operations only proceed when authentication is valid
- **No Trust Assumptions**: Every authentication step is verified, preventing bugs in one component from compromising security

### Fixed Issues
- Resolved PyInstaller packaging issues
- Fixed TOTP generation and QR code scanning
- Ensured resource files are correctly packaged with the executable
- Enhanced file path handling for better cross-platform support
- Fixed critical authentication issues in the secure vault implementation
- Eliminated potential for vault state inconsistencies that could lead to unauthorized access

### Development
- Added automated tests for critical functionality 
- Improved build scripts with better validation and error reporting
- Enhanced code structure for better maintainability
- Added comprehensive debug logging for security-critical functions

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
- **Password Verification**: PBKDF2 with 100,000 iterations and secure salt handling
- **Secure Comparison**: Constant-time hash comparison prevents timing attacks
- **Defensive Programming**: Multiple security checks with explicit fail-safe behavior

## Documentation

- [QR Code Guide](QR_CODE_GUIDE.md)
- [Runner Scripts](README_RUNNERS.md)

## Contributing

This project is under active development. Issues and pull requests are welcome.

## License

MIT License - See [LICENSE](LICENSE) for details.
