# TrueFA-Py Documentation

Welcome to the TrueFA-Py documentation. This directory contains comprehensive guides to help you use, understand, and contribute to TrueFA-Py.

## Documentation Index

### For Users

- [**Main README**](../README.md) - Installation, features, usage, and security architecture
- [**Security Documentation**](SECURITY.md) - Detailed security model and implementation

### For Developers

- [**Developer Guide**](DEVELOPER_GUIDE.md) - Development setup, testing, Rust integration, build process, and security considerations
- [**Development Status**](DEVELOPMENT_STATUS.md) - Current state of the project, recent improvements, and planned enhancements
- [**Dev Tools README**](../dev-tools/README.md) - Build scripts and development utilities documentation

## Project Structure

```
truefa-py/
├── docs/                 # Documentation files
├── dev-tools/            # Development and build tools
│   ├── tests/            # Testing scripts
│   └── build-tools/      # Build configuration files
├── docker/               # Docker files
├── rust_crypto/          # Rust cryptography module
│   └── src/              # Rust source code
├── src/                  # Python source code
│   ├── totp/             # TOTP implementation
│   ├── security/         # Security and vault management
│   ├── truefa_crypto/    # Crypto module with Rust bindings
│   └── utils/            # Utility functions
├── images/               # Directory for QR code images
└── main.py               # Main application entry point
```

## Getting Started

- For **installation and usage**, see the [Main README](../README.md)
- For **development setup**, see the [Developer Guide](DEVELOPER_GUIDE.md)
- For **project status**, see the [Development Status](DEVELOPMENT_STATUS.md)
- For **security details**, see the [Security Documentation](SECURITY.md)

## Additional Resources

- GitHub Repository: [TrueFA-Py](https://github.com/zainibeats/truefa-py)
- Issue Tracker: [GitHub Issues](https://github.com/zainibeats/truefa-py/issues)
