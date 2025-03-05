# TrueFA-Py Documentation

This directory contains comprehensive documentation for the TrueFA-Py project.

## Documentation Index

### Core Documentation

- [BUILD_GUIDE.md](BUILD_GUIDE.md) - Detailed instructions for building TrueFA-Py
- [SECURITY_GUIDE.md](SECURITY_GUIDE.md) - Security model and cryptography implementation
- [TESTING_GUIDE.md](TESTING_GUIDE.md) - Testing infrastructure and results

### Legacy Documentation

These documents are kept for reference but have been consolidated into the guides above:

- [BUILD_INSTRUCTIONS.md](BUILD_INSTRUCTIONS.md) - Legacy build instructions
- [SECURITY_CRYPTO.md](SECURITY_CRYPTO.md) - Legacy security documentation
- [TESTING_SUMMARY.md](TESTING_SUMMARY.md) - Legacy testing summary

## Project Structure

TrueFA-Py is organized as follows:

```
truefa-py/
├── assets/                  # Application assets (icons, etc.)
├── dev-tools/               # Development tools
│   ├── build-tools/         # Build and packaging scripts
│   ├── docker-tests/        # Docker testing configurations
│   ├── vm-testing/          # VM testing tools
│   └── ...                  # Core dev tools
├── docs/                    # Documentation
├── rust_crypto/             # Rust cryptography module
├── src/                     # Python source code
├── truefa_crypto/           # Cryptography module with fallbacks
├── main.py                  # Application entry point
├── requirements.txt         # Python dependencies
└── README.md                # Project overview
```

## Development Tools

The `dev-tools` directory contains various scripts and utilities for development:

- **Build Tools**: Scripts for building the application and creating packages
- **Docker Tests**: Configuration and scripts for testing in Docker containers
- **VM Testing**: Tools for testing in Windows VMs
- **Core Tools**: Utilities for development tasks

## Quick Start

For a quick start with development, refer to the [BUILD_GUIDE.md](BUILD_GUIDE.md) document.

For testing the application, refer to the [TESTING_GUIDE.md](TESTING_GUIDE.md) document.

For understanding the security model, refer to the [SECURITY_GUIDE.md](SECURITY_GUIDE.md) document.
