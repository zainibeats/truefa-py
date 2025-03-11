# TrueFA-Py Developer Guide

This guide provides information for developing, building, testing, and securing TrueFA-Py.

## Table of Contents

1. [Development Environment Setup](#development-environment-setup)
2. [Building TrueFA-Py](#building-truefa-py)
3. [Rust Cryptography Integration](#rust-cryptography-integration)
4. [Logging System](#logging-system)
5. [Testing](#testing)
6. [Security Considerations](#security-considerations)
7. [Distribution](#distribution)
8. [Troubleshooting](#troubleshooting)

## Development Environment Setup

### Prerequisites

- **Python 3.10+**: [python.org](https://www.python.org/downloads/) (ensure it's in PATH)
- **Rust**: Install via [rustup](https://rustup.rs/) (required for cryptography)
- **NSIS**: [NSIS website](https://nsis.sourceforge.io/Download) (for Windows installers)
- **Visual C++ Redistributable 2015-2022**: [Microsoft](https://aka.ms/vs/17/release/vc_redist.x64.exe) (required for Windows)

### Setting up the Development Environment

```powershell
# Clone and set up the repository
git clone https://github.com/zainibeats/truefa-py.git && cd truefa-py
python -m venv venv && .\venv\Scripts\Activate.ps1
pip install -r dev-tools/dev-requirements.txt
python dev-tools\setup.py
```

### Key Components

1. **Cryptography Module** (`src/truefa_crypto/`): Rust bindings with Python fallbacks
2. **TOTP Implementation** (`src/totp/`): TOTP generation and QR code processing
3. **Vault Management** (`src/security/`): Encrypted storage and authentication
4. **Configuration System** (`src/config.py`): Settings and path management

### Environment Variables

TrueFA-Py supports several environment variables to customize behavior:

| Variable | Description | Default |
|----------|-------------|---------|
| `TRUEFA_PORTABLE` | Enable portable mode (1=yes) | Current directory |
| `TRUEFA_DATA_DIR` | Override data directory | Platform user directory |
| `TRUEFA_USE_FALLBACK` | Force Python fallback (1=yes) | Auto-detection |
| `TRUEFA_DEBUG` | Enable debug mode (1=yes) | Disabled |
| `TRUEFA_LOG` | Enable file logging (1=yes) | Enabled |

## Building TrueFA-Py

### Building the Rust Cryptography Module

```powershell
# Build the Rust library (direct or via script)
cd rust_crypto && cargo build --release && cd ..
# OR
python dev-tools\build_rust.py
```

### Building the Application

```powershell
# Build options (combine as needed)
.\dev-tools\build.ps1 [-BuildRust] [-Clean] [-Portable] [-Installer] [-Console] [-Fallback]

# Example: Build everything with fresh Rust compilation
.\dev-tools\build.ps1 -BuildRust -Clean -Portable -Installer
```

This creates:
- `dist/TrueFA-Py.exe` (portable version)
- `dist/TrueFA-Py_Setup_0.1.0.exe` (installer version)

## Rust Cryptography Integration

TrueFA-Py uses Rust for critical cryptographic operations with Python fallbacks when needed.

### Key Functions

| Function | Purpose |
|----------|---------|
| `c_secure_random_bytes` | Secure random bytes generation |
| `c_generate_salt` | Salt creation for key derivation |
| `c_create_secure_string` | Protected memory for sensitive data |
| `c_derive_master_key` | Master key derivation from password |
| `c_encrypt/decrypt_master_key` | Key encryption/decryption |

### Recent Improvements

- Fixed function exports with proper error handling
- Enhanced DLL loading with multi-location search
- Implemented secure memory management
- Added comprehensive verification and test suites

### Intelligent Fallback

The system automatically detects issues and falls back to Python:
- Function-level error monitoring
- Session state caching
- Manual override via `TRUEFA_USE_FALLBACK=1`

### Testing Rust Integration

```bash
# Verify the integration with these tools
python dev-tools/tests/verify_dll_exports.py  # Checks FFI exports
python dev-tools/tests/verify_rust_crypto.py  # Tests functionality
```

## Logging System

TrueFA-Py implements a standardized logging system based on Python's built-in `logging` module.

### Logging Architecture

The logging system in `src/utils/logger.py` provides:

1. **Dual-Channel Logging**:
   - Console output (configurable level)
   - File logging (separate level control)
   - Control via command-line flags: `--debug`, `--no-log`

2. **Log Levels**:
   - DEBUG: Detailed development information
   - INFO: General information messages
   - WARNING: Potential issues (default console level)
   - ERROR: Operation failures
   - CRITICAL: Application-breaking issues

3. **File Organization**:
   - Log files stored in `~/.truefa/logs/`
   - Timestamp-based naming: `truefa_YYYYMMDD_HHMMSS.log`

### Logging vs. Debug System

TrueFA-Py has two systems for different purposes:

- **Logging System** (`logger.py`): Structured, persistent logging with multiple levels
- **Debug System** (`debug.py`): Simple on/off toggle for development-time debugging

For all new code, use the logging system functions.

### Usage

#### Command-Line Options

```bash
# Standard: warnings in console, all to file
python main.py

# Debug mode: debug messages in console, all to file
python main.py --debug

# No file logging: warnings in console only
python main.py --no-log
```

#### Logging Functions

```python
from src.utils.logger import debug, info, warning, error, critical

# For detailed implementation details
debug("Processing value: {}", some_value)

# For general information
info("Operation completed successfully")

# For potential issues that don't stop execution
warning("Deprecated method used")

# For operation failures
error("Failed to open file: {}", filename)

# For application-breaking issues
critical("System cannot continue: {}", error_msg)
```

### Best Practices

1. **Use Appropriate Levels** based on message importance and audience
2. **Include Context** such as object IDs and relevant values (avoid logging secrets)
3. **Configure External Modules** with `logging.getLogger('module_name').setLevel(level)`

### Log Format

```
[2023-03-09 15:42:45] DEBUG [main.py:154]: Importing modules...
[2023-03-09 15:42:45] INFO [vault.py:235]: Vault created successfully
[2023-03-09 15:42:46] WARNING [secure_memory.py:102]: Fallback implementation used
```

Each entry includes timestamp, level, source location, and the actual message.

## Testing

### Unit and Integration Testing

```bash
# Run unit tests
pytest dev-tools/tests/  # All tests
pytest dev-tools/tests/test_vault_creation.py  # Specific test

# Clean test data when needed
python dev-tools/clean_truefa.py
```

### Windows Docker Container Testing

#### Prerequisites
- Docker Desktop (Windows containers mode)
- Built executables in `dist` directory

#### Test Environment Setup

The Docker testing environment includes:
- **Dockerfile** with Visual C++ Redistributable and test files
- **Verification Script** to check DLL functionality
- **Test Runner Script** with volume support for persistence testing
- **Test QR Code** for verifying QR functionality

#### Running Docker Tests

```powershell
# Container management options (combine as needed)
.\docker\windows\run_vault_test_docker.ps1 [-Clean] [-Resume] [-BuildImage]
```

#### Testing Areas

Inside the container, test these key areas:

1. **Portable Executable**: Basic functionality and vault operations
   ```cmd
   TrueFA-Py.exe --create-vault --vault-dir C:\vault_data
   TrueFA-Py.exe --vault-dir C:\vault_data
   ```

2. **QR Code Scanning**: Using the included test image
   ```cmd
   # When prompted for QR code path, enter:
   C:\TrueFA\images\test_qr.png
   ```

3. **Installer**: Silent installation and functionality
   ```cmd
   # Install and verify
   TrueFA-Py_Setup_0.1.0.exe /S
   dir "C:\Program Files (x86)\TrueFA-Py"
   "C:\Program Files (x86)\TrueFA-Py\TrueFA-Py.exe" --vault-dir C:\vault_data
   
   # Optional: Test uninstallation
   "C:\Program Files (x86)\TrueFA-Py\Uninstall.exe" /S
   ```

4. **Persistence**: Test across container restarts using the Resume flag

#### Troubleshooting Docker Tests

Common issues include:
- **DLL Loading Problems**: Check DLL presence and Visual C++ installation
- **QR Code Issues**: Verify test image exists and path is correct
- **Container Access**: Ensure Windows containers mode and proper permissions
- **Installation Issues**: Check paths and try without silent mode if needed

## Security Considerations

TrueFA-Py implements a comprehensive security model to protect sensitive authentication data. For detailed information about the security implementation, please refer to the [Security Documentation](SECURITY.md).

### Key Security Features

- Two-layer encryption model with PBKDF2 and AES-GCM
- Secure memory handling with automatic zeroing
- Rust implementation of critical cryptographic functions
- Platform-specific security optimizations

For security auditing, focus on these critical components:

1. Rust cryptography in `rust_crypto/src/`
2. Python-Rust binding in `src/truefa_crypto/__init__.py`
3. Vault implementation in `src/security/vault.py`
4. TOTP handling in `src/totp/auth_opencv.py`

## Distribution

### Windows Distribution

```powershell
# Create distribution packages (combine as needed)
.\dev-tools\build.ps1 -BuildRust -Clean -Portable -Installer
```

### Portable Distribution

- Output: `dist/TrueFA-Py.exe`
- Self-contained with minimal dependencies
- Supports custom vault locations

## Troubleshooting

### Common Issues

#### Rust DLL Not Found
- Ensure Rust is installed and DLL is built
- Check expected locations or use fallback (`TRUEFA_USE_FALLBACK=1`)

#### Build Failures
- Use `-Clean` option for fresh builds
- Check for Python environment conflicts

#### Permission Issues
- Run as administrator for system directories
- Use custom vault location with `-VaultDir` option
