# TrueFA-Py Developer Guide

This comprehensive guide provides all the information needed for developing, building, and testing TrueFA-Py.

## Table of Contents

1. [Development Environment Setup](#development-environment-setup)
2. [Project Structure](#project-structure)
3. [Building TrueFA-Py](#building-truefa-py)
4. [Rust Cryptography Integration](#rust-cryptography-integration)
5. [Testing](#testing)
6. [Distribution](#distribution)
7. [Troubleshooting](#troubleshooting)

## Development Environment Setup

### Prerequisites

Before developing TrueFA-Py, ensure you have the following installed:

1. **Python 3.10 or later**
   - Download from [python.org](https://www.python.org/downloads/)
   - Ensure Python is added to your PATH during installation

2. **Rust** (Required for cryptography backend)
   - Install using [rustup](https://rustup.rs/)
   - Follow the installation instructions for your platform

3. **NSIS** (Optional, for creating Windows installers)
   - Download from [NSIS website](https://nsis.sourceforge.io/Download)
   - Install with default options

4. **Visual C++ Redistributable 2015-2022** (Required for Windows)
   - Download from [Microsoft](https://aka.ms/vs/17/release/vc_redist.x64.exe)
   - Required for using the Rust cryptography module

### Setting up the Development Environment

```powershell
# Clone the repository
git clone https://github.com/zainibeats/truefa-py.git
cd truefa-py

# Create a virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt

# Setup development environment
python dev-tools\setup.py
```

## Project Structure

TrueFA-Py is organized as follows:

```
truefa-py/
├── assets/                  # Application assets (icons, etc.)
├── dev-tools/               # Development tools
│   ├── build-tools/         # Build and packaging scripts
│   └── docker/              # Docker testing configurations
├── docs/                    # Documentation
├── rust_crypto/             # Rust cryptography module
│   ├── src/                 # Rust source code
│   └── Cargo.toml           # Rust package configuration
├── src/                     # Python source code
│   ├── totp/                # TOTP implementation
│   │   ├── auth.py          # Core TOTP functionality (pyzbar)
│   │   └── auth_opencv.py   # Alternative TOTP implementation (OpenCV)
│   ├── truefa_crypto/       # Cryptography module with fallbacks
│   └── vault/               # Secure vault implementation
├── main.py                  # Application entry point
└── requirements.txt         # Python dependencies
```

### Key Components

1. **Cryptography Module** (`src/truefa_crypto/`):
   - Provides bindings to the Rust cryptography library
   - Includes Python fallback implementations
   - Handles DLL loading and error detection

2. **TOTP Implementation** (`src/totp/`):
   - Implements time-based one-time password generation
   - Handles QR code scanning and processing
   - Provides secure password management

3. **Vault Management** (`src/vault/`):
   - Implements secure storage for TOTP secrets
   - Handles encryption and decryption of vault contents
   - Manages user authentication and security

## Building TrueFA-Py

### Building the Rust Cryptography Module

The Rust cryptography module must be built before the Python application:

```powershell
# Build the Rust library
cd rust_crypto
cargo build --release
cd ..

# Alternatively, use the build script:
python dev-tools\build_rust.py
```

### Building Options

TrueFA-Py includes several build tools in the `dev-tools` directory:

#### 1. PowerShell Build Script (Recommended)

```powershell
# Basic build (creates portable EXE and installer)
.\dev-tools\build.ps1

# Build only portable EXE
.\dev-tools\build.ps1 -Portable

# Build with Rust cryptography backend first
.\dev-tools\build.ps1 -BuildRust -Clean -Portable

# Build with console window (for debugging)
.\dev-tools\build.ps1 -Console

# Force use of Python fallback implementation
.\dev-tools\build.ps1 -Fallback
```

#### 2. Python Build Package Script

```powershell
# Build both portable EXE and installer
python dev-tools\build_package.py

# Build only portable EXE
python dev-tools\build_package.py --portable

# Build with console window
python dev-tools\build_package.py --console
```

#### 3. Secure Build Script

```powershell
# Build with cryptographic module verification
python dev-tools\secure_build_fix.py
```

This script will:
1. Build the Rust library in release mode
2. Validate that all required functions are exported
3. Configure fallback to Python implementation if needed

## Rust Cryptography Integration

TrueFA-Py relies on a native Rust implementation for critical cryptographic operations.

### Key Rust Functions

1. **c_secure_random_bytes** - Generates cryptographically secure random bytes
2. **c_generate_salt** - Creates a cryptographically secure salt for key derivation
3. **c_derive_master_key** - Derives a master key from a password and salt
4. **c_encrypt_master_key** - Encrypts the master key with the vault key
5. **c_decrypt_master_key** - Decrypts the master key with the vault key

### Recent Improvements

The `c_generate_salt` function has been completely redesigned to address critical issues:

```rust
#[no_mangle]
pub extern "C" fn c_generate_salt(
    out: *mut u8,
    out_max_len: size_t,
    out_len: *mut size_t
) -> bool {
    // Safety checks
    if out.is_null() || out_len.is_null() {
        return false;
    }
    
    // Generate 16 random bytes for the salt
    let mut salt = [0u8; 16];
    let mut rng = OsRng;
    
    // Fill the salt buffer with random bytes
    if rng.try_fill_bytes(&mut salt).is_err() {
        return false;
    }
    
    // Base64 encode the salt
    let encoded = base64::encode(&salt);
    let encoded_bytes = encoded.as_bytes();
    let encoded_len = encoded_bytes.len();
    
    // Check if output buffer is large enough
    if encoded_len > out_max_len {
        return false;
    }
    
    // Copy the encoded salt to the output buffer
    unsafe {
        ptr::copy_nonoverlapping(encoded_bytes.as_ptr(), out, encoded_len);
        *out_len = encoded_len;
    }
    
    true
}
```

Key improvements in the implementation:
1. Eliminates potential deadlocks with Python's GIL
2. Implements direct random byte generation
3. Handles base64 encoding within Rust
4. Adds proper error handling for memory operations

### Python Integration with Timeouts

The Python side now implements timeout protection for all Rust functions:

```python
def _run_with_timeout(func, timeout=DEFAULT_TIMEOUT, *args, **kwargs):
    """Run a function with timeout protection."""
    if timeout <= 0:
        return func(*args, **kwargs)
    
    # Set up the alarm
    old_handler = signal.signal(signal.SIGALRM, _timeout_handler)
    signal.alarm(int(timeout))
    
    try:
        result = func(*args, **kwargs)
        return result
    finally:
        # Reset the alarm and restore the old handler
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old_handler)
```

## Testing

TrueFA-Py includes a comprehensive testing infrastructure to ensure reliability.

### Testing the Rust Integration

To verify the Rust DLL integration:

```powershell
# Test the cryptography module
python dev-tools\test_crypto_wrapper.py

# Test specific functions
python dev-tools\test_generate_salt.py

# Test automatic fallback
python dev-tools\test_auto_fallback.py
```

### Docker Testing

Testing in a clean Windows Docker container:

```batch
# Run the Docker test script
.\dev-tools\docker\test_docker.bat
```

This will:
1. Build a Docker container with Windows
2. Run the application within the container
3. Verify functionality and report results

### Compatibility Testing

To check Windows compatibility:

```powershell
# Run the compatibility checker
.\windows_compatibility_check.ps1
```

## Distribution

### Creating Windows Packages

To create a distribution package for Windows:

```powershell
# Create a Windows package
.\dev-tools\build-tools\create_windows_package.ps1
```

This creates a self-contained package with:
1. The TrueFA-Py executable
2. Visual C++ Redistributable installer
3. Launcher scripts for proper environment setup
4. Documentation and README files

### Release Process

For creating a release with proper versioning:

```powershell
# Create a release
.\dev-tools\build-tools\ez-release.ps1 -VersionType [major|minor|patch|none]
```

## Troubleshooting

### DLL Loading Issues

If you encounter DLL loading issues:

1. Check that the Rust DLL exists in the expected location
2. Ensure Visual C++ Redistributable is installed
3. Try rebuilding the Rust library with `cargo build --release`
4. Check the `.truefa` directory for error marker files

### Build Errors

For PyInstaller build errors:

1. Make sure PyInstaller is installed: `pip install pyinstaller`
2. Clear the PyInstaller cache: `python -m PyInstaller --clean`
3. Check the PyInstaller spec file for correct paths

### Rust Build Errors

If you encounter Rust build errors:

1. Ensure Rust is installed and up to date: `rustup update`
2. Check that your Rust installation is working: `rustc --version`
3. Try rebuilding with verbose output: `cargo build --release -vv`

### Testing Framework Failures

If tests are failing:

1. Check the logs in the `.truefa` directory
2. Verify that the DLL functions are exporting correctly
3. Ensure timeout protection is properly configured
4. Test the fallback implementations separately 