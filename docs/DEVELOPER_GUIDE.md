# TrueFA-Py Developer Guide

This comprehensive guide provides all the information needed for developing, building, testing, and securing TrueFA-Py.

## Table of Contents

1. [Development Environment Setup](#development-environment-setup)
2. [Project Structure](#project-structure)
3. [Building TrueFA-Py](#building-truefa-py)
4. [Rust Cryptography Integration](#rust-cryptography-integration)
5. [Testing](#testing)
6. [Security Considerations](#security-considerations)
7. [Distribution](#distribution)
8. [Troubleshooting](#troubleshooting)

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

### Recent Rust Integration Fixes

The Rust cryptography module has undergone significant improvements to resolve critical issues:

1. **Fixed `c_generate_salt` function** that was causing applications to hang on Windows systems:
   - Eliminated potential deadlocks with Python's GIL
   - Implemented direct random byte generation using Rust's `OsRng`
   - Added proper error handling for memory operations

2. **Enhanced fallback mechanism** with automatic detection of DLL function failures and timeouts

### Building Options

TrueFA-Py includes several build tools in the `dev-tools` directory:

#### 1. PowerShell Build Script (Recommended)

```powershell
# Basic build (creates portable EXE and installer)
.\dev-tools\build.ps1

# Build with Rust cryptography backend first
.\dev-tools\build.ps1 -BuildRust -Clean -Portable

# Build with console window (for debugging)
.\dev-tools\build.ps1 -Console

# Force use of Python fallback implementation
.\dev-tools\build.ps1 -Fallback
```

#### Creating Distribution Packages

For Windows distribution:

```powershell
# Build portable package and installer
.\dev-tools\build.ps1 -BuildRust -Clean -Portable

# Create Windows distribution package
python dev-tools\build_package.py --portable --installer
```

This will create:
- `dist/TrueFA-Py-Windows.zip` (portable version)
- `dist/TrueFA-Py_Setup.exe` (installer version)

## Rust Cryptography Integration

TrueFA-Py relies on a native Rust implementation for critical cryptographic operations.

### Key Rust Functions

| Function | Purpose | Description |
|----------|---------|-------------|
| `c_secure_random_bytes` | Random Generation | Generates cryptographically secure random bytes |
| `c_generate_salt` | Key Derivation | Creates a cryptographically secure salt for key derivation |
| `c_derive_master_key` | Key Management | Derives a master key from a password and salt |
| `c_encrypt_master_key` | Encryption | Encrypts the master key with the vault key |
| `c_decrypt_master_key` | Decryption | Decrypts the master key with the vault key |
| `c_create_secure_string` | Memory Security | Stores sensitive strings in protected memory |
| `c_verify_signature` | Verification | Verifies cryptographic signatures |

### Optimized Implementation

The `c_generate_salt` function has been completely redesigned to address critical issues on Windows systems:

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

### Python Integration with Timeout Protection

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

### Intelligent Fallback Mechanism

TrueFA-Py implements an intelligent fallback system that automatically detects issues with the Rust implementation and falls back to Python:

1. **Function-level tracking**: Each Rust function is monitored for timeouts or failures
2. **Predictive fallback**: Once a function times out, future calls bypass it
3. **Manual override**: Set `TRUEFA_USE_FALLBACK=1` to force Python implementation

### DLL Loading Strategy

The application searches for the Rust DLL in multiple locations:

1. Application directory
2. PyInstaller bundle directory
3. Module directory
4. User's home `.truefa` directory
5. Current working directory

## Testing

### Unit Testing

Run unit tests with pytest:

```bash
# Run all tests
pytest tests/

# Run specific test category
pytest tests/test_crypto.py
```

### Integration Testing

To test the cryptography module integration:

```python
import truefa_crypto

# Test random bytes generation
random_bytes = truefa_crypto.secure_random_bytes(32)
print(f"Generated {len(random_bytes)} random bytes")

# Test salt generation
salt = truefa_crypto.generate_salt()
print(f"Generated salt: {salt}")

# Test fallback mechanism
import os
os.environ["TRUEFA_USE_FALLBACK"] = "1"
fallback_salt = truefa_crypto.generate_salt()
print(f"Fallback salt: {fallback_salt}")
```

### Automated Test Scripts

The `dev-tools` directory contains automated test scripts:

- `create_test_qr.py`: Creates test QR codes for validation
- `test_script.ps1`: Tests functionality across different environments

### Windows Compatibility Testing

Test compatibility across different Windows versions:

```powershell
# Run the Windows compatibility check
.\windows_compatibility_check.ps1
```

## Security Considerations

### Cryptographic Design

TrueFA-Py uses a two-layer security model:

1. **Outer Layer**: User's master password derives a key using PBKDF2 with 100,000 iterations
2. **Inner Layer**: Master key encrypts individual TOTP secrets using AES-GCM

### Implementation Security

#### Memory Safety

- Sensitive data (passwords, keys) use secure memory when available
- Memory is explicitly zeroed when no longer needed
- Secure strings prevent accidental logging or exposure

#### Authentication

- The master password is never stored, only a derived key verification value
- Failed authentication attempts do not reveal timing information about password correctness

#### Transport Security

- No network communication for core cryptographic operations
- QR codes can be loaded from files rather than direct camera access

### Audit Recommendations

For security auditing, focus on:

1. The Rust cryptography implementation in `rust_crypto/src/`
2. Python-Rust binding in `src/truefa_crypto/__init__.py`
3. Vault implementation in `src/vault/vault.py`
4. Secret handling in `src/totp/auth.py`

## Distribution

### Windows Distribution

1. Run the build script with installer option:
   ```powershell
   .\dev-tools\build.ps1 -BuildRust -Clean -Installer
   ```

2. Verify the installer in `dist/TrueFA-Py_Setup.exe`

### Portable Distribution

1. Build the portable package:
   ```powershell
   .\dev-tools\build.ps1 -BuildRust -Clean -Portable
   ```

2. Verify the package in `dist/TrueFA-Py-Windows.zip`

## Troubleshooting

### Common Development Issues

#### Rust DLL Not Found

**Symptoms**: Error loading the Rust DLL, such as `ImportError: DLL load failed`

**Solution**:
- Ensure Rust is installed and the DLL is built (`cargo build --release`)
- Check that the DLL is in one of the expected locations
- Look for `.dll_crash` marker file in `.truefa` directory
- Try with `TRUEFA_USE_FALLBACK=1` to bypass the Rust implementation

#### Build Failures

**Symptoms**: PyInstaller fails to build the application

**Solution**:
- Use the `-Clean` option to start with a fresh build
- Check PyInstaller logs in the `build` directory
- Ensure all dependencies are installed (`pip install -r requirements.txt`)
- Verify the Rust DLL is correctly built

#### Testing Failures

**Symptoms**: Tests fail, especially on specific platforms

**Solution**:
- Check compatibility with the platform/Python version
- Use isolated testing environments
- Review test logs for specific error messages

#### Function Hanging

**Symptoms**: Application hangs when calling Rust functions

**Solution**:
- Use the optimized implementation with timeout protection
- Set `TRUEFA_USE_FALLBACK=1` to use Python implementation
- Check for deadlocks in the Rust code 