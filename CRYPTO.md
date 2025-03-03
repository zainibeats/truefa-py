# TrueFA Cryptography Module

## Overview

The TrueFA cryptography module (`truefa_crypto`) provides critical security operations for the TrueFA-Py application. It is implemented with a dual-layer approach:

1. **Rust Implementation**: High-performance, memory-safe native implementation (preferred)
2. **Python Fallback**: Pure Python implementation used when the Rust module is unavailable

## Implementation Details

### Rust Implementation

The Rust implementation provides enhanced security through:
- Protected memory handling with automatic cleanup
- Improved performance for cryptographic operations
- Better protection against memory-based attacks
- C-compatible FFI interface for Python integration

### Python Fallback

The Python fallback implementation ensures that TrueFA-Py can function even when the Rust library cannot be loaded:
- Uses standard Python cryptographic libraries
- Maintains API compatibility with the Rust implementation
- Automatically activates when the Rust library is not available
- Function-level fallback for specific missing operations

## Fixed Issues and Improvements

The following issues were resolved in the cryptography module:

### DLL Loading Strategy
- Implemented intelligent DLL search paths based on runtime environment
- Prioritizes PyInstaller bundle paths in packaged applications
- Falls back to standard locations in development environments
- Logs detailed search path information for troubleshooting
- Early verification of DLL compatibility before use

### Function Exports
- Added prefix `c_` to all exported functions to clarify C ABI boundary
- Implemented partial function loading with targeted fallbacks
- Core functions include:
  - `c_secure_random_bytes` (Rust implementation)
  - `c_create_secure_string` (Rust implementation)
  - Other functions with Python fallbacks as needed

### SecureString Implementation
- Added hybrid implementation approach for secure string handling
- Rust implementation for core operations when available
- Automatic fallback to Python implementation for unavailable functions
- Consistent API between implementations

### Build Process
- Enhanced build scripts with runtime environment detection
- Support for both portable and installed application modes
- Automatic DLL validation during build process
- Streamlined packaging for Windows environments

## Usage

### Loading the Module

The module is designed to be loaded with proper fallback behavior:

```python
# Import the crypto module with automatic fallback
from src.truefa_crypto import secure_random_bytes, create_vault, unlock_vault
```

### Environment Detection

The module automatically detects the runtime environment:

```python
# Current environment will be detected automatically
# - PyInstaller bundle (portable or installed)
# - Development environment
# - CI/CD pipeline
```

### Controlling Implementation

You can control which implementation is used via environment variables:

```python
# Force use of Python fallback
os.environ["TRUEFA_USE_FALLBACK"] = "true"

# Use Rust implementation (if available)
os.environ["TRUEFA_USE_FALLBACK"] = "false"
```

### Checking Implementation

To verify which implementation is in use:

```python
from src.truefa_crypto import is_using_rust

if is_using_rust():
    print("Using high-performance Rust implementation")
else:
    print("Using Python fallback implementation")
```

## Building the Rust Module

The Rust module can be built using the provided build scripts:

```powershell
# Build and validate the Rust crypto module
python secure_build_fix.py
```

This will:
1. Compile the Rust library with optimizations
2. Validate all required functions are exported
3. Copy the DLL to the correct locations
4. Configure the Python module to use the Rust implementation

## Security Considerations

- The Rust implementation provides better memory protection than the Python fallback
- For maximum security, always use the Rust implementation in production
- The Python fallback should be used only when the Rust library cannot be loaded
- Both implementations use the same cryptographic primitives and security model
