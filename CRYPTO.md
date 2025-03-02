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

## Fixed Issues and Improvements

The following issues were resolved in the cryptography module:

### DLL Integration
- Fixed export naming conventions to ensure C ABI compatibility
- Implemented proper memory management for cross-language boundary
- Added validation of DLL functions before use
- Established robust error handling for missing functions

### Function Exports
- Added prefix `c_` to all exported functions to clarify C ABI boundary
- Ensured all required functions are properly exported:
  - `c_secure_random_bytes`
  - `c_is_vault_unlocked`
  - `c_vault_exists`
  - `c_create_vault`
  - `c_unlock_vault`
  - `c_lock_vault`
  - `c_generate_salt`
  - `c_derive_master_key`
  - `c_encrypt_master_key`
  - `c_decrypt_master_key`
  - `c_verify_signature`
  - `c_create_secure_string`

### SecureString Implementation
- Added proper memory protection for sensitive string data
- Implemented automatic cleanup when strings are no longer needed
- Created consistent API between Rust and Python implementations

### Build Process
- Created enhanced build scripts with automatic validation
- Added DLL verification to ensure all required functions are available
- Implemented automatic copying of DLL to required locations
- Added environment variable control for fallback behavior

## Usage

### Loading the Module

The module is designed to be loaded with proper fallback behavior:

```python
# Import the crypto module with automatic fallback
from src.truefa_crypto import secure_random_bytes, create_vault, unlock_vault
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
