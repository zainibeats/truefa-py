# TrueFA-Py Security and Cryptography Guide

## Security Model Overview

TrueFA-Py implements a multi-layered security approach to protect TOTP secrets with a core focus on:

1. **Defense-in-Depth**: Multiple protective layers prevent a single failure from compromising security
2. **Principle of Least Privilege**: Components only have access to what they absolutely need
3. **Secure by Default**: Security-critical features are enabled without user configuration
4. **Zero Trust Architecture**: Each component verifies the security state of the system
5. **Fail Secure**: All failures default to a secure state

## Two-Layer Security Architecture

TrueFA-Py uses a two-layer authentication model for vault access:

### Layer 1: Vault Authentication
- **Purpose**: Protect access to the vault itself
- **Mechanism**: PBKDF2 password verification with secure salting
- **Implementation**: 
  - Password hash is stored in vault metadata
  - Salt is randomly generated during vault creation (16 bytes)
  - PBKDF2 with SHA-256 and 100,000 iterations
  - Constant-time comparison to prevent timing attacks

### Layer 2: Secret Encryption
- **Purpose**: Encrypt individual TOTP secrets
- **Mechanism**: AES-GCM authenticated encryption
- **Implementation**:
  - Master key derived from password via Scrypt
  - Unique nonce for each encryption operation
  - Authentication tag protects against tampering

## Cryptography Implementation

The cryptography module (`truefa_crypto`) follows a dual-layer approach:

### 1. Rust Implementation (Preferred)

The native Rust implementation provides high-performance, memory-safe cryptographic operations:

```
┌───────────────────────┐
│ Python Application    │
└───────────┬───────────┘
            │
┌───────────▼───────────┐
│ Python/Rust Bindings  │     ┌───────────────────┐
│ with Timeout Control  │◄────┤ Fallback Trigger  │
└───────────┬───────────┘     └───────────────────┘
            │
┌───────────▼───────────┐
│ Rust Crypto Library   │
└───────────────────────┘
```

#### Key Security Features:

1. **Optimized Rust Functions**:
   - Redesigned `c_generate_salt` function to prevent hanging and deadlocks
   - Direct base64 encoding within Rust for compatibility
   - Memory-safe implementation with proper bounds checking
   - Complete GIL avoidance for critical functions

2. **Protected Memory Handling**:
   - Secure memory allocation for sensitive data
   - Automatic clearing of sensitive buffers
   - Memory zeroing when buffers are freed

3. **Error Protection**:
   - Robust error handling with appropriate return values
   - Timeout protection for potentially problematic functions
   - Automatic fallback to Python implementation on error

### 2. Python Fallback (Automatic)

The Python fallback implementation maintains API compatibility with the Rust module:

```
┌───────────────────────┐
│ Python Application    │
└───────────┬───────────┘
            │
┌───────────▼───────────┐
│ Python Fallback       │
│ Implementations       │
└───────────────────────┘
```

#### Key Features:

1. **Identical API**: Same function signatures as the Rust implementation
2. **Automatic Activation**: Triggers when Rust functions fail or time out
3. **Environment Control**: Can be explicitly enabled via environment variables
4. **Diagnostic Capability**: Creates marker files to track failures

### Rust Function Security Enhancements

The Rust module has been significantly enhanced for security and reliability:

#### 1. Optimized `c_generate_salt` Function

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

Security improvements:
- Direct use of OS random number generator
- No Python callbacks that could lead to GIL deadlocks
- Proper error handling for memory operations
- Buffer size validation to prevent overflow

#### 2. Timeout Protection in Python Integration

The Python binding layer now implements timeout protection for all Rust functions:

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

This ensures that no cryptographic function can hang indefinitely, providing:
- Protection against potential infinite loops
- Graceful fallback to Python implementations
- Diagnostic information about which functions are problematic

## Critical Security Components

### 1. SecureVault Class

The `SecureVault` class manages the overall vault security:

- **Password Verification**: Verifies master password against stored hash
- **State Management**: Maintains vault state and security parameters
- **Directory Selection**: Validates and creates secure directories
- **Metadata Handling**: Manages vault metadata including salt and password hash

### 2. SecureStorage Class

The `SecureStorage` class handles encryption and storage operations:

- **Secret Encryption/Decryption**: Handles encryption of individual TOTP secrets
- **Storage Operations**: Manages saving and loading encrypted data
- **Authentication Handling**: Ensures only authenticated users can access secrets

## Windows Compatibility and Security

TrueFA-Py implements enhanced security features for Windows environments:

### Security Features

1. **DLL Validation**: Ensures only trusted libraries are loaded
2. **Controlled Search Paths**: Limits DLL loading to prevent hijacking
3. **Path Detection**: Tests for appropriate permissions before writing sensitive data
4. **Fallback Modes**: Intelligent fallback when Rust libraries fail to load
5. **Marker File System**: Creates diagnostic marker files to track issues

### Rust DLL Integration Improvements

Recent improvements to the Rust DLL integration include:

1. **Optimized Salt Generation**: Completely redesigned to prevent hanging on Windows
2. **Timeout Protection**: All cryptographic functions have timeout protection
3. **Error Tracking**: Improved error detection and reporting
4. **Fallback Mechanism**: Automatic activation of Python implementations when needed

## Vault Implementation

The secure vault uses a two-layer security model:

1. **Vault Password** - Unlocks the vault and decrypts the master key
2. **Master Key** - Encrypts/decrypts individual TOTP secrets

This envelope encryption approach ensures that even if one layer is compromised, your secrets remain protected by the other layer.

## Data Storage Locations

### Default Path

Persistent vault state is stored in the `~/.truefa/.vault/` directory.

### Path Resolution

The application automatically searches for your vault in various locations:

1. `C:\Users\<username>\.truefa\.vault\`
2. `C:\Users\<username>\.truefa_vault\`
3. `C:\Users\<username>\.truefa_secure\`
4. Application data directories

### Portable Mode

When running in portable mode (with TRUEFA_PORTABLE=1 environment variable), the application uses local directories instead of user-specific paths.

## Threat Model

TrueFA-Py is designed to protect against:

1. **Offline Password Attacks**: Mitigated via key stretching (PBKDF2 with high iteration count)
2. **Timing Attacks**: Prevented using constant-time comparison for password verification
3. **Memory Scraping**: Limited via secure memory handling when Rust module is available
4. **Data At Rest Attacks**: Protected via strong encryption (AES-GCM)
5. **Implementation Bugs**: Multiple validation checks prevent security bypass
6. **Deadlocks and Hanging**: Prevented by redesigned Rust functions and timeout protection

## Security Recommendations

For maximum security, users should:

1. Use strong, unique master passwords
2. Keep the vault backup in a secure location
3. Update TrueFA-Py regularly for security improvements
4. Use the official Windows package for best compatibility
5. Run the compatibility check script if experiencing issues

## Reporting Security Issues

Please report security vulnerabilities to [cheyenne@czaini.net](mailto:cheyenne@czaini.net) rather than creating a public issue.
