# TrueFA-Py Security Model

This document describes the security model, cryptographic implementations, and best practices for the TrueFA-Py application

## Table of Contents

1. [Cryptographic Design](#cryptographic-design)
2. [Rust Implementation](#rust-implementation)
3. [Secure Storage](#secure-storage)
4. [Memory Management](#memory-management)
5. [Authentication](#authentication)
6. [Security Considerations](#security-considerations)
7. [Audit Guidelines](#audit-guidelines)
8. [References](#references)
9. [Related Documentation](#related-documentation)
10. [GUI Security](#gui-security)

## Cryptographic Design

TrueFA-Py implements a comprehensive two-layer security model for protecting sensitive authentication secrets:

### Two-Layer Encryption Model

1. **Outer Layer: Master Password Protection**
   - User's master password is processed using PBKDF2 with 100,000 iterations
   - Salt values are randomly generated using cryptographically secure functions
   - The derived key is used for vault access control and master key encryption
   - Password verification uses constant-time comparison to prevent timing attacks

2. **Inner Layer: Secret Encryption**
   - Individual TOTP secrets are encrypted using AES-256 in GCM mode
   - Each secret has its own initialization vector (IV) for enhanced security
   - The master key is used for encrypting all secrets but is itself encrypted
   - Integrity protection via GCM authentication tags prevents tampering

### Key Management

- The master key is never stored in plaintext on disk
- During runtime, keys are kept in secure memory when available
- Key derivation uses platform-optimized implementations where possible
- All key material is zeroed in memory when no longer needed

## Rust Implementation

TrueFA-Py implements critical cryptographic functions in Rust for enhanced security:

### Core Security Functions

| Function | Purpose | Security Benefits |
|----------|---------|-------------------|
| `c_secure_random_bytes` | Generate random data | Uses OS-level CSPRNG (e.g., getrandom/BCryptGenRandom) |
| `c_generate_salt` | Create key derivation salt | Cryptographically secure, properly sized for algorithms |
| `c_create_secure_string` | Protect passwords in memory | Memory protection, zeroing on drop |
| `c_derive_master_key` | Key derivation | Hardware-optimized PBKDF2 implementation |
| `c_encrypt_master_key` | Protect the master key | AES-GCM with integrity protection |
| `c_decrypt_master_key` | Recover the master key | Authenticated decryption preventing oracle attacks |

### Memory Protection

- Sensitive data in Rust is stored in protected memory
- Custom SecureString type prevents accidental logging and exposure
- Memory is locked (when platform allows) to prevent swapping to disk
- Automatic zeroing when objects are dropped from scope

### Fallback Mechanism

For enhanced security and reliability, the system includes a Python fallback implementation:

- Function-level error monitoring detects any issues with the Rust implementation
- Automatic detection of missing or compromised DLL files
- Session state tracking to maintain consistent encryption across operations
- Manual override via `TRUEFA_USE_FALLBACK=1` environment variable

## Secure Storage

### Vault Structure

The secure vault implements several security features:

- **Directory Security**: Platform-specific permission restrictions
- **File Encryption**: All secret files are individually encrypted
- **Metadata Separation**: Sensitive data separated from non-sensitive metadata
- **Format Versioning**: Version tracking for future security upgrades
- **State Verification**: Periodic cryptographic verification of vault unlock state

### File Security

- Files are created with restricted permissions
- Secret files use `.enc` extension and are encrypted with AES-GCM
- Vault metadata contains only verification data, not actual secrets
- Encrypted files include integrity protection

### Secure Exports

TrueFA-Py provides secure export and import functionality for vault secrets:

- **Standardized Encrypted JSON Format**: Exports use a standardized format for interoperability with other authenticator applications
- **Direct AES-256 Encryption**: Exports use AES-256 in CBC mode with PKCS#7 padding
- **Password-Derived Keys**: Export files are encrypted with keys derived from user-provided passwords using PBKDF2
- **Unique Initialization Vectors**: Each export uses a randomly generated IV for enhanced security
- **Environment-Aware Paths**: Export paths prioritize environment variables and application-defined secure directories
- **Directory Structure Preservation**: Exports maintain the application's secure directory structure
- **Default Path Security**: When no path is specified, exports go to a dedicated exports directory with appropriate permissions
- **Fallback Mechanism**: Secure fallback paths when preferred directories are unavailable
- **Path Validation**: Extensive validation of export paths with proper error handling for permissions

Implementation: 
- [src/security/exporters.py](../src/security/exporters.py) handles all export operations with a modular design.
- [src/security/importers.py](../src/security/importers.py) handles all import operations with comprehensive format support.

### Vault State Verification

- **Deep Verification**: Vault unlock state is verified by testing actual cryptographic operations
- **Automatic Correction**: Any inconsistencies between reported and actual state are automatically fixed
- **Periodic Checks**: State verification is performed regularly during application operation
- **Fail-Secure**: Any verification failures default to a locked state for maximum security

Implementation: [src/security/secure_storage.py:verify_unlocked()](../src/security/secure_storage.py) method

## Memory Management

### Secure Memory Handling

TrueFA-Py implements several memory protection mechanisms:

- **Zero-After-Use**: All sensitive data is explicitly zeroed when no longer needed
- **Memory Locking**: When available, memory is locked to prevent swapping to disk
- **Secure Allocation**: Memory for sensitive data uses secure allocation when available
- **Stack Protection**: Stack-allocated sensitive data is minimized

### Protected String Types

- Custom SecureString implementation prevents accidental exposure
- String comparison operations use constant-time algorithms
- Automatic clearing when strings go out of scope
- Protection against accidental logging or printing

Implementation: [src/security/secure_string.py](../src/security/secure_string.py) and Rust-based implementation in [rust_crypto/src](../rust_crypto/src)

## Authentication

### Master Password Verification

- Only a derived verification value is stored, never the password itself
- Failed attempts do not reveal timing information about password correctness
- No limit on password complexity or length
- No transmission of the master password over any network
- Cryptographic confirmation of successful unlocking using secure verification

### Session Management

- Session keys are optionally cached in memory only
- No persistent cookies or session identifiers
- Session state can be explicitly cleared on demand
- Automatic timeout for idle sessions
- Session state synchronized with actual cryptographic vault state

## Security Considerations

### Platform-Specific Security

#### Windows
- Uses Windows Data Protection API when available
- Secure permissions with proper ACLs
- Visual C++ Redistributable required for secure memory operations

#### Linux/macOS
- Uses mlock() to prevent memory swapping
- File permissions set to 0600 for all sensitive files
- Directory permissions restricted to user only

### Operational Security

- No network transmission of secrets
- QR codes can be loaded from files rather than camera for air-gapped systems
- Export functionality includes AES-256 encrypted exports with password protection
- Multiple export formats supported (encrypted file, OTPAuth URI)
- User-friendly error handling with specific security-related messages
- Clear memory option for panic situations

## Audit Guidelines

### Recommended Audit Areas

For security auditing, focus on these critical components:

1. **Rust Cryptography Implementation**
   - Located in `rust_crypto/src/`
   - Key functions: `encrypt_data`, `decrypt_data`, `secure_random`
   - Memory handling in `secure_string.rs`

2. **Python-Rust FFI Binding**
   - Located in `src/truefa_crypto/__init__.py`
   - Error handling and parameter validation
   - Fallback implementation security

3. **Vault Implementation**
   - Located in `src/security/vault.py`
   - Key derivation and management
   - File encryption/decryption operations
   - Vault state verification and integrity checks

4. **Export Implementation**
   - Located in `src/security/exporters.py`
   - Password-based AES encryption
   - Secure key derivation and IV handling
   - File format security and data serialization

5. **TOTP Secret Handling**
   - Located in `src/totp/auth_opencv.py`
   - QR code processing security
   - Secret extraction and validation

### Security Testing

- Verify secure deletion of memory
- Test fallback mechanisms under various failure scenarios
- Validate encryption/decryption operations with known test vectors
- Verify resistance to timing attacks in authentication
- Test vault state verification under various failure conditions

## References

- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [NIST SP 800-63B Digital Identity Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [Rust Security Advisory Database](https://rustsec.org/)

## Related Documentation

- [Developer Guide](DEVELOPER_GUIDE.md) - Development setup and technical details
- [Development Status](DEVELOPMENT_STATUS.md) - Current state and security improvements
- [Documentation Index](README.md) - Overview of all available documentation
- [Main README](../README.md) - Project overview and high-level security architecture

## GUI Security

The TrueFA-Py GUI implementation follows the same security principles as the CLI version, while providing a user-friendly interface:

### Authentication and Vault Security
- Master password authentication with PBKDF2 key derivation (100,000 iterations)
- Auto-locking of vault when switching to the login screen
- Password masking in all input fields
- Automatic clearing of password fields after use

### TOTP Secret Handling
- Secrets are only stored in memory when the vault is unlocked
- All secrets are cleared from memory when the vault is locked
- The application never logs actual TOTP tokens or secrets
- Token display is ephemeral and cleared when switching accounts

### Data Security
- The same two-layer encryption model used in the CLI version
- AES-GCM authenticated encryption for vault data
- Atomic file operations to prevent data corruption
- Secure export/import functionality with password protection

### UI Security Considerations
- No screenshots are stored by the application
- The application does not retain or cache sensitive information
- Minimal logging of sensitive operations
- Support for secure vault deletion

For detailed information about the core security implementation, please refer to the sections above. 