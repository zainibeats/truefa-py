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

### Vault State Verification

- **Deep Verification**: Vault unlock state is verified by testing actual cryptographic operations
- **Automatic Correction**: Any inconsistencies between reported and actual state are automatically fixed
- **Periodic Checks**: State verification is performed regularly during application operation
- **Fail-Secure**: Any verification failures default to a locked state for maximum security

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
- Export functionality includes encrypted options
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

4. **TOTP Secret Handling**
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
- [TrueFA-Py Developer Guide](DEVELOPER_GUIDE.md) 