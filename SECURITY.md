# TrueFA Security Model

## Overview

TrueFA implements a multi-layered security approach to protect TOTP secrets. This document outlines the security architecture, authentication mechanisms, and threat mitigations used in the application.

## Core Security Principles

1. **Defense-in-Depth**: Multiple protective layers prevent a single failure from compromising security
2. **Principle of Least Privilege**: Components only have access to what they absolutely need
3. **Secure by Default**: Security-critical features are enabled without user configuration
4. **Zero Trust Architecture**: Each component verifies the security state of the system
5. **Fail Secure**: All failures default to a secure state

## Vault Authentication

TrueFA uses a two-layer authentication model for vault access:

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

## Security Validations

To prevent security bugs, TrueFA implements multiple validation checks:

1. **Vault Initialization Check**: Verifies vault is properly set up before operations
2. **State Consistency Verification**: Ensures vault unlock state is consistently tracked
3. **Double Authentication Verification**: Confirms both vault and application-level authentication
4. **Secure Default Implementation**: Falls back to secure Python implementations when Rust is unavailable
5. **Directory Permission Validation**: Tests write permissions before using a directory
6. **Windows-Specific ACL Management**: Uses Windows security APIs for proper permissions on secure directories

## Implementation Details

### Critical Security Components

1. **SecureVault Class**:
   - Primary vault management
   - Password verification
   - State management
   - Directory selection and validation

2. **SecureStorage Class**:
   - Secret encryption/decryption
   - Secret storage operations
   - Authentication handling

3. **Rust Cryptographic Module**:
   - Secure memory operations (with Python fallback)
   - Random number generation
   - Cryptographic primitives

### Directory Security

TrueFA implements enhanced directory security:
- Windows ACLs configured to limit access to the current user only
- Test file creation/deletion to verify write permissions
- Automatic fallback paths when permissions cannot be secured
- Dynamic path selection based on application mode (portable vs. installed)

### Upgrading Legacy Vaults

TrueFA automatically upgrades older vault formats:
- Detects vaults missing password hashes
- Computes and stores the hash during first successful login
- Preserves backward compatibility while enhancing security

## Threat Model

TrueFA is designed to protect against:

1. **Offline Password Attacks**: Mitigated via key stretching (PBKDF2 with high iteration count)
2. **Timing Attacks**: Prevented using constant-time comparison for password verification
3. **Memory Scraping**: Limited via secure memory handling when Rust module is available
4. **Data At Rest Attacks**: Protected via strong encryption (AES-GCM)
5. **Implementation Bugs**: Multiple validation checks prevent security bypass

## Security Recommendations

For maximum security, users should:

1. Use strong, unique master passwords
2. Keep the vault backup in a secure location
3. Update TrueFA regularly for security improvements
4. Use stateless mode when possible, to minimize exposure
5. Consider using hardware security tokens for additional protection

## Debugging Security Issues

For security researchers or debugging:

1. Enable DEBUG mode via environment variable: `DEBUG=true`
2. Review debug output for authentication flows
3. Examine vault metadata (located in ~/.truefa/.vault/)
4. Check security validations in src/security/vault.py

## Reporting Security Issues

Please report security vulnerabilities to [security@example.com](mailto:security@example.com) rather than creating a public issue.
