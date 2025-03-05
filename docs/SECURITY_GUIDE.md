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

1. **Rust Implementation** (Preferred)
   - High-performance, memory-safe native implementation
   - Protected memory handling with automatic cleanup
   - Better protection against memory-based attacks

2. **Python Fallback** (Automatic)
   - Pure Python implementation used when the Rust module is unavailable
   - Maintains API compatibility with the Rust implementation
   - Automatically activates when the Rust library cannot be loaded

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

### Security-Critical Methods

- **unlock_vault()** - Verifies the master password against stored hash
- **_save_vault_state()** - Persists vault metadata to disk  
- **_load_vault_state()** - Loads vault metadata including salt and password hash

## Windows Compatibility

TrueFA-Py implements enhanced security and compatibility features for Windows:

### Security Features
- **DLL Validation**: Ensures that only trusted libraries are loaded
- **Controlled Search Paths**: Limits DLL loading to prevent hijacking
- **Path Detection**: Tests for appropriate permissions before writing sensitive data
- **Fallback Modes**: Intelligent fallback when Rust libraries fail to load

### Windows Package Enhancements
- **Embedded Python Support**: Pre-compiled DLLs ensure consistent operation
- **Visual C++ Integration**: Auto-detection and installation guidance
- **Launcher Support**: Environment configuration for proper DLL loading
- **Compatibility Check**: Diagnostic script for common Windows issues

### Resolving Common Windows Issues

1. **DLL Loading Failures**: 
   - Use the Windows package with the included launcher script
   - Alternatively, use the `--use-fallback` flag

2. **Missing Dependencies**: 
   - Run `setup.bat` to install the required Visual C++ Redistributable
   - Or download from Microsoft: https://aka.ms/vs/17/release/vc_redist.x64.exe

3. **Path Permission Issues**: 
   - The application detects and uses paths with correct permissions
   - First-time setup may benefit from running as administrator

## Vault Implementation

The secure vault uses a two-layer security model:
1. **Vault Password** - Unlocks the vault and decrypts the master key
2. **Master Key** - Encrypts/decrypts individual TOTP secrets

This envelope encryption approach ensures that even if one layer is compromised, your secrets remain protected by the other layer.

## Data Storage Locations

### Default Path
Persistent vault state is stored in the `~/.truefa/.vault/` directory.

### Path Resolution
The application will automatically search for your vault in various locations when unlocking:
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

## Recent Security Improvements

The following improvements enhance security and reliability:

- **Timeout Mechanisms**: Protection for encryption operations to prevent hanging
- **Enhanced Error Handling**: Better diagnostics and graceful degradation
- **Fallback Implementation**: Improved Python-based fallback for critical operations
- **Windows Compatibility**: Special handling for Windows-specific security paths
- **DLL Loading Strategy**: Intelligent search paths based on runtime environment

## Security Recommendations

For maximum security, users should:

1. Use strong, unique master passwords
2. Keep the vault backup in a secure location
3. Update TrueFA-Py regularly for security improvements
4. Use the official Windows package for best compatibility
5. Run the compatibility check script if experiencing issues

## Reporting Security Issues

Please report security vulnerabilities to [security@example.com](mailto:security@example.com) rather than creating a public issue.
