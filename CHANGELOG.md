# TrueFA Changelog

## Version 0.2.1 - 2025-02-28

### Fixed
- Resolved issue with saving secrets for the first time by properly prompting for vault and master passwords
- Improved error handling in the secure storage implementation
- Fixed the OpenCV edition to properly handle vault creation

## Version 0.2.0 - 2025-02-28

### Added
- Improved fallback mechanism for cryptographic functions when Rust DLL fails to load
- Enhanced SecureVault implementation with proper file structure and error handling
- Added comprehensive encryption/decryption for secure data storage
- Created test scripts to verify vault and crypto functionality
- Added debug output for better troubleshooting

### Fixed
- Resolved issues with DLL function loading in packaged executable
- Fixed vault initialization and unlocking process
- Corrected key derivation in the fallback implementation
- Fixed SecureStorage implementation to work with or without Rust DLL
- Enhanced error handling throughout the application
- Fixed file path handling for vault metadata

### Technical Details
- The Rust DLL now includes explicit C-linkage exports for key functions
- Added comprehensive fallback implementations for all crypto functions
- Enhanced security through proper key management and envelope encryption
- Improved vault file structure for better maintainability
- Fixed PyInstaller packaging to properly include all necessary components
