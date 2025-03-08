# TrueFA-Py - Secure TOTP Authenticator

TrueFA-Py is a secure, offline Two-Factor Authentication (2FA) application built with Python and Rust. It provides a robust command-line interface for managing TOTP (Time-based One-Time Password) authentication codes while keeping your security tokens encrypted and stored locally in a secure vault.

## Features

- 🔑 Encrypted local vault with master password
- 📷 QR code scanning from image files
- 🔐 Two-layer security architecture with envelope encryption
- 🛡️ Optimized Rust crypto module with robust fallback mechanisms
- 🖥️ Portable executable with no installation required
- 🔍 Multiple vault location detection capabilities
- 📥 Save and retrieve TOTP secrets
- 🐳 Optional docker installation

## Installation & Usage

### Windows

TrueFA-Py provides two deployment options for Windows systems:

#### Quick Install (Recommended)
- Download the latest `TrueFA-Py_Setup.exe` from the [releases page](https://github.com/zainibeats/truefa-py/releases)
- Run the installer and follow the instructions
- Launch from the Start Menu or Desktop shortcut

#### Portable Version
- Download `TrueFA-Py-Portable.zip` from the [releases page](https://github.com/zainibeats/truefa-py/releases)
- Extract and run `TrueFA-Py.exe`

#### System Requirements
- Windows 10 or higher is recommended
- Visual C++ Redistributable 2015-2022 must be installed 
  - Automatically installed by the setup script
  - Can be downloaded from [Microsoft](https://aka.ms/vs/17/release/vc_redist.x64.exe)

### Docker

#### Quick Run (Non-Persistent)
```bash
# Basic run with temporary volumes (PowerShell)
.\docker\run_docker.ps1
```

#### Persistent Storage Run
```bash
# Run with persistent vault data and local images folder (PowerShell)
.\docker\run_docker_persistent.ps1
```

#### Manual Configuration
```bash
# Build the Docker image
docker build -t truefa-py -f docker/Dockerfile .

# Run with persistent storage
docker run -it --rm \
  -v "truefa-vault:/home/truefa/.truefa" \
  -v "./images:/app/images" \
  -e "TRUEFA_USE_FALLBACK=1" \
  -e "TRUEFA_PORTABLE=1" \
  truefa-py
```

**Notes for Docker Usage:**
- The `/app/images` directory in the container is mapped to a local `images` folder
- Place your QR code images in the local `images` folder
- Vault data is stored in a Docker volume for persistence

### From Source
```bash
git clone https://github.com/zainibeats/truefa-py.git && cd truefa-py
python -m venv venv && .\venv\Scripts\Activate.ps1
pip install -r requirements.txt
python main.py
```

## Cross-Platform Compatibility

TrueFA-Py is designed with robust cross-platform compatibility:

- **Rust Cryptography DLL**: Provides high-performance, memory-safe cryptographic operations on Windows
- **Python Fallback Implementation**: Automatically activates when the Rust DLL cannot be loaded
- **Intelligent Detection**: Seamlessly switches to the appropriate implementation based on your environment

This dual-implementation approach ensures the application works flawlessly across different Windows systems and other platforms.

## Documentation

- [User Guide](docs/USER_GUIDE.md) - Installation, configuration, and usage
- [Developer Guide](docs/DEVELOPER_GUIDE.md) - Development setup and technical details
- [FAQ](docs/FAQ.md) - Common questions and troubleshooting
- [Windows Testing](docs/WINDOWS_TESTING.md) - Details on Windows compatibility testing

## Security Architecture

TrueFA-Py uses a hybrid approach with a Rust cryptography module for performance and security, with a Python fallback implementation. The secure vault employs envelope encryption:

1. **Vault Password** - Unlocks the vault and decrypts the master key
2. **Master Key** - Encrypts/decrypts individual TOTP secrets

## License

This project is licensed under the MIT License. See the LICENSE file for details.

## Contributing

Contributions are welcome! Please refer to the [Developer Guide](docs/DEVELOPER_GUIDE.md) for contribution guidelines.

## Project Overview
TrueFA-Py is a secure Two-Factor Authentication (TOTP) application written in Python. It provides functionality for scanning QR codes, generating TOTP codes, and securely storing authentication secrets in an encrypted vault.

## Directory Structure
```
truefa-py/
├── main.py                 # Main entry point for the application
├── src/
│   ├── main_opencv.py      # Alternative entry point with OpenCV support
│   ├── config.py           # Configuration settings
│   ├── images/             # Directory for QR code images
│   ├── security/           # Security-related modules
│   │   └── vault_state.py  # Handles vault state management
│   ├── totp/               # TOTP-related modules
│   │   └── auth_opencv.py  # Contains TwoFactorAuth class for TOTP operations
│   ├── truefa_crypto/      # Cryptographic functions
│   └── utils/              # Utility functions
├── rust_crypto/            # Rust implementation of cryptographic functions
└── truefa_crypto/          # DLL for cryptographic operations
```

## Key Components

### TwoFactorAuth Class
The main class in `src/totp/auth_opencv.py` responsible for:
- QR code scanning
- TOTP code generation
- Secret management
- Vault operations

### SecureVault Class
Handles the encryption and storage of sensitive information in a vault file.

### SecureStorage Class
Acts as a bridge between the application and the SecureVault, providing higher-level functions for storing and retrieving data.

## Current Issues

### 1. QR Code Loading Issue
When loading a QR code from an image, the application fails with:
```
DEBUG: Path validation error: argument should be a str or an os.PathLike object where __fspath__ returns a str, not 'NoneType'
Error extracting secret: Invalid path: argument should be a str or an os.PathLike object where __fspath__ returns a str, not 'NoneType'
```

This suggests a NoneType is being passed to a function expecting a path string.

### 2. Vault Initialization and Path Issues
Previously, there were issues with:
- The `vault_path` attribute not existing (fixed by using `vault_dir` and constructing the file path)
- Inconsistent checking of vault initialization status
- Storage instance sharing between components

### 3. DLL Loading Warnings
The application shows warnings related to fallback implementations for crypto operations, which indicates that the native DLL is not loading correctly.

## Suggested Fixes

### Fix for QR Code Loading
The error occurs in the `_validate_image_path` method when it's called with None. The issue is likely in the `extract_secret_from_qr` method. Examine how it handles the image path before passing it to validation.

Possible fix in `auth_opencv.py`:
```python
def extract_secret_from_qr(self, image_path):
    """Extract TOTP secret from a QR code image."""
    try:
        # Debug the raw image path
        print(f"DEBUG: Raw image path: {image_path}")
        
        # Ensure image_path is not None before validation
        if image_path is None:
            return None, "No image path provided"
            
        # Validate the image path
        validated_path = self._validate_image_path(image_path)
        if validated_path is None:
            return None, "Invalid image path"
            
        # Rest of the function...
```

### Fix for Vault Initialization
Ensure consistent handling of vault paths and initialization checking:

1. In `TwoFactorAuth.save_secret`:
```python
# Get the vault file path
vault_file = os.path.join(self.storage.vault_dir, "vault.json")

# Check initialization using storage instance
if not self.storage.is_initialized:
    # Handle vault creation
```

2. Consider adding a helper method in SecureStorage to check if a path exists and is a valid vault file.

### Fix for DLL Loading
Look into the DLL loading process in the application. It's currently falling back to Python implementations, which reduces security. Ensure the correct DLL is accessible and its functions are properly exposed.

## Next Steps

1. **Fix QR Code Loading**: Modify the `extract_secret_from_qr` method to handle None values and proper path validation.

2. **Verify Vault Operations**: After fixing the QR code issue, test the full workflow:
   - Load a QR code
   - Generate TOTP codes
   - Create a vault
   - Save a secret
   - List saved secrets

3. **Enhance Error Handling**: Add better error messages throughout the application, especially for common operations like file access and QR code scanning.

4. **Security Review**: Once functionality is working, conduct a security review to ensure sensitive data is properly protected.

## Testing Instructions

1. **Reset the Vault**: Delete existing vault files:
   ```
   python cleanup_vault.py
   ```

2. **Run the Application**:
   ```
   python -m main
   ```

3. **Test Workflow**:
   - Option 1: Load QR code from image (use "qrtest.png" or a valid QR code image)
   - Option 3: Save the current secret (create a vault with password "testpassword")
   - Option 4: View saved secrets (should show the saved secret)
   - Option 7: Exit

## Common Errors and Solutions

### Path Validation Errors
If you encounter path validation errors, check that:
- The image file exists in the expected location
- The code correctly handles relative and absolute paths
- Debug output is added to trace the path resolution

### Vault Access Issues
If you encounter vault access issues:
- Verify the vault file exists at the expected location
- Check permissions on the vault directory
- Ensure consistent use of storage references throughout the application

### Debug Tips
Add debug print statements to trace execution flow, particularly when:
- Processing user input
- Validating paths
- Performing vault operations
- Handling encryption/decryption

## Contact
For issues or questions, please contact the project maintainer.
