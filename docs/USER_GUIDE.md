# TrueFA-Py User Guide

This guide provides comprehensive instructions for installing, configuring, and using TrueFA-Py, a secure time-based one-time password (TOTP) authenticator application.

## Table of Contents

1. [Introduction](#introduction)
2. [Installation](#installation)
3. [First-Time Setup](#first-time-setup)
4. [Managing Authentication Tokens](#managing-authentication-tokens)
5. [Using TOTP Codes](#using-totp-codes)
6. [Vault Management](#vault-management)
7. [Advanced Options](#advanced-options)
8. [Troubleshooting](#troubleshooting)
9. [FAQs](#faqs)

## Introduction

TrueFA-Py is a secure, offline Two-Factor Authentication (2FA) application that allows you to manage and generate time-based one-time passwords (TOTP) for your accounts. Unlike cloud-based authenticator apps, TrueFA-Py stores all your security tokens locally in an encrypted vault, ensuring your authentication secrets never leave your device.

### Key Features

- **Local Secure Storage**: All secrets are stored in an encrypted vault on your device
- **QR Code Scanning**: Import 2FA tokens by scanning QR codes from image files
- **Manual Secret Entry**: Manually enter secret keys if QR codes are unavailable
- **Secure Design**: Two-layer security architecture with envelope encryption
- **Offline Operation**: Generate codes without an internet connection
- **Portable Mode**: Run the application without installation
- **Vault Backup**: Export and back up your encrypted secrets

## Installation

### Windows Installation

#### Portable Version (Recommended)

1. Download the latest `TrueFA-Py-Windows.zip` package from the [releases page](https://github.com/zainibeats/truefa-py/releases)
2. Extract the ZIP file to your preferred location
3. Run `setup.bat` to install required dependencies
4. Use `TrueFA-Py.bat` to launch the application

#### Installer Version

1. Download the latest `TrueFA-Py_Setup.exe` from the [releases page](https://github.com/zainibeats/truefa-py/releases)
2. Run the installer and follow the on-screen instructions
3. Launch TrueFA-Py from the Start menu shortcut

### Linux Installation

For Linux, use the Python package:

```bash
# Install from PyPI
pip install truefa-py

# Run the application
truefa-py
```

### Prerequisites

TrueFA-Py requires:

- Windows 10 or higher (for Windows users)
- Visual C++ Redistributable 2015-2022 (automatically installed by setup.bat)
- Python 3.10 or higher (for source installation)

## First-Time Setup

When you first launch TrueFA-Py, you'll need to create a master password for your vault.

### Creating a Master Password

1. Launch TrueFA-Py
2. You'll be prompted to create a master password
3. Enter a strong password and confirm it
4. This password will encrypt your vault and must be remembered

### Application Interface

TrueFA-Py uses a command-line interface with numbered options:

```
TrueFA-Py: Secure TOTP Authenticator
--------------------------------------
1. Load QR code from image
2. Enter secret key manually
3. Save current secret
4. View saved secrets
5. Export secrets
6. Clear screen
7. Exit
```

Select options by entering the corresponding number.

## Managing Authentication Tokens

### Adding Tokens via QR Code

1. Select option 1 from the main menu: "Load QR code from image"
2. Enter the path to the QR code image file
   - You can use absolute paths (e.g., `C:\Users\YourName\Downloads\qr.png`)
   - Or relative paths (e.g., `qr.png` if in the current directory)
3. The application will extract the secret from the QR code
4. You'll see the current TOTP code for the extracted secret

### Adding Tokens Manually

1. Select option 2 from the main menu: "Enter secret key manually"
2. Enter the secret key (usually a base32-encoded string)
3. Optionally enter a name to identify this token
4. The application will generate and display the current TOTP code

### Saving Tokens to the Vault

After adding a token (either via QR code or manually), you can save it to your vault:

1. Select option 3 from the main menu: "Save current secret"
2. Enter a name for the token if prompted (e.g., "Gmail:myaccount@gmail.com")
3. Enter your vault master password when prompted
4. The token will be encrypted and saved to your vault

## Using TOTP Codes

### Generating TOTP Codes

1. Select option 4 from the main menu: "View saved secrets"
2. Enter your vault master password when prompted
3. Select the token from the list of saved secrets
4. The current TOTP code will be displayed, along with the time remaining before it expires

### Understanding TOTP Codes

- TOTP codes are typically 6-digit numbers
- Each code is valid for 30 seconds
- The application shows a countdown to indicate when the code will expire
- A new code is automatically generated when the current one expires

## Vault Management

### Viewing Saved Tokens

1. Select option 4 from the main menu: "View saved secrets"
2. Enter your vault master password when prompted
3. You'll see a list of all saved tokens

### Exporting Your Vault

1. Select option 5 from the main menu: "Export secrets"
2. Enter your vault master password when prompted
3. Specify the export file path when prompted
4. Your encrypted vault will be exported to the specified location

### Changing Your Master Password

To change your master password, you'll need to:

1. Export your current vault (option 5)
2. Delete the `.truefa` directory in your user home folder
3. Restart the application and create a new vault with a new password
4. Import your tokens from the exported file

## Advanced Options

### Portable Mode

To run TrueFA-Py in portable mode (storing the vault in the application directory instead of your user profile):

1. Set the `TRUEFA_PORTABLE=1` environment variable
2. Launch the application normally

This mode is useful for running the application from a USB drive or other removable media.

### Using Python Fallback Mode

If you encounter issues with the Rust cryptography module:

1. Set the `TRUEFA_USE_FALLBACK=1` environment variable
2. Launch the application normally

This forces the application to use the Python implementation for all cryptographic operations.

## Troubleshooting

### Common Issues and Solutions

#### Application Hangs or Crashes

**Symptoms**: The application freezes or crashes, especially when generating salts or performing cryptographic operations.

**Solution**: 
1. Use the latest version with optimized cryptography implementation
2. Try running with Python fallback mode: `TRUEFA_USE_FALLBACK=1`
3. Check for `.dll_crash` or other marker files in the `.truefa` directory
4. Ensure Visual C++ Redistributable is properly installed

#### "Vault Not Found" Error

**Symptoms**: The application cannot find your vault, even though you've previously set it up.

**Solution**:
1. Check if the `.truefa` directory exists in your user home folder
2. Ensure the application has read/write permissions for this directory
3. If running in portable mode, check the application directory
4. Try using the backup vault files if available

#### QR Code Not Recognized

**Symptoms**: The application cannot extract the secret from a QR code image.

**Solution**:
1. Ensure the image is clear and not distorted
2. Verify the QR code is a valid TOTP setup code
3. Try using the alternative QR code reader (`TRUEFA_USE_OPENCV=1`)
4. Use the manual entry option if QR code scanning fails

#### "Invalid Secret" Error

**Symptoms**: The application reports that the secret key is invalid.

**Solution**:
1. Ensure the secret is a valid base32-encoded string
2. Check for spaces or other extraneous characters
3. Verify the secret with the service provider
4. Try re-scanning the QR code if available

### Diagnostic Markers

TrueFA-Py creates marker files in the `.truefa` directory to help diagnose issues:

- `.dll_crash`: Indicates a problem loading the Rust DLL
- `.c_generate_salt_error`: Indicates an issue with the salt generation function
- `.vault_corrupt`: Indicates vault corruption
- `.fallback_active`: Indicates the application is using fallback mode

## FAQs

### General Questions

#### Q: Is TrueFA-Py secure for storing my 2FA tokens?
A: Yes, TrueFA-Py uses strong encryption (AES-GCM) with a two-layer security model. Your master password is never stored, and all secrets are encrypted using industry-standard cryptographic techniques.

#### Q: Can I use TrueFA-Py on multiple devices?
A: Yes, you can export your vault from one device and import it on another. Just ensure you keep your export file secure.

#### Q: Does TrueFA-Py support backup codes?
A: TrueFA-Py focuses on TOTP codes. You should keep backup codes provided by services separately in a secure location.

### Technical Questions

#### Q: What encryption does TrueFA-Py use?
A: TrueFA-Py uses AES-GCM for encrypting secrets, with keys derived using PBKDF2 with SHA-256 and a high iteration count.

#### Q: Where are my secrets stored?
A: Secrets are stored in an encrypted vault in the `.truefa` directory in your user home folder (or in the application directory if running in portable mode).

#### Q: Will TrueFA-Py work offline?
A: Yes, TrueFA-Py works completely offline. TOTP codes are generated based on the current time and don't require an internet connection.

#### Q: Is TrueFA-Py compatible with other authenticator apps?
A: Yes, TrueFA-Py is compatible with Google Authenticator, Authy, and other TOTP-based authenticator apps, as it follows the RFC 6238 standard.

## Getting Help

For additional help:

- Check the [GitHub repository](https://github.com/zainibeats/truefa-py) for updates
- Review the issues and discussions sections for common problems
- Submit a detailed issue report if you encounter a new problem
- Contact the developers via email for security concerns 