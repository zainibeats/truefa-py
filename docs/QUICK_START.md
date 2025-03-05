# TrueFA-Py Quick Start Guide

This guide will help you quickly get started with TrueFA-Py, a secure two-factor authentication (2FA) application.

## Installation

### Windows Users

#### Portable Version (Recommended)

1. Download `TrueFA-Py-Windows.zip` from the [releases page](https://github.com/zainibeats/truefa-py/releases)
2. Extract the ZIP file to any location
3. Run `setup.bat` to install prerequisites
4. Launch the application using `TrueFA-Py.bat`

#### Installer Version

1. Download `TrueFA-Py_Setup.exe` from the [releases page](https://github.com/zainibeats/truefa-py/releases)
2. Run the installer and follow the prompts
3. Launch TrueFA-Py from the Start menu

### Linux Users

```bash
# Install from PyPI
pip install truefa-py

# Run the application
truefa-py
```

## Initial Setup

1. When first launched, you'll be prompted to create a vault master password
2. Create a strong, memorable password - this will protect all your 2FA tokens
3. Remember this password as it cannot be recovered if forgotten

## Adding Your First 2FA Token

### Using a QR Code Image

1. Save a 2FA setup QR code as an image file (PNG, JPG, etc.)
2. Select option 1 from the main menu: "Load QR code from image"
3. Enter the path to the image file
4. The application will extract the secret and display your first TOTP code

### Manual Entry

1. Select option 2 from the main menu: "Enter secret key manually"
2. Enter your secret key (base32-encoded string provided by the service)
3. Enter a name for this token when prompted
4. The application will generate your TOTP code

## Saving Tokens

After adding a token (via QR code or manually):

1. Select option 3: "Save current secret"
2. Enter your master password when prompted
3. The token is now securely saved in your vault

## Generating TOTP Codes

1. Select option 4: "View saved secrets"
2. Enter your master password when prompted
3. Select the desired token from the list
4. The current TOTP code will be displayed with a countdown timer

## Common Commands

| Option | Action | Description |
|--------|--------|-------------|
| 1 | Load QR code | Import 2FA token from QR code image |
| 2 | Enter secret manually | Manually input a 2FA secret key |
| 3 | Save current secret | Save the current token to your vault |
| 4 | View saved secrets | Access your saved tokens and generate codes |
| 5 | Export secrets | Back up your encrypted vault |
| 6 | Clear screen | Clear the terminal screen |
| 7 | Exit | Exit the application securely |

## Troubleshooting

If you encounter issues:

- **Application hangs**: Try running with `TRUEFA_USE_FALLBACK=1`
- **QR code not recognized**: Ensure the image is clear and try again
- **Vault not found**: Check permissions on the `.truefa` directory
- **Invalid secret**: Verify the secret key is properly formatted

For detailed troubleshooting, see the [User Guide](USER_GUIDE.md).

## Getting Help

- Full documentation: [User Guide](USER_GUIDE.md)
- Security details: [Security Guide](SECURITY_GUIDE.md)
- GitHub repository: [TrueFA-Py](https://github.com/zainibeats/truefa-py) 