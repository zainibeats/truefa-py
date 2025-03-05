# TrueFA-Py Test Package

This package contains everything needed to test TrueFA-Py on a fresh Windows installation.

## Installation

1. Run setup.bat as Administrator to install dependencies
2. Run TrueFA-Py.bat to start the application

## Testing

1. Create a new vault with a master password
2. Add a TOTP secret manually or use the test QR code in the images folder
   - Test QR Code Secret: TESTINGKEY123456
3. Generate TOTP codes
4. Save and reload your vault

## Compatibility

Windows 10 or newer is required. Run windows_compatibility_check.ps1 to check
if your system meets all the requirements:

`
powershell -ExecutionPolicy Bypass -File windows_compatibility_check.ps1
`

## Reporting Issues

When reporting issues, please include:
- Windows version and build number
- Error messages (if any)
- Steps to reproduce the issue
- Screenshots if possible

## Known Issues

- If you encounter "DLL not found" errors, make sure you've run setup.bat
- Admin privileges might be required for first-time setup
