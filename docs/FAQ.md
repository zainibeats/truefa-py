# TrueFA-Py: Frequently Asked Questions

## General Questions

### What is TrueFA-Py?
TrueFA-Py is a secure, offline Two-Factor Authentication (2FA) application that generates Time-based One-Time Password (TOTP) codes for your accounts. It stores all your authentication secrets locally in an encrypted vault.

### Is TrueFA-Py free?
Yes, TrueFA-Py is completely free and open-source.

### Which operating systems are supported?
TrueFA-Py runs on Windows, macOS, and Linux. The Windows version includes a dedicated installer and portable version.

### Does TrueFA-Py require an internet connection?
No, TrueFA-Py works completely offline. Once you've set up your authentication tokens, you can generate codes without an internet connection.

### How does TrueFA-Py compare to other authenticator apps?
Unlike many authenticator apps, TrueFA-Py:
- Stores all data locally (not in the cloud)
- Uses strong encryption with a two-layer security model
- Provides a command-line interface
- Works on all major desktop platforms
- Offers both Rust and Python implementations for cryptography
- Can be run in portable mode from removable media

## Security Questions

### How secure is TrueFA-Py?
TrueFA-Py uses industry-standard encryption (AES-GCM) with a two-layer security model:
1. Your master password unlocks the vault and decrypts the master key
2. The master key encrypts/decrypts individual TOTP secrets

This envelope encryption approach ensures that even if one layer is compromised, your secrets remain protected by the other layer.

### Where are my authentication secrets stored?
All secrets are stored in an encrypted vault in the `.truefa` directory in your user home folder. In portable mode, they're stored in the application directory.

### Can someone recover my master password if I forget it?
No, your master password is never stored. It's used to derive encryption keys through a one-way process. If you forget your master password, you cannot recover your stored secrets unless you have a backup.

### Does TrueFA-Py have a security audit?
While TrueFA-Py follows security best practices, it has not undergone a formal third-party security audit. We welcome security researchers to review our code and report any findings.

## Usage Questions

### How do I add a new 2FA token?
You can add tokens in two ways:
1. Using a QR code image (option 1)
2. Manually entering the secret key (option 2)

After adding a token, use option 3 to save it to your vault.

### How do I generate a TOTP code?
Select option 4 from the main menu, enter your master password, select the desired token, and the application will display the current TOTP code with a countdown timer.

### How do I back up my tokens?
Use option 5 from the main menu to export your encrypted vault. Keep this exported file secure, as it contains all your tokens (though they remain encrypted).

### Can I transfer my tokens to another device?
Yes, export your vault from the first device and then copy the exported file to the second device. You can then import it using the appropriate commands.

### Can I use TrueFA-Py with my mobile phone?
TrueFA-Py is designed for desktop use. For mobile devices, you may want to consider compatible TOTP apps like Aegis (Android) or Tofu (iOS).

## Technical Questions

### What is the difference between portable and installer versions?
- The portable version can run without installation and stores data in its directory
- The installer version installs to Program Files and creates Start menu shortcuts

### Does TrueFA-Py support hardware security keys?
Not currently. TrueFA-Py focuses on TOTP-based authentication rather than U2F or WebAuthn.

### What is the Rust cryptography module?
TrueFA-Py uses a Rust-based module for high-performance, memory-safe cryptographic operations. This provides enhanced security and performance compared to pure Python implementations.

### What happens if the Rust module doesn't work on my system?
TrueFA-Py automatically falls back to a pure Python implementation if the Rust module can't be loaded or encounters issues. You can also force this behavior with the `TRUEFA_USE_FALLBACK=1` environment variable.

### How do I run TrueFA-Py in portable mode?
Set the `TRUEFA_PORTABLE=1` environment variable before running the application, or use the included portable launcher in the Windows package.

## Troubleshooting

### The application hangs when I try to create or unlock my vault
This was an issue in older versions due to the Rust `c_generate_salt` function. Recent versions have completely redesigned this function to eliminate hanging issues. Make sure you're using the latest release.

If you still experience hanging, try running with `TRUEFA_USE_FALLBACK=1` to use the Python implementation.

### I can't scan QR codes on Windows
TrueFA-Py uses OpenCV for QR code scanning which provides reliable operation across all platforms including Windows.

### I'm getting "DLL not found" errors
Ensure that the Visual C++ Redistributable 2015-2022 is installed. The `setup.bat` script in the Windows package should install this automatically.

### I've forgotten my master password
Unfortunately, if you've forgotten your master password and don't have a backup, there's no way to recover your stored secrets. You'll need to reset your vault and set up your tokens again.

### The application can't find my vault
Check if the `.truefa` directory exists in your user home folder and ensure the application has read/write permissions for this directory. If running in portable mode, check the application directory.

### I'm getting permission errors when trying to create a vault
Try running the application with administrator privileges, or set the `TRUEFA_PORTABLE=1` environment variable to use a different storage location.

## Development Questions

### How can I contribute to TrueFA-Py?
Contributions are welcome! See the [DEVELOPER_GUIDE.md](DEVELOPER_GUIDE.md) for details on setting up a development environment and the project structure.

### How do I build TrueFA-Py from source?
Check the [DEVELOPER_GUIDE.md](DEVELOPER_GUIDE.md) for detailed build instructions.

### Can I use TrueFA-Py code in my own project?
Yes, TrueFA-Py is licensed under the MIT License, which allows you to use, modify, and distribute the code in your own projects, even for commercial purposes, as long as you include the original copyright notice.

### Where can I report bugs or request features?
You can report bugs and request features on the [GitHub Issues page](https://github.com/zainibeats/truefa-py/issues).

## Other Questions

### Does TrueFA-Py support other 2FA methods besides TOTP?
Currently, TrueFA-Py only supports TOTP-based authentication (RFC 6238). Support for other methods such as HOTP may be added in the future.

### Is TrueFA-Py compatible with Google Authenticator/Authy/etc.?
Yes, TrueFA-Py is compatible with any service that follows the TOTP standard (RFC 6238), which includes most major services that offer 2FA.

### How often are updates released?
Updates are released as needed to fix bugs, add features, and improve security. Check the [GitHub repository](https://github.com/zainibeats/truefa-py) for the latest releases.

### How can I contact the developers directly?
For security-related concerns, you can email [cheyenne@czaini.net](mailto:cheyenne@czaini.net). For other questions, please use the GitHub issues or discussions. 