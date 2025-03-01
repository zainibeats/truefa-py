# TrueFA - True Factor Authentication

A secure, Rust-backed two-factor authentication application with enhanced security features.

## Features

- **Secure Storage**: All secrets are stored using memory protection techniques
- **Rust Cryptography**: Core security operations implemented in Rust for enhanced security
- **Two UI Modes**: Console and GUI interfaces available
- **Portable**: Available as both a standalone executable and installer package
- **QR Code Support**: Import tokens via camera or image files
- **Time-Based OTP**: Full TOTP implementation with customizable parameters

## Prerequisites

To build TrueFA from source, you need:

- Python 3.10 or later
- Rust (latest stable version)
- PyInstaller
- NSIS (for building Windows installer)

## Building from Source

### Setting up the Environment

1. Clone the repository
2. Create a virtual environment:
   ```
   python -m venv venv
   .\venv\Scripts\Activate.ps1
   pip install -r requirements.txt
   ```

### Building the Rust Cryptography Backend

1. Ensure Rust is installed by checking:
   ```
   rustc --version
   ```

2. Run the build script:
   ```
   python secure_build_fix.py
   ```
   This script will compile the Rust cryptography module and place the DLL in the correct location.

### Building the Application

There are several ways to build TrueFA:

#### Method 1: Using the build_package.py script

The simplest way to build both the executable and installer:

```
python build_package.py
```

This creates both a portable executable and an installer in the `dist` directory.

#### Method 2: Using PyInstaller directly

For more control over the build process:

```
pyinstaller TrueFA_simple.spec
```

#### Method 3: Building the installer manually

```
pyinstaller TrueFA_installer.spec
makensis installer.nsi
```

### Build Outputs

The build process will place these files in the `dist` directory:

- Portable executable: `TrueFA.exe` or `TrueFA_gui.exe`
- Installer: `TrueFA_Setup.exe`

## Installation

### Portable Version

Simply download and run `TrueFA.exe`. No installation required. The application will store its data in the user's AppData folder.

### Installer Version

Run `TrueFA_Setup.exe` and follow the installation wizard. This will:
- Install TrueFA to the Program Files directory
- Create start menu shortcuts
- Add an uninstaller
- Register the application with Windows

## Usage

### Console Mode

Run `TrueFA.exe` from the command line to use the text-based interface.

### GUI Mode

Double-click the TrueFA icon to launch the graphical user interface.

## Note on Rust Cryptography Integration

TrueFA uses a hybrid approach for cryptography:

1. **Primary Implementation**: Rust-based cryptography module provides enhanced security through memory protection and Rust's safety guarantees
2. **Fallback Mechanism**: If the Rust module fails to load, the application will automatically fall back to a pure Python implementation

This design ensures maximum compatibility while prioritizing security when possible.

## License

MIT 

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Acknowledgements

- [Add acknowledgements here]
