# TrueFA

A secure two-factor authentication code generator with support for QR code scanning and encrypted storage. This tools is designed to generate TOPT codes from QR code images or screenshots

## Features

- Secure memory handling for sensitive data
- QR code scanning support
- Encrypted storage of TOTP secrets
- Master password protection
- Export/import functionality
- Auto-cleanup of secrets
- Cross-platform support

## Installation

### Option 1: Docker (Recommended)

1. Clone the repository:
```bash
git clone https://github.com/zainibeats/truefa.git
cd truefa
```

2. Build and run with Docker:
```bash
# Build the Docker image
docker build -t truefa .

# Run the container
docker run -it --name truefa \
  -v "${PWD}/images:/app/images" \
  -v "${PWD}/.truefa:/app/.truefa" \
  -v "$HOME/Downloads:/home/truefa/Downloads" \
  truefa

# On Windows PowerShell, use:
docker run -it --name truefa `
  -v "${PWD}\images:/app/images" `
  -v "${PWD}\.truefa:/app/.truefa" `
  -v "$HOME\Downloads:/home/truefa/Downloads" `
  truefa

# For subsequent runs, just use:
docker start -ai truefa
```

The application will be available in your terminal. Place your QR code images in the `images` directory to scan them

### Option 2: Direct Installation

#### Windows Prerequisites

1. Install ZBar:
   - Download the [ZBar Windows Binaries](https://sourceforge.net/projects/zbar/files/zbar/0.10/zbar-0.10-setup.exe/download)
   - Run the installer
   - Add the installation directory (usually `C:\Program Files (x86)\ZBar`) to your system PATH

2. Install GPG:
   - Download [GPG4Win](https://www.gpg4win.org/download.html)
   - Run the installer
   - Add the installation directory to your system PATH

#### Linux/macOS Prerequisites

- For Ubuntu/Debian:
  ```bash
  sudo apt-get install libzbar0 zbar-tools gpg
  ```

- For macOS:
  ```bash
  brew install zbar gpg
  ```

#### Installation Steps

1. Clone the repository:
```bash
git clone https://github.com/zainibeats/truefa.git
cd truefa
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Install the package:
```bash
pip install -e .
```

## Usage

### Using with Docker

1. Place your QR code images in the `images` directory
2. Start the container:
```bash
docker start -ai truefa
```
3. Use the interactive menu in your terminal
4. When exporting secrets, they will be saved to your system's Downloads folder
5. To stop the application, press Ctrl+C

### Running Locally

1. Run the application:
```bash
truefa
```

2. Follow the on-screen menu to:
   - Load QR codes from images
   - Enter TOTP secrets manually
   - Save secrets securely
   - Load saved secrets
   - Export secrets (will be saved to your Downloads folder)

## Directory Structure

- `images/` - Place your QR code images here
- `.truefa/` - Secure storage for encrypted secrets
- Your system's Downloads folder - Location for exported secrets

## Security Features

- Secure memory handling with page locking
- AES-GCM encryption for stored secrets
- Scrypt key derivation for master password
- Auto-cleanup of secrets after timeout
- GPG encryption for exports

## Requirements

### For Docker Installation
- Docker

### For Direct Installation
- Python 3.8 or higher
- GPG for export functionality
- ZBar library for QR code scanning

## Development

1. Set up a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

2. Install development dependencies:
```bash
pip install -r requirements.txt
```

## Project Structure

```
truefa/
├── src/
│   ├── security/         # Security-related modules
│   │   ├── secure_memory.py
│   │   ├── secure_string.py
│   │   └── secure_storage.py
│   ├── totp/            # TOTP-related functionality
│   │   └── auth.py
│   ├── utils/           # Utility functions
│   │   └── screen.py
│   └── main.py          # Main application entry point
├── images/              # Directory for QR code images
├── .truefa/             # Secure storage directory
├── Dockerfile          # Docker configuration
└── requirements.txt     # Python dependencies
```

## License

This project is licensed under the MIT License. See the LICENSE file for details.
