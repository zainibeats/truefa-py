"""
TrueFA-Py: TOTP Authenticator Application

This is the entry point for the TrueFA-Py application.
It uses OpenCV for QR code scanning for reliable operation across all platforms.
"""

# Import and run the OpenCV version
from src.main_opencv import main

if __name__ == "__main__":
    main() 