"""
TOTP-related modules for TrueFA
"""

# Using OpenCV for QR code scanning for reliable cross-platform operation
from .auth_opencv import TwoFactorAuth

__all__ = ['TwoFactorAuth'] 