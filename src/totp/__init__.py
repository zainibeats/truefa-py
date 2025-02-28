"""
TOTP-related modules for TrueFA
"""

# Import the OpenCV-based implementation instead of the pyzbar-based one
from .auth_opencv import TwoFactorAuth

__all__ = ['TwoFactorAuth'] 