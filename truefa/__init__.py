# TrueFA Python Module
from datetime import datetime
import hashlib
import time

def generate_totp(secret, digits=6, period=30):
    """Generate a time-based one-time password."""
    timestamp = int(time.time() // period)
    msg = timestamp.to_bytes(8, byteorder='big')
    digest = hashlib.sha1(secret + msg).digest()
    offset = digest[-1] & 0x0F
    binary = ((digest[offset] & 0x7F) << 24)
    binary = binary | ((digest[offset + 1] & 0xFF) << 16)
    binary = binary | ((digest[offset + 2] & 0xFF) << 8)
    binary = binary | (digest[offset + 3] & 0xFF)
    return str(binary % (10 ** digits)).zfill(digits)

def verify_totp(token, secret, digits=6, period=30, valid_window=1):
    """Verify a time-based one-time password."""
    for i in range(-valid_window, valid_window + 1):
        current_token = generate_totp(secret, digits, period)
        if current_token == token:
            return True
    return False
