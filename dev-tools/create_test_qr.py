"""
Create a test QR code for TrueFA-Py testing.
This generates a valid TOTP QR code that can be used for testing.
"""

import qrcode
import os
import base64
from urllib.parse import quote

# Create the 'assets/test' directory if it doesn't exist
test_dir = os.path.join('assets', 'test')
os.makedirs(test_dir, exist_ok=True)

# TOTP URI format: otpauth://totp/LABEL?PARAMETERS
secret = "TESTINGKEY123456"  # Replace with your secret
issuer = "TrueFA-Test"
account = "test@example.com"
label = f"{issuer}:{account}"
uri = f"otpauth://totp/{quote(label)}?secret={secret}&issuer={quote(issuer)}"

# Create QR code
qr = qrcode.QRCode(
    version=1,
    error_correction=qrcode.constants.ERROR_CORRECT_L,
    box_size=10,
    border=4,
)
qr.add_data(uri)
qr.make(fit=True)

# Create an image from the QR Code
img = qr.make_image(fill_color="black", back_color="white")

# Save the QR code
qr_file_path = os.path.join(test_dir, 'test_qr.png')
img.save(qr_file_path)

print(f"Test QR code created at: {qr_file_path}")
print(f"URI: {uri}")
print(f"Secret: {secret}")
