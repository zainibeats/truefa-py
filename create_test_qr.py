import qrcode
import os

# Create a QR code with a valid TOTP URI
# This is a test secret (don't use for real 2FA)
secret = "JBSWY3DPEHPK3PXP"  # Standard test secret used in TOTP examples
uri = f"otpauth://totp/Test:example@test.com?secret={secret}&issuer=Test"

# Generate QR code
qr = qrcode.QRCode(
    version=1,
    error_correction=qrcode.constants.ERROR_CORRECT_L,
    box_size=10,
    border=4,
)
qr.add_data(uri)
qr.make(fit=True)

# Create an image from the QR code
img = qr.make_image(fill_color="black", back_color="white")

# Save it to the images directory
os.makedirs("images", exist_ok=True)
img.save("images/qrtest.png")

print(f"Created QR code with secret '{secret}' at images/qrtest.png")
print(f"URI: {uri}")
