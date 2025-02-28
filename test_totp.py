import sys
import os
import pyotp
from src.security.secure_string import SecureString
from src.totp.auth_opencv import TwoFactorAuth

def main():
    print("Testing TOTP generation directly...")
    
    # Initialize the auth component
    auth = TwoFactorAuth()
    
    # Test with a known working secret
    test_secret = "JBSWY3DPEHPK3PXP"  # Standard test secret
    print(f"Using test secret: {test_secret}")
    
    # Create a secure string from the test secret
    secure_secret = SecureString(test_secret)
    print(f"Created SecureString with value: {str(secure_secret)}")
    
    # Try generating TOTP directly with pyotp
    try:
        direct_totp = pyotp.TOTP(test_secret)
        direct_code = direct_totp.now()
        print(f"Direct TOTP generation successful: {direct_code}")
    except Exception as e:
        print(f"Error with direct TOTP generation: {str(e)}")
    
    # Try generating with our auth class
    auth.secret = secure_secret
    code, remaining = auth.generate_totp()
    if code:
        print(f"TrueFA TOTP generation successful: {code} (expires in {remaining}s)")
    else:
        print("TrueFA TOTP generation failed")
    
    # Try QR code parsing if an argument is provided
    if len(sys.argv) > 1:
        image_path = sys.argv[1]
        print(f"Testing QR code extraction from: {image_path}")
        secret, error = auth.extract_secret_from_qr(image_path)
        if error:
            print(f"QR extraction error: {error}")
        else:
            print(f"QR extraction successful, parsed: {getattr(auth, 'issuer', 'Unknown')}:{getattr(auth, 'account', 'Unknown')}")
            code, remaining = auth.generate_totp()
            if code:
                print(f"TOTP from QR: {code} (expires in {remaining}s)")
            else:
                print("Failed to generate TOTP from QR")

if __name__ == "__main__":
    main()
