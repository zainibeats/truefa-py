#!/bin/bash
set -e

# Check if the Rust library is available and working
echo "Checking Rust crypto library..."
if [ -f "/app/truefa_crypto/libtruefa_crypto.so" ]; then
    echo "Found Rust library at /app/truefa_crypto/libtruefa_crypto.so"
else
    echo "WARNING: Rust library not found, will use Python fallback"
    export TRUEFA_USE_FALLBACK=1
fi

# Ensure images directory has proper permissions
if [ ! -d "/app/images" ]; then
    mkdir -p /app/images
fi
chmod 755 /app/images
echo "Images directory is at /app/images"
echo "You can place QR code images here for scanning"

# Show instructions for volume mounting
echo ""
echo "USAGE NOTES:"
echo "------------"
echo "1. To persist vault data: -v /path/on/host:/home/truefa/.truefa"
echo "2. To share QR code images: -v /path/to/images:/app/images"
echo ""

# Run the main application
exec "$@" 