#!/bin/bash
set -e

# Check if the Rust library is available and working
echo "Checking Rust crypto library..."
RUST_LIB_PATHS=(
    "/app/truefa_crypto/libtruefa_crypto.so"
    "/usr/local/lib/libtruefa_crypto.so"
)

RUST_LIB_FOUND=false
for path in "${RUST_LIB_PATHS[@]}"; do
    if [ -f "$path" ] && [ -s "$path" ]; then  # File exists and is not empty
        # Check if the file is a valid shared object and not just a placeholder
        if file "$path" | grep -q "shared object"; then
            echo "Found valid Rust library at $path"
            RUST_LIB_FOUND=true
            # Make sure the library has proper permissions
            chmod 755 "$path" 2>/dev/null || true
            break
        else
            echo "Found $path but it doesn't appear to be a valid shared library"
        fi
    fi
done

if [ "$RUST_LIB_FOUND" = false ]; then
    echo "WARNING: Valid Rust library not found, will use Python fallback"
    export TRUEFA_USE_FALLBACK=1
else
    echo "Rust library found, attempting to use native implementation"
    # Only use fallback if explicitly requested
    if [ "${TRUEFA_USE_FALLBACK}" = "1" ]; then
        echo "TRUEFA_USE_FALLBACK is set to 1, using Python fallback despite Rust library being available"
    else
        # Unset fallback flag if it was set to empty string
        unset TRUEFA_USE_FALLBACK
    fi
fi

# Ensure directories have proper permissions
echo "Setting up application directories..."

# Images directory for QR codes
if [ ! -d "/app/images" ]; then
    mkdir -p /app/images
fi
# Try to change permissions but don't fail if it doesn't work (for Windows hosts)
chmod 755 /app/images || echo "Note: Could not change permissions on /app/images (this is normal when mounting from Windows)"
echo "Images directory is at /app/images"
echo "You can place QR code images here for scanning"

# Export directory for exported secrets
if [ ! -d "/home/truefa/.truefa/exports" ]; then
    mkdir -p /home/truefa/.truefa/exports
fi
chmod 700 /home/truefa/.truefa/exports || echo "Note: Could not change permissions on exports directory (this is normal when mounting from Windows)"
echo "Exports directory is at /home/truefa/.truefa/exports"
echo "Exported secrets will be stored here"

# Logs directory
if [ ! -d "/home/truefa/.truefa/logs" ]; then
    mkdir -p /home/truefa/.truefa/logs
fi
chmod 700 /home/truefa/.truefa/logs || echo "Note: Could not change permissions on logs directory"

# Show instructions for volume mounting
echo ""
echo "USAGE NOTES:"
echo "------------"
echo "1. To persist vault data and exports: -v /path/on/host:/home/truefa/.truefa"
echo "2. To share QR code images: -v /path/to/images:/app/images"
echo ""
echo "IMPORT/EXPORT FUNCTIONALITY:"
echo "--------------------------"
echo "- Export secrets: Use menu option 5"
echo "- Import secrets: Use menu option 6"
echo "- Exported files are saved to /home/truefa/.truefa/exports"
echo "- Import files from /app/images or specify full path"
echo ""

# Run the main application
exec "$@" 