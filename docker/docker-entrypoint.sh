#!/bin/bash
set -e

# Set data directory explicitly to ensure it uses the mounted volume
export TRUEFA_DATA_DIR="/home/truefa/.truefa"
echo "Setting TRUEFA_DATA_DIR to $TRUEFA_DATA_DIR"

# Check if the Rust library is available and working
echo "Checking Rust crypto library..."
RUST_LIB_PATHS=(
    "/app/truefa_crypto/libtruefa_crypto.so"
    "/usr/local/lib/libtruefa_crypto.so"
)

RUST_LIB_FOUND=false
for path in "${RUST_LIB_PATHS[@]}"; do
    if [ -f "$path" ]; then
        echo "Found Rust library at $path"
        RUST_LIB_FOUND=true
        # Make sure the library has proper permissions
        chmod 755 "$path" 2>/dev/null || true
    fi
done

if [ "$RUST_LIB_FOUND" = false ]; then
    echo "WARNING: Rust library not found, will use Python fallback"
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

# Ensure the .truefa directory exists and is writable
if [ ! -d "$TRUEFA_DATA_DIR" ]; then
    # Try to create the directory
    mkdir -p "$TRUEFA_DATA_DIR" || echo "WARNING: Could not create data directory - using local fallback"
    
    # If we couldn't create it, use a local directory instead
    if [ ! -d "$TRUEFA_DATA_DIR" ]; then
        echo "Creating local fallback directory at /app/local_vault"
        mkdir -p /app/local_vault
        export TRUEFA_DATA_DIR=/app/local_vault
        
        # Create subdirectories in the local vault
        mkdir -p /app/local_vault/exports
        mkdir -p /app/local_vault/logs
        
        # Set permissions
        chmod -R 700 /app/local_vault
        
        echo "Using local directory for vault: /app/local_vault"
        echo "NOTE: Data will be lost when container stops unless /app is mounted"
    fi
fi

# Create exports directory if possible
if [ -d "$TRUEFA_DATA_DIR" ]; then
    # Export directory for exported secrets
    if [ ! -d "$TRUEFA_DATA_DIR/exports" ]; then
        mkdir -p "$TRUEFA_DATA_DIR/exports" || echo "WARNING: Could not create exports directory"
    fi
    chmod 700 "$TRUEFA_DATA_DIR/exports" 2>/dev/null || echo "Note: Could not change permissions on exports directory"
    echo "Exports directory is at $TRUEFA_DATA_DIR/exports"
    
    # Logs directory
    if [ ! -d "$TRUEFA_DATA_DIR/logs" ]; then
        mkdir -p "$TRUEFA_DATA_DIR/logs" || echo "WARNING: Could not create logs directory"
    fi
    chmod 700 "$TRUEFA_DATA_DIR/logs" 2>/dev/null || echo "Note: Could not change permissions on logs directory"
fi

# Show instructions for volume mounting
echo ""
echo "USAGE NOTES:"
echo "------------"
echo "1. To persist vault data and exports: -v /path/on/host:$TRUEFA_DATA_DIR"
echo "2. To share QR code images: -v /path/to/images:/app/images"
echo ""
echo "IMPORT/EXPORT FUNCTIONALITY:"
echo "--------------------------"
echo "- Export secrets: Use menu option 5"
echo "- Import secrets: Use menu option 6"
echo "- Exported files are saved to the $TRUEFA_DATA_DIR/exports directory"
echo "- Import files from the images directory or specify full path"
echo ""

# Run the main application
exec "$@" 