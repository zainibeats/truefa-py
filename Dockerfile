# Stage 1: Build the Rust crypto module
# Using Rust 1.85 for compatibility with the latest Cargo.lock format
FROM rust:1.85-slim AS rust-builder

# Install Python dependencies required for PyO3 bindings
RUN apt-get update && apt-get install -y \
    python3 \
    python3-dev \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Set up build environment and compile Rust library
WORKDIR /build
COPY ./rust_crypto /build/rust_crypto
WORKDIR /build/rust_crypto
RUN cargo build --release
RUN mkdir -p /build/output && \
    cp /build/rust_crypto/target/release/libtruefa_crypto.so /build/output/

# Stage 2: Build the final Python application
FROM python:3.10-slim

# Install system dependencies:
# - libzbar0 & zbar-tools: Required for QR code scanning
# - gnupg2: Required for secure export functionality
RUN apt-get update && apt-get install -y \
    libzbar0 \
    zbar-tools \
    gnupg2 \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN useradd -m -s /bin/bash truefa

# Set up application directory
WORKDIR /app

# Configure GPG for the truefa user
RUN mkdir -p /home/truefa/.gnupg && \
    chmod 700 /home/truefa/.gnupg && \
    gpg --list-keys

# Copy the Rust crypto library from builder stage
COPY --from=rust-builder --chown=truefa:truefa /build/output/libtruefa_crypto.so /usr/local/lib/
COPY --from=rust-builder --chown=truefa:truefa /build/output/libtruefa_crypto.so /app/truefa_crypto/

# Copy application code
COPY --chown=truefa:truefa . .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Set up Python bindings for the Rust crypto library
RUN mkdir -p /app/truefa_crypto && \
    echo 'import os, sys\n\
import ctypes\n\
\n\
# Path to the Rust crypto library\n\
_dir = os.path.dirname(os.path.abspath(__file__))\n\
try:\n\
    # Try to load from the module directory first\n\
    _lib = ctypes.CDLL(os.path.join(_dir, "libtruefa_crypto.so"))\n\
except OSError:\n\
    # Fall back to system library path\n\
    _lib = ctypes.CDLL("/usr/local/lib/libtruefa_crypto.so")\n\
\n\
def verify_signature(message: bytes, signature: bytes, public_key: bytes) -> bool:\n\
    """Verify a digital signature using the Rust crypto library.\n\
    \n\
    This function validates a digital signature against a message using the provided public key.\n\
    \n\
    Args:\n\
        message: The original message bytes that was signed\n\
        signature: The signature bytes to verify\n\
        public_key: The public key bytes used for verification\n\
    \n\
    Returns:\n\
        bool: True if the signature is valid, False otherwise\n\
    """\n\
    _lib.verify_signature.argtypes = [ctypes.c_char_p, ctypes.c_size_t,\n\
                                   ctypes.c_char_p, ctypes.c_size_t,\n\
                                   ctypes.c_char_p, ctypes.c_size_t]\n\
    _lib.verify_signature.restype = ctypes.c_bool\n\
    return _lib.verify_signature(message, len(message),\n\
                              signature, len(signature),\n\
                              public_key, len(public_key))\n\
' > /app/truefa_crypto/__init__.py && \
    chmod 644 /app/truefa_crypto/__init__.py

# Create and secure application directories
RUN mkdir -p images .truefa/exports && \
    chmod 700 .truefa && \
    chmod 700 .truefa/exports

# Switch to non-root user for security
USER truefa

# Configure environment
ENV HOME=/home/truefa \
    GNUPGHOME=/home/truefa/.gnupg \
    PYTHONPATH=/app

# Set working directory
WORKDIR /app

# Start the application
CMD ["python", "-m", "src.main"]