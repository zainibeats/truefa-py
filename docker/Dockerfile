# Stage 1: Build the Rust crypto module
# Using the latest Rust version to support Cargo.lock v4
FROM rust:latest AS rust-builder

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

# Build the Rust library for Linux (no Windows-specific export flags)
RUN RUST_BACKTRACE=1 cargo build --release --verbose && \
    ls -la target/release/

# Make sure the shared library is properly copied to the output directory
RUN mkdir -p /build/output && \
    cp /build/rust_crypto/target/release/libtruefa_crypto.so /build/output/ && \
    chmod 755 /build/output/libtruefa_crypto.so

# Stage 2: Build the final Python application
FROM python:3.10-slim

# Install system dependencies:
# - gnupg2: Required for secure export functionality
# - libgl1-mesa-glx: Required for OpenCV
# - libxext6: Additional dependency for OpenCV display functionality
# - libglib2.0-0: Required for OpenCV threading operations
# - openssl: Provides cryptographic functions for import/export
RUN apt-get update && apt-get install -y \
    gnupg2 \
    libgl1-mesa-glx \
    libxext6 \
    libglib2.0-0 \
    openssl \
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

# Copy the entrypoint script separately
COPY --chown=truefa:truefa docker/docker-entrypoint.sh /app/
RUN chmod +x /app/docker-entrypoint.sh

# Copy the rest of the application code
COPY --chown=truefa:truefa . .

# Check the location of the entrypoint script
RUN ls -la /app && \
    echo "Checking for entrypoint script..."

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir pycryptodome pycryptodomex

# Create and secure application directories including exports
RUN mkdir -p images && chmod 755 images && \
    mkdir -p /home/truefa/.truefa /home/truefa/.truefa/exports /home/truefa/.truefa/logs && \
    chown -R truefa:truefa /home/truefa/.truefa && \
    chmod -R 700 /home/truefa/.truefa

# Create volume mount points for QR code images and exports
VOLUME ["/app/images", "/home/truefa/.truefa"]

# Switch to non-root user for security
USER truefa

# Configure environment
ENV HOME=/home/truefa \
    GNUPGHOME=/home/truefa/.gnupg \
    PYTHONPATH=/app \
    TRUEFA_FALLBACK_TIMEOUT=30000 \
    TRUEFA_DEBUG_CRYPTO=1 \
    PYTHONUNBUFFERED=1

# Set working directory
WORKDIR /app

# Use the entrypoint script
ENTRYPOINT ["/app/docker-entrypoint.sh"]

# Start the application
CMD ["python", "main.py"]