# TrueFA-Py Docker Environment
# This Dockerfile creates a containerized environment for the TrueFA-Py application
# with support for import/export functionality and Rust cryptography.
#
# Known issues and workarounds:
# 1. Rust build may fail in Linux due to Windows-specific linker flags
#    - We patch build.rs to comment out Windows-specific /EXPORT: flags
# 2. Entrypoint script location may be inconsistent in different build contexts
#    - We create a backup entrypoint script to handle this case
# 3. Python fallback mode will be used if Rust build fails
#    - The entrypoint script detects if the Rust library is valid
#
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

# Patch the build.rs file to be compatible with Linux
# This removes Windows-specific /EXPORT: flags that cause build failures
RUN sed -i 's|/EXPORT:|# /EXPORT:|g' build.rs

# Try to build the Rust library but continue even if it fails
RUN cargo build --release || echo "Rust build failed, will use Python fallback"

# Create output directory (whether build succeeded or not)
RUN mkdir -p /build/output
# Copy the library if it exists, otherwise create an empty placeholder
RUN if [ -f "/build/rust_crypto/target/release/libtruefa_crypto.so" ]; then \
    cp /build/rust_crypto/target/release/libtruefa_crypto.so /build/output/ && \
    chmod 755 /build/output/libtruefa_crypto.so; \
    else \
    echo "Rust build failed, creating placeholder" && \
    touch /build/output/libtruefa_crypto.so; \
    fi

# Stage 2: Build the final Python application
FROM python:3.10-slim

# Install system dependencies:
# - gnupg2: Required for secure export functionality
# - libgl1-mesa-glx: Required for OpenCV
# - libxext6: Additional dependency for OpenCV display functionality
# - libglib2.0-0: Required for OpenCV threading operations
# - openssl: Provides cryptographic functions for import/export
# - file: Used to validate the Rust library
RUN apt-get update && apt-get install -y \
    gnupg2 \
    libgl1-mesa-glx \
    libxext6 \
    libglib2.0-0 \
    openssl \
    file \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN useradd -m -s /bin/bash truefa

# Set up application directory
WORKDIR /app

# Configure GPG for the truefa user
RUN mkdir -p /home/truefa/.gnupg && \
    chmod 700 /home/truefa/.gnupg && \
    gpg --list-keys

# Copy the Rust crypto library from builder stage (or placeholder)
COPY --from=rust-builder --chown=truefa:truefa /build/output/libtruefa_crypto.so /usr/local/lib/
COPY --from=rust-builder --chown=truefa:truefa /build/output/libtruefa_crypto.so /app/truefa_crypto/

# Copy application code
COPY --chown=truefa:truefa . .

# Create a basic backup entrypoint script that will be used if the main one fails to copy
RUN echo '#!/bin/bash' > /app/backup-entrypoint.sh && \
    echo 'set -e' >> /app/backup-entrypoint.sh && \
    echo 'echo "Using backup entrypoint script"' >> /app/backup-entrypoint.sh && \
    echo 'mkdir -p /home/truefa/.truefa/exports /home/truefa/.truefa/logs' >> /app/backup-entrypoint.sh && \
    echo 'chmod -R 700 /home/truefa/.truefa' >> /app/backup-entrypoint.sh && \
    echo 'export TRUEFA_USE_FALLBACK=1' >> /app/backup-entrypoint.sh && \
    echo 'exec "$@"' >> /app/backup-entrypoint.sh && \
    chmod +x /app/backup-entrypoint.sh

# Try to use the real entrypoint script, but fall back to the backup if it fails
COPY --chown=truefa:truefa ["docker/docker-entrypoint.sh", "/app/docker-entrypoint.sh"]
RUN if [ -f "/app/docker-entrypoint.sh" ]; then \
    chmod +x /app/docker-entrypoint.sh; \
    else \
    cp /app/backup-entrypoint.sh /app/docker-entrypoint.sh; \
    echo "Warning: Using backup entrypoint script"; \
    fi

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Create and secure application directories including exports
RUN mkdir -p images .truefa/exports .truefa/logs && \
    chmod 700 .truefa && \
    chmod 700 .truefa/exports && \
    chmod 700 .truefa/logs && \
    chmod 755 images

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