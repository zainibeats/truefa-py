FROM python:3.10-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    libzbar0 \
    zbar-tools \
    gnupg2 \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -s /bin/bash truefa
USER truefa
WORKDIR /app

# Set up GPG home directory with correct permissions
RUN mkdir -p /home/truefa/.gnupg && \
    chmod 700 /home/truefa/.gnupg && \
    gpg --list-keys

# Copy application files
COPY --chown=truefa:truefa . .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Create necessary directories with correct permissions
RUN mkdir -p images .truefa/exports && \
    chmod 700 .truefa && \
    chmod 700 .truefa/exports

# Set environment variables
ENV QR_IMAGES_DIR=/app/images
ENV HOME=/home/truefa
ENV GNUPGHOME=/home/truefa/.gnupg

# Run the application
CMD ["python", "-m", "src.main"] 