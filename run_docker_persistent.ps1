# PowerShell script to run the truefa-py Docker container with named volumes
# This ensures better persistence across container runs

# Check if Docker is installed and running
try {
    docker info | Out-Null
} catch {
    Write-Host "Error: Docker doesn't seem to be running. Please start Docker Desktop and try again." -ForegroundColor Red
    exit 1
}

# Check for and create Docker volumes if they don't exist
$vaultVolumeExists = docker volume ls -q -f "name=truefa-vault" 2>$null
if (-not $vaultVolumeExists) {
    Write-Host "Creating Docker volume for vault data..." -ForegroundColor Yellow
    docker volume create truefa-vault
} else {
    Write-Host "Using existing Docker volume 'truefa-vault'" -ForegroundColor Cyan
}

# Initialize the volume with proper permissions
Write-Host "Initializing volume with proper permissions..." -ForegroundColor Yellow
docker run --rm `
    -v "truefa-vault:/data" `
    alpine sh -c "mkdir -p /data/.truefa /data/.truefa/exports /data/.truefa/crypto && chmod -R 777 /data"

# Create a local images directory if it doesn't exist
$imagesDir = "$PSScriptRoot\images"
if (-not (Test-Path $imagesDir)) {
    Write-Host "Creating local images directory: $imagesDir" -ForegroundColor Yellow
    New-Item -ItemType Directory -Path $imagesDir -Force | Out-Null
} else {
    Write-Host "Using existing local images directory: $imagesDir" -ForegroundColor Cyan
}

# Run the Docker container
Write-Host "Starting truefa-py container with persistent storage..." -ForegroundColor Green
Write-Host "Press Ctrl+C to stop the container when done." -ForegroundColor Yellow
Write-Host "Your data will be saved in Docker volumes and persist between runs." -ForegroundColor Cyan
Write-Host "To use QR codes, place images in: $imagesDir" -ForegroundColor Cyan

# Check if the image exists
$imageExists = docker images -q truefa-py 2>$null
if (-not $imageExists) {
    Write-Host "Warning: truefa-py Docker image not found. Make sure you've built it first with:" -ForegroundColor Yellow
    Write-Host "docker build -t truefa-py ." -ForegroundColor Yellow
    $buildNow = Read-Host "Would you like to build the Docker image now? (y/n)"
    if ($buildNow -eq 'y') {
        docker build -t truefa-py .
    } else {
        exit 1
    }
}

# Run the container with named volumes for persistence and local directory mount for images
docker run -it --rm `
    -v "truefa-vault:/home/truefa/.truefa" `
    -v "$imagesDir`:/app/images" `
    -e "HOME=/home/truefa" `
    -e "TRUEFA_DEBUG=1" `
    -e "TRUEFA_USE_FALLBACK=1" `
    -e "TRUEFA_PORTABLE=1" `
    -e "TRUEFA_DATA_DIR=/home/truefa/.truefa" `
    -e "TRUEFA_EXPORTS_DIR=/home/truefa/.truefa/exports" `
    -e "PYTHONUNBUFFERED=1" `
    truefa-py
