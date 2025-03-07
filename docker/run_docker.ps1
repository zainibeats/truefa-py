# PowerShell script to run the truefa-py Docker container
# This script properly handles volume mounts for Windows

# Check if Docker is installed and running
try {
    docker info | Out-Null
} catch {
    Write-Host "Error: Docker doesn't seem to be running. Please start Docker Desktop and try again." -ForegroundColor Red
    exit 1
}

# Make sure the local directories exist
$vaultDir = Join-Path -Path (Get-Location).Path -ChildPath "vault"
$imagesDir = Join-Path -Path (Get-Location).Path -ChildPath "images"

if (-not (Test-Path -Path $vaultDir)) {
    Write-Host "Creating vault directory..." -ForegroundColor Yellow
    New-Item -Path $vaultDir -ItemType Directory | Out-Null
} else {
    Write-Host "Using existing vault directory: $vaultDir" -ForegroundColor Cyan
}

if (-not (Test-Path -Path $imagesDir)) {
    Write-Host "Creating images directory..." -ForegroundColor Yellow
    New-Item -Path $imagesDir -ItemType Directory | Out-Null
} else {
    Write-Host "Using existing images directory: $imagesDir" -ForegroundColor Cyan
}

# Show configuration
$currentDir = (Get-Location).Path
Write-Host "Current directory: $currentDir" -ForegroundColor Cyan
Write-Host "Vault directory: $vaultDir" -ForegroundColor Cyan
Write-Host "Images directory: $imagesDir" -ForegroundColor Cyan

# Check for Docker volumes
$volumeExists = docker volume ls -q -f "name=truefa-vault" 2>$null
if (-not $volumeExists) {
    Write-Host "Creating Docker volume for vault data..." -ForegroundColor Yellow
    docker volume create truefa-vault
}

# Run the Docker container
Write-Host "Starting truefa-py container..." -ForegroundColor Green
Write-Host "Press Ctrl+C to stop the container when done." -ForegroundColor Yellow
Write-Host "Your data will be saved in '$vaultDir'" -ForegroundColor Cyan

# Check if the image exists
$imageExists = docker images -q truefa-py 2>$null
if (-not $imageExists) {
    Write-Host "Warning: truefa-py Docker image not found. Make sure you've built it first with:" -ForegroundColor Yellow
    Write-Host "docker build -t truefa-py -f docker/Dockerfile ." -ForegroundColor Yellow
    $buildNow = Read-Host "Would you like to build the Docker image now? (y/n)"
    if ($buildNow -eq 'y') {
        docker build -t truefa-py -f docker/Dockerfile .
    } else {
        exit 1
    }
}

# Run the container with proper mount paths
# Using Z option to relabel the content for SELinux compatibility
docker run -it --rm `
    -v "${vaultDir}:/home/truefa/.truefa:Z" `
    -v "${imagesDir}:/app/images:Z" `
    -e "HOME=/home/truefa" `
    -e "TRUEFA_DEBUG=1" `
    -e "TRUEFA_USE_FALLBACK=1" `
    truefa-py