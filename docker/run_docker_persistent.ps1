# TrueFA-Py Docker Runner (Persistent Mode)
# This script builds and runs the TrueFA-Py Docker container with persistent storage

# Display header
Write-Host "TrueFA-Py Docker Runner (Persistent Mode)" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host ""

# Ensure we're in the correct directory (repository root)
$repoRoot = $PSScriptRoot | Split-Path -Parent
Set-Location $repoRoot

# Create local directories if they don't exist
$imagesDir = Join-Path $repoRoot "images"
$vaultDir = Join-Path $repoRoot "vault_data"

if (-not (Test-Path $imagesDir)) {
    Write-Host "Creating images directory: $imagesDir" -ForegroundColor Yellow
    New-Item -ItemType Directory -Path $imagesDir | Out-Null
}

if (-not (Test-Path $vaultDir)) {
    Write-Host "Creating vault data directory: $vaultDir" -ForegroundColor Yellow
    New-Item -ItemType Directory -Path $imagesDir | Out-Null
    New-Item -ItemType Directory -Path $vaultDir | Out-Null
    New-Item -ItemType Directory -Path "$vaultDir\exports" | Out-Null
    New-Item -ItemType Directory -Path "$vaultDir\logs" | Out-Null
}

# Build the Docker image
Write-Host "Building Docker image..." -ForegroundColor Green
docker build -t truefa-py -f docker/Dockerfile .

# Check if the build was successful
if ($LASTEXITCODE -ne 0) {
    Write-Host "Docker build failed with exit code $LASTEXITCODE" -ForegroundColor Red
    exit $LASTEXITCODE
}

# Run the container with persistent volumes
Write-Host "Running container with persistent storage..." -ForegroundColor Green
Write-Host "- Vault data and exports will be stored in: $vaultDir" -ForegroundColor Yellow
Write-Host "- Place QR code images in: $imagesDir" -ForegroundColor Yellow
Write-Host ""
Write-Host "IMPORT/EXPORT FUNCTIONALITY:" -ForegroundColor Cyan
Write-Host "- Export secrets: Use menu option 5" -ForegroundColor Cyan
Write-Host "- Import secrets: Use menu option 6" -ForegroundColor Cyan
Write-Host "- Exported files are saved to the vault_data directory" -ForegroundColor Cyan
Write-Host "- Import files from the images directory or specify full path" -ForegroundColor Cyan
Write-Host ""

# Run the container
docker run -it --rm `
    -v "${imagesDir}:/app/images" `
    -v "${vaultDir}:/home/truefa/.truefa" `
    -e "TRUEFA_PORTABLE=1" `
    -e "TRUEFA_DATA_DIR=/home/truefa/.truefa" `
    truefa-py

# Show completion message
Write-Host ""
Write-Host "Container execution completed." -ForegroundColor Green
Write-Host "Your vault data is saved in: $vaultDir" -ForegroundColor Green
