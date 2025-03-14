# TrueFA-Py Docker Runner (Ephemeral Mode)
# This script builds and runs the TrueFA-Py Docker container with temporary storage

# Display header
Write-Host "TrueFA-Py Docker Runner (Ephemeral Mode)" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "WARNING: In this mode, your vault data will NOT be saved after the container exits!" -ForegroundColor Yellow
Write-Host "Use run_docker_persistent.ps1 for persistent storage." -ForegroundColor Yellow
Write-Host ""

# Ensure we're in the correct directory (repository root)
$repoRoot = $PSScriptRoot | Split-Path -Parent
Set-Location $repoRoot

# Create local images directory if it doesn't exist
$imagesDir = Join-Path $repoRoot "images"
if (-not (Test-Path $imagesDir)) {
    Write-Host "Creating images directory: $imagesDir" -ForegroundColor Yellow
    New-Item -ItemType Directory -Path $imagesDir | Out-Null
}

# Build the Docker image
Write-Host "Building Docker image..." -ForegroundColor Green
docker build -t truefa-py -f docker/Dockerfile .

# Check if the build was successful
if ($LASTEXITCODE -ne 0) {
    Write-Host "Docker build failed with exit code $LASTEXITCODE" -ForegroundColor Red
    exit $LASTEXITCODE
}

# Run the container
Write-Host "Running container (ephemeral mode)..." -ForegroundColor Green
Write-Host "- Vault data will be LOST when the container exits" -ForegroundColor Red
Write-Host "- Place QR code images in: $imagesDir" -ForegroundColor Yellow
Write-Host ""
Write-Host "IMPORT/EXPORT FUNCTIONALITY:" -ForegroundColor Cyan
Write-Host "- Export secrets: Use menu option 5" -ForegroundColor Cyan
Write-Host "- Import secrets: Use menu option 6" -ForegroundColor Cyan
Write-Host "- Exported files will be LOST when the container exits" -ForegroundColor Red
Write-Host "- Import files from the images directory or specify full path" -ForegroundColor Cyan
Write-Host ""

# Run the container
docker run -it --rm `
    -v "${imagesDir}:/app/images" `
    -e "TRUEFA_PORTABLE=1" `
    -e "TRUEFA_DATA_DIR=/app/local_vault" `
    truefa-py

# Show completion message
Write-Host ""
Write-Host "Container execution completed. All vault data is lost." -ForegroundColor Yellow