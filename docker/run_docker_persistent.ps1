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
    New-Item -ItemType Directory -Path $vaultDir | Out-Null
}

# Check required files for Docker build
$entrypointScript = Join-Path $repoRoot "docker\docker-entrypoint.sh"
if (-not (Test-Path $entrypointScript)) {
    Write-Host "ERROR: Docker entrypoint script not found at: $entrypointScript" -ForegroundColor Red
    Write-Host "Please ensure the docker-entrypoint.sh file exists in the docker directory" -ForegroundColor Red
    exit 1
}

# Build the Docker image with retry logic
Write-Host "Building Docker image..." -ForegroundColor Green
$buildSuccess = $false
$maxRetries = 2
$retryCount = 0

while (-not $buildSuccess -and $retryCount -lt $maxRetries) {
    docker build -t truefa-py -f docker/Dockerfile .
    
    if ($LASTEXITCODE -eq 0) {
        $buildSuccess = $true
        Write-Host "Docker build successful!" -ForegroundColor Green
    } else {
        $retryCount++
        if ($retryCount -lt $maxRetries) {
            Write-Host "Docker build failed, retrying (attempt $retryCount of $maxRetries)..." -ForegroundColor Yellow
        }
    }
}

# If build still fails, offer to run with fallback mode
if (-not $buildSuccess) {
    Write-Host "Docker build failed after $maxRetries attempts." -ForegroundColor Red
    $fallbackChoice = Read-Host "Would you like to run in Python fallback mode? (y/n)"
    
    if ($fallbackChoice -ne "y") {
        Write-Host "Exiting..." -ForegroundColor Red
        exit 1
    }
    
    Write-Host "Running in Python fallback mode..." -ForegroundColor Yellow
    $forceFallback = $true
} else {
    $forceFallback = $false
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

# Set up environment variables
$envParams = @(
    "-e", "TRUEFA_PORTABLE=1"
)

# Add fallback flag if needed
if ($forceFallback) {
    $envParams += "-e"
    $envParams += "TRUEFA_USE_FALLBACK=1"
    Write-Host "Using Python fallback implementation" -ForegroundColor Yellow
}

# Run the container with all the parameters
$params = @(
    "run", "-it", "--rm",
    "-v", "${imagesDir}:/app/images",
    "-v", "${vaultDir}:/home/truefa/.truefa"
)
$params += $envParams
$params += "truefa-py"

docker $params

# Show completion message
Write-Host ""
Write-Host "Container execution completed." -ForegroundColor Green
