# PowerShell script to build and run TrueFA-Py in a Windows Docker container
# This script properly handles Windows containers for testing the application

# Ensure Docker is in Windows container mode
Write-Host "Checking Docker configuration..." -ForegroundColor Cyan
$dockerInfo = docker info
if ($dockerInfo -match "OSType:\s+linux") {
    Write-Host "Switching Docker to Windows container mode..." -ForegroundColor Yellow
    Write-Host "Please run: 'Start-Process -WindowStyle Hidden -FilePath 'C:\Program Files\Docker\Docker\DockerCli.exe' -ArgumentList '-SwitchWindowsEngine'" -ForegroundColor Red
    Write-Host "Then run this script again after Docker has fully switched to Windows containers." -ForegroundColor Red
    exit 1
}

# Check if Docker is installed and running
try {
    docker info | Out-Null
} catch {
    Write-Host "Error: Docker doesn't seem to be running. Please start Docker Desktop and try again." -ForegroundColor Red
    exit 1
}

# Create required directories
$imagesDir = Join-Path -Path (Get-Location).Path -ChildPath "images"
if (-not (Test-Path -Path $imagesDir)) {
    Write-Host "Creating images directory..." -ForegroundColor Yellow
    New-Item -Path $imagesDir -ItemType Directory | Out-Null
} else {
    Write-Host "Using existing images directory: $imagesDir" -ForegroundColor Cyan
}

# Ask if user wants to rebuild
$rebuild = $args -contains "-rebuild" -or $args -contains "--rebuild"
if (-not $rebuild) {
    $imageExists = docker images -q truefa-py-windows 2>$null
    if ($imageExists) {
        $rebuild = (Read-Host "Docker image 'truefa-py-windows' already exists. Rebuild? (y/n)") -eq 'y'
    } else {
        $rebuild = $true
    }
}

# Build the Docker image if needed
if ($rebuild) {
    Write-Host "Building Windows Docker image 'truefa-py-windows'..." -ForegroundColor Green
    docker build -t truefa-py-windows -f Dockerfile.windows .
    
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Error: Docker build failed with exit code $LASTEXITCODE" -ForegroundColor Red
        exit 1
    }
    
    Write-Host "Docker image 'truefa-py-windows' built successfully!" -ForegroundColor Green
}

# Run the container
Write-Host "Starting truefa-py-windows container..." -ForegroundColor Green
Write-Host "Press Ctrl+C to stop the container when done." -ForegroundColor Yellow
Write-Host "Any QR code images should be placed in: $imagesDir" -ForegroundColor Cyan

docker run -it --rm `
    -v "${imagesDir}:C:/app/images" `
    -e "TRUEFA_DEBUG=1" `
    -e "TRUEFA_USE_FALLBACK=1" `
    -e "TRUEFA_PORTABLE=1" `
    truefa-py-windows

if ($LASTEXITCODE -ne 0) {
    Write-Host "Container exited with code $LASTEXITCODE" -ForegroundColor Yellow
} else {
    Write-Host "Container exited successfully" -ForegroundColor Green
} 