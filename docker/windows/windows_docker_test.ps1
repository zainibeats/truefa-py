# PowerShell script to test TrueFA-Py Rust implementation in a Windows Docker container
# This script specifically tests the Rust cryptography implementation for vault creation and persistence

# Set error action
$ErrorActionPreference = "Stop"

Write-Host "TrueFA-Py Windows Docker Test - Rust Implementation" -ForegroundColor Cyan
Write-Host "==================================" -ForegroundColor Cyan

# Get the script directory
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectRoot = Split-Path -Parent (Split-Path -Parent $scriptDir)

# Ensure Docker is in Windows container mode
Write-Host "Checking Docker configuration..." -ForegroundColor Cyan
$dockerInfo = docker info
if ($dockerInfo -match "OSType:\s+linux") {
    Write-Host "Switching Docker to Windows container mode..." -ForegroundColor Yellow
    Write-Host "Please run: 'Start-Process -WindowStyle Hidden -FilePath 'C:\Program Files\Docker\Docker\DockerCli.exe' -ArgumentList '-SwitchWindowsEngine'" -ForegroundColor Red
    Write-Host "Then run this script again after Docker has fully switched to Windows containers." -ForegroundColor Red
    exit 1
}

# Check if the Rust DLL exists
$dllPath = Join-Path $projectRoot "rust_crypto\target\release\truefa_crypto.dll"
if (-not (Test-Path $dllPath)) {
    Write-Host "Rust DLL not found at $dllPath" -ForegroundColor Yellow
    Write-Host "Building Rust DLL..." -ForegroundColor Cyan
    
    # Build the Rust DLL
    Push-Location (Join-Path $projectRoot "rust_crypto")
    cargo build --release --features="export_all_symbols"
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Failed to build Rust DLL! Using pre-built DLL if available." -ForegroundColor Red
        # Continue with the test, but the Docker container will need a pre-built DLL
    } else {
        Write-Host "Rust DLL built successfully!" -ForegroundColor Green
    }
    Pop-Location
}

# Clean up any existing test containers and volumes
Write-Host "Cleaning up any existing test containers and volumes..." -ForegroundColor Yellow
docker container ls -a -q -f "name=truefa-test-*" | ForEach-Object { docker container rm $_ -f }
docker volume rm truefa-test-vault -f 2>$null
docker volume rm truefa-test-images -f 2>$null

# Create persistent volumes
Write-Host "Creating persistent volumes..." -ForegroundColor Green
docker volume create truefa-test-vault
docker volume create truefa-test-images

# Build the Docker image
Write-Host "Building Windows test Docker image for Rust testing..." -ForegroundColor Green
$dockerfilePath = Join-Path $scriptDir "Dockerfile.windows"
Set-Location $projectRoot
docker build -t truefa-py-windows-test -f $dockerfilePath .

if ($LASTEXITCODE -ne 0) {
    Write-Host "Error: Docker build failed with exit code $LASTEXITCODE" -ForegroundColor Red
    exit 1
}

Write-Host "Docker image built successfully!" -ForegroundColor Green

# Run the test container
Write-Host "Running test container with Rust implementation..." -ForegroundColor Green
docker run --name truefa-test-run `
    -v truefa-test-vault:C:/data/.truefa `
    -v truefa-test-images:C:/data/images `
    -e TRUEFA_USE_FALLBACK=0 `
    -e TRUEFA_DEBUG_CRYPTO=1 `
    --rm truefa-py-windows-test

# Check the result
if ($LASTEXITCODE -ne 0) {
    Write-Host "Test failed with exit code $LASTEXITCODE" -ForegroundColor Red
    
    # Run again with fallback enabled for comparison
    Write-Host "Retrying with Python fallback enabled for comparison..." -ForegroundColor Yellow
    docker run --name truefa-test-fallback `
        -v truefa-test-vault:C:/data/.truefa `
        -v truefa-test-images:C:/data/images `
        -e TRUEFA_USE_FALLBACK=1 `
        -e TRUEFA_DEBUG_CRYPTO=1 `
        --rm truefa-py-windows-test
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Python fallback test passed but Rust implementation failed." -ForegroundColor Yellow
        Write-Host "This confirms there's an issue specifically with the Rust implementation on Windows." -ForegroundColor Yellow
    } else {
        Write-Host "Both Rust and Python fallback tests failed." -ForegroundColor Red
    }
    
    # Clean up volumes on failure
    Write-Host "Cleaning up test volumes..." -ForegroundColor Yellow
    docker volume rm truefa-test-vault -f
    docker volume rm truefa-test-images -f
    
    exit 1
} else {
    Write-Host "Rust implementation test completed successfully!" -ForegroundColor Green
    
    # Keep volumes for inspection if needed
    Write-Host "Test volumes 'truefa-test-vault' and 'truefa-test-images' are preserved for inspection." -ForegroundColor Cyan
    Write-Host "Run 'docker volume rm truefa-test-vault truefa-test-images' to clean up." -ForegroundColor Cyan
    
    exit 0
} 