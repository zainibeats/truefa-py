# PowerShell script to test TrueFA-Py in a Windows Docker container
# This consolidated script supports testing both the Rust cryptography module and Python fallback

# Set error action
$ErrorActionPreference = "Stop"

Write-Host "TrueFA-Py Windows Docker Test" -ForegroundColor Cyan
Write-Host "==================================" -ForegroundColor Cyan

# Ensure Docker is in Windows container mode
Write-Host "Checking Docker configuration..." -ForegroundColor Cyan
$dockerInfo = docker info
if ($dockerInfo -match "OSType:\s+linux") {
    Write-Host "Switching Docker to Windows container mode..." -ForegroundColor Yellow
    Write-Host "Please run: 'Start-Process -WindowStyle Hidden -FilePath 'C:\Program Files\Docker\Docker\DockerCli.exe' -ArgumentList '-SwitchWindowsEngine'" -ForegroundColor Red
    Write-Host "Then run this script again after Docker has fully switched to Windows containers." -ForegroundColor Red
    exit 1
}

# Clean up any existing test containers
Write-Host "Cleaning up any existing test containers..." -ForegroundColor Yellow
docker container ls -a -q -f "name=truefa-test-*" | ForEach-Object { docker container rm $_ -f }

# Build the Docker image
Write-Host "Building Windows test Docker image..." -ForegroundColor Green
docker build -t truefa-py-windows-test -f Dockerfile.windows.test .

if ($LASTEXITCODE -ne 0) {
    Write-Host "Error: Docker build failed with exit code $LASTEXITCODE" -ForegroundColor Red
    exit 1
}

Write-Host "Docker image built successfully!" -ForegroundColor Green

# Check if we should run with Rust DLL
$rustMode = $false
if ($args.Contains("-rust")) {
    $rustMode = $true
    $testMode = "rust"
    
    # Check if DLL exists
    if (Test-Path "src\truefa_crypto\truefa_crypto.dll") {
        Write-Host "Creating container with Rust DLL..." -ForegroundColor Green
        docker create --name truefa-test-container truefa-py-windows-test
        
        # Copy the DLL into the container
        docker cp "src\truefa_crypto\truefa_crypto.dll" truefa-test-container:"/app/src/truefa_crypto/truefa_crypto.dll"
        
        # Commit the changes to a new image
        docker commit truefa-test-container truefa-py-windows-test-with-dll
        
        # Remove the temporary container
        docker rm truefa-test-container
        
        # Use the new image for testing
        $imageToUse = "truefa-py-windows-test-with-dll"
    } else {
        Write-Host "Rust DLL not found, running in fallback mode" -ForegroundColor Yellow
        $rustMode = $false
        $testMode = "fallback"
        $imageToUse = "truefa-py-windows-test"
    }
} else {
    $testMode = "fallback"
    $imageToUse = "truefa-py-windows-test"
}

# Run the test
Write-Host "Running test in Windows Docker container..." -ForegroundColor Green
Write-Host "Test mode: $testMode" -ForegroundColor Cyan

# Run the container
docker run --name truefa-test-run --rm -e "TRUEFA_TEST_MODE=$testMode" $imageToUse

# Check the result
if ($LASTEXITCODE -ne 0) {
    Write-Host "Test failed with exit code $LASTEXITCODE" -ForegroundColor Red
    exit 1
} else {
    Write-Host "Test completed successfully!" -ForegroundColor Green
    exit 0
} 