# Simple testing script for TrueFA-Py in Docker

[CmdletBinding()]
param (
    [Parameter(Mandatory=$false)]
    [switch]$Clean,
    
    [Parameter(Mandatory=$false)]
    [switch]$Resume
)

$dockerPath = 'C:\Program Files\Docker\Docker\resources\bin\docker.exe'
$containerName = "truefa-test"
$imageName = "truefa-test"

# Banner
Write-Host "===== TrueFA Simple Testing Environment =====" -ForegroundColor Green
Write-Host

# Clean up existing containers if requested
if ($Clean) {
    Write-Host "Cleaning up previous test environment..." -ForegroundColor Cyan
    & $dockerPath rm -f $containerName 2>$null
    Write-Host "Cleanup completed." -ForegroundColor Green
    Write-Host
}

# Resume existing container if requested
if ($Resume) {
    Write-Host "Checking for existing container..." -ForegroundColor Cyan
    $containerExists = & $dockerPath ps -a --filter "name=$containerName" --format "{{.Names}}"
    
    if ($containerExists -eq $containerName) {
        Write-Host "Resuming existing container..." -ForegroundColor Green
        Write-Host "This will maintain your previously saved TrueFA data." -ForegroundColor Yellow
        Write-Host
        
        & $dockerPath start -i $containerName
        exit 0
    } else {
        Write-Host "No existing container found. Starting fresh..." -ForegroundColor Yellow
        Write-Host
    }
}

# Build Docker image and run container
Write-Host "Building Docker image..." -ForegroundColor Cyan
& $dockerPath build -t $imageName -f docker/windows/Dockerfile .

if ($LASTEXITCODE -ne 0) {
    Write-Host "Failed to build Docker image." -ForegroundColor Red
    exit 1
}

Write-Host "Docker image built successfully." -ForegroundColor Green
Write-Host

Write-Host "Starting Docker container..." -ForegroundColor Cyan
Write-Host "Inside the container, simply run 'TrueFA-Py.exe' to start the application." -ForegroundColor Yellow
Write-Host "Type 'exit' when done to leave the container." -ForegroundColor Yellow
Write-Host
Write-Host "To resume this container later (preserving your data), run:" -ForegroundColor Cyan
Write-Host ".\docker\windows\test-simple.ps1 -Resume" -ForegroundColor White
Write-Host

& $dockerPath run -it --name $containerName $imageName

Write-Host "Container session ended." -ForegroundColor Green
Write-Host "To resume testing with your saved data, run:" -ForegroundColor Cyan
Write-Host ".\docker\windows\test-simple.ps1 -Resume" -ForegroundColor White 