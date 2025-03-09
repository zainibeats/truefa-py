# TrueFA-Py Windows Docker Test Script
# This script builds and runs a Windows Docker container for testing the TrueFA-Py executable
# with support for persistent vault storage.

[CmdletBinding()]
param (
    [Parameter(Mandatory=$false)]
    [switch]$Clean,
    
    [Parameter(Mandatory=$false)]
    [switch]$Resume,
    
    [Parameter(Mandatory=$false)]
    [switch]$BuildImage
)

# Configuration
$containerName = "truefa-test"
$imageName = "truefa-windows-test"
$volumeName = "truefa-vault-data"
# Set Docker executable path - use full path since it might not be in PATH
$dockerExe = "C:\Program Files\Docker\Docker\resources\bin\docker.exe"

# Set to current directory
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location (Split-Path -Parent (Split-Path -Parent $scriptDir))

# Show banner
Write-Host "===== TrueFA-Py Windows Docker Test Environment =====" -ForegroundColor Green
Write-Host "Testing the TrueFA-Py executable in a clean Windows container" -ForegroundColor Cyan
Write-Host

# Function to build Docker image
function Build-Image {
    Write-Host "Building Docker image..." -ForegroundColor Cyan
    
    & $dockerExe build -t $imageName -f docker/windows/Dockerfile .
    
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Failed to build Docker image. See error above." -ForegroundColor Red
        exit 1
    }
    
    Write-Host "Docker image built successfully." -ForegroundColor Green
    Write-Host
}

# Function to create Docker volume
function Create-Volume {
    # Check if volume exists
    $volumeExists = & $dockerExe volume ls --filter "name=$volumeName" --format "{{.Name}}"
    
    if ($volumeExists -ne $volumeName) {
        Write-Host "Creating Docker volume for persistent vault data..." -ForegroundColor Cyan
        
        & $dockerExe volume create $volumeName
        
        if ($LASTEXITCODE -ne 0) {
            Write-Host "Failed to create Docker volume. See error above." -ForegroundColor Red
            exit 1
        }
        
        Write-Host "Docker volume created successfully." -ForegroundColor Green
        Write-Host
    } else {
        Write-Host "Using existing Docker volume for persistent vault data." -ForegroundColor Green
        Write-Host
    }
}

# Function to start container
function Start-Container {
    Write-Host "Starting Docker container..." -ForegroundColor Cyan
    
    & $dockerExe run -it --name $containerName -v ${volumeName}:C:\vault_data $imageName
    
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Failed to start Docker container. See error above." -ForegroundColor Red
        exit 1
    }
}

# Function to resume container
function Resume-Container {
    Write-Host "Resuming Docker container..." -ForegroundColor Cyan
    
    & $dockerExe start -i $containerName
    
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Failed to resume Docker container. See error above." -ForegroundColor Red
        exit 1
    }
}

# Function to check if container exists
function Check-Container {
    $containerExists = & $dockerExe ps -a --filter "name=$containerName" --format "{{.Names}}"
    return $containerExists -eq $containerName
}

# Function to clean up environment
function Clean-Environment {
    Write-Host "Cleaning up Docker environment..." -ForegroundColor Cyan
    
    # Remove container if exists
    $containerExists = & $dockerExe ps -a --filter "name=$containerName" --format "{{.Names}}"
    if ($containerExists -eq $containerName) {
        & $dockerExe rm -f $containerName
    }
    
    # Remove volume if exists
    $volumeExists = & $dockerExe volume ls --filter "name=$volumeName" --format "{{.Name}}"
    if ($volumeExists -eq $volumeName) {
        & $dockerExe volume rm $volumeName
    }
    
    Write-Host "Docker environment cleaned up successfully." -ForegroundColor Green
    Write-Host
}

# Function to show testing instructions
function Show-Instructions {
    Write-Host "===== TESTING INSTRUCTIONS =====" -ForegroundColor Yellow
    Write-Host
    Write-Host "FIRST TIME SETUP:" -ForegroundColor Cyan
    Write-Host "1. Create a vault: TrueFA-Py.exe --create-vault --vault-dir C:\vault_data" 
    Write-Host "2. Enter a master password when prompted"
    Write-Host
    Write-Host "TESTING PROCESS:" -ForegroundColor Cyan
    Write-Host "1. Launch the app: TrueFA-Py.exe --vault-dir C:\vault_data"
    Write-Host "2. Follow the on-screen prompts to add and manage TOTP secrets"
    Write-Host "3. Type 'exit' to close the container when finished"
    Write-Host
    Write-Host "TESTING PERSISTENCE:" -ForegroundColor Cyan
    Write-Host "1. Exit the container"
    Write-Host "2. Run this script again with the -Resume parameter"
    Write-Host "3. Verify your vault and secrets are still available"
    Write-Host
    Write-Host "==============================="-ForegroundColor Yellow
    Write-Host
}

# Main execution
if ($Clean) {
    Clean-Environment
}

if ($Resume) {
    if (Check-Container) {
        Show-Instructions
        Resume-Container
    } else {
        Write-Host "No existing container found. Starting fresh..." -ForegroundColor Yellow
        if ($BuildImage -or -not (& $dockerExe images $imageName -q)) {
            Build-Image
        }
        Create-Volume
        Show-Instructions
        Start-Container
    }
} else {
    if ($BuildImage -or -not (& $dockerExe images $imageName -q)) {
        Build-Image
    }
    Create-Volume
    Show-Instructions
    Start-Container
}

Write-Host "Test session complete." -ForegroundColor Green
