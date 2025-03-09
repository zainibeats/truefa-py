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

# Check if Docker is running
try {
    $dockerStatus = & $dockerExe info 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: Docker is not running or not accessible. Please start Docker Desktop and try again." -ForegroundColor Red
        Write-Host "Docker error: $dockerStatus" -ForegroundColor Red
        exit 1
    }
} catch {
    Write-Host "ERROR: Failed to run Docker. Is Docker Desktop installed and in your PATH?" -ForegroundColor Red
    Write-Host "Exception: $_" -ForegroundColor Red
    exit 1
}

# Set to current directory
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location (Split-Path -Parent (Split-Path -Parent $scriptDir))

# Show banner
Write-Host "===== TrueFA-Py Windows Docker Test Environment =====" -ForegroundColor Green
Write-Host "Testing the TrueFA-Py portable executable and installer in a clean Windows container" -ForegroundColor Cyan
Write-Host

# Function to build Docker image
function Build-Image {
    Write-Host "Building Docker image '$imageName'..." -ForegroundColor Cyan
    
    # Remove existing image if it exists
    $imageExists = & $dockerExe images --filter "reference=$imageName" --format "{{.Repository}}"
    if ($imageExists -eq $imageName) {
        Write-Host "Removing existing image '$imageName'..." -ForegroundColor Yellow
        & $dockerExe rmi -f $imageName
    }
    
    & $dockerExe build -t $imageName -f docker/windows/Dockerfile .
    
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Failed to build Docker image. See error above." -ForegroundColor Red
        exit 1
    }
    
    Write-Host "Docker image '$imageName' built successfully." -ForegroundColor Green
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
    Write-Host "Starting Docker container '$containerName'..." -ForegroundColor Cyan
    
    # Check if container with this name already exists and remove it
    $containerExists = & $dockerExe ps -a --filter "name=$containerName" --format "{{.Names}}"
    if ($containerExists -eq $containerName) {
        Write-Host "Container '$containerName' already exists. Removing it..." -ForegroundColor Yellow
        & $dockerExe rm -f $containerName
    }
    
    # Run with explicit container name
    Write-Host "Running: docker run -it --name $containerName -v ${volumeName}:C:\vault_data $imageName" -ForegroundColor Gray
    & $dockerExe run -it --name $containerName -v ${volumeName}:C:\vault_data $imageName
    
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Failed to start Docker container. See error above." -ForegroundColor Red
        exit 1
    }
    
    # Verify container is running with the correct name
    $runningContainer = & $dockerExe ps --filter "name=$containerName" --format "{{.Names}}"
    if ($runningContainer -ne $containerName) {
        Write-Host "WARNING: Container '$containerName' is not running after startup." -ForegroundColor Yellow
        Write-Host "Container may have exited immediately. Check Docker logs for details:" -ForegroundColor Yellow
        Write-Host "docker logs $containerName" -ForegroundColor Gray
    } else {
        Write-Host "Container '$containerName' is running successfully." -ForegroundColor Green
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
        Write-Host "Removing container '$containerName'..." -ForegroundColor Yellow
        & $dockerExe rm -f $containerName
    } else {
        Write-Host "Container '$containerName' not found. Nothing to remove." -ForegroundColor Gray
    }
    
    # Remove volume if exists
    $volumeExists = & $dockerExe volume ls --filter "name=$volumeName" --format "{{.Name}}"
    if ($volumeExists -eq $volumeName) {
        Write-Host "Removing volume '$volumeName'..." -ForegroundColor Yellow
        & $dockerExe volume rm $volumeName
    } else {
        Write-Host "Volume '$volumeName' not found. Nothing to remove." -ForegroundColor Gray
    }
    
    # Remove image if exists
    $imageExists = & $dockerExe images --filter "reference=$imageName" --format "{{.Repository}}"
    if ($imageExists -eq $imageName) {
        Write-Host "Removing image '$imageName'..." -ForegroundColor Yellow
        & $dockerExe rmi -f $imageName
    } else {
        Write-Host "Image '$imageName' not found. Nothing to remove." -ForegroundColor Gray
    }
    
    Write-Host "Docker environment cleaned up successfully." -ForegroundColor Green
    Write-Host
}

# Function to show testing instructions
function Show-Instructions {
    Write-Host "===== TESTING INSTRUCTIONS =====" -ForegroundColor Yellow
    Write-Host
    Write-Host "PORTABLE EXECUTABLE TESTING:" -ForegroundColor Cyan
    Write-Host "1. Create a vault: TrueFA-Py.exe --create-vault --vault-dir C:\vault_data" 
    Write-Host "2. Enter a master password when prompted"
    Write-Host "3. Launch the app: TrueFA-Py.exe --vault-dir C:\vault_data"
    Write-Host "4. Follow the on-screen prompts to add and manage TOTP secrets"
    Write-Host
    Write-Host "INSTALLER TESTING:" -ForegroundColor Cyan
    Write-Host "1. Run the installer in silent mode: TrueFA-Py_Setup_0.1.0.exe /S"
    Write-Host "2. Wait for installation to complete (might take a few seconds)"
    Write-Host "3. Check common installation locations:"
    Write-Host "   - dir ""C:\Program Files\TrueFA-Py"""
    Write-Host "   - dir ""C:\Program Files (x86)\TrueFA-Py"""
    Write-Host "   - dir ""C:\Users\ContainerAdministrator\AppData\Local\Programs\TrueFA-Py"""
    Write-Host "4. Run the installed application from the found location"
    Write-Host "5. Test with custom vault location if needed"
    Write-Host
    Write-Host "UNINSTALLATION TESTING:" -ForegroundColor Cyan
    Write-Host "1. Find the uninstaller: dir ""C:\Program Files\TrueFA-Py\Uninstall.exe"""
    Write-Host "2. Run uninstaller in silent mode: ""C:\Program Files\TrueFA-Py\Uninstall.exe"" /S"
    Write-Host "3. Verify removal: dir ""C:\Program Files\TrueFA-Py"""
    Write-Host
    Write-Host "TESTING PERSISTENCE:" -ForegroundColor Cyan
    Write-Host "1. Exit the container"
    Write-Host "2. Run this script again with the -Resume parameter"
    Write-Host "3. Verify your vault and secrets are still available"
    Write-Host
    Write-Host "WHEN DONE TESTING:" -ForegroundColor Cyan
    Write-Host "Type 'exit' to close the container" 
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
