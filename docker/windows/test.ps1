# TrueFA Test Script for Windows
# This script helps test the TrueFA-Py executable in a clean Windows environment
# with support for persistent vault storage across container restarts.

[CmdletBinding()]
param (
    [Parameter(Mandatory=$false)]
    [switch]$Clean,
    
    [Parameter(Mandatory=$false)]
    [switch]$Resume,
    
    [Parameter(Mandatory=$false)]
    [switch]$BuildFirst
)

# Configuration
$containerName = "truefa-test"
$imageName = "truefa-test"
$volumeName = "truefa-vault-data"
$dockerPath = 'C:\Program Files\Docker\Docker\resources\bin\docker.exe'

# Set to current directory
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location (Split-Path -Parent (Split-Path -Parent $scriptDir))

# Show banner
Write-Host "===== TrueFA Testing Environment =====" -ForegroundColor Green
Write-Host "Testing the PyInstaller executable in a clean Windows container" -ForegroundColor Cyan
Write-Host

# Build TrueFA if requested
function Build-TrueFA {
    if ($BuildFirst) {
        Write-Host "Building TrueFA-Py executable..." -ForegroundColor Cyan
        
        # Check if dev-tools\build.ps1 exists
        if (Test-Path "dev-tools\build.ps1") {
            & "dev-tools\build.ps1" -Clean -Portable -BuildRust
            
            if ($LASTEXITCODE -ne 0) {
                Write-Host "Failed to build TrueFA-Py executable. See error above." -ForegroundColor Red
                exit 1
            }
            
            Write-Host "TrueFA-Py executable built successfully." -ForegroundColor Green
            Write-Host
        } else {
            Write-Host "Build script not found. Skipping build step." -ForegroundColor Yellow
            Write-Host
        }
    }
}

# Function to build Docker image
function Build-Image {
    Write-Host "Building Docker image..." -ForegroundColor Cyan
    
    & $dockerPath build -t $imageName -f docker/windows/Dockerfile .
    
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Failed to build Docker image. See error above." -ForegroundColor Red
        exit 1
    }
    
    Write-Host "Docker image built successfully." -ForegroundColor Green
    Write-Host
}

# Function to create Docker volume
function Create-Volume {
    Write-Host "Creating Docker volume for persistent vault data..." -ForegroundColor Cyan
    
    & $dockerPath volume create $volumeName
    
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Failed to create Docker volume. See error above." -ForegroundColor Red
        exit 1
    }
    
    Write-Host "Docker volume created successfully." -ForegroundColor Green
    Write-Host
}

# Function to start container
function Start-Container {
    Write-Host "Starting Docker container..." -ForegroundColor Cyan
    
    & $dockerPath run -it --name $containerName -v ${volumeName}:C:\vault_data $imageName
    
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Failed to start Docker container. See error above." -ForegroundColor Red
        exit 1
    }
}

# Function to resume container
function Resume-Container {
    Write-Host "Resuming Docker container..." -ForegroundColor Cyan
    
    & $dockerPath start -i $containerName
    
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Failed to resume Docker container. See error above." -ForegroundColor Red
        exit 1
    }
}

# Function to check if container exists
function Check-Container {
    $containerExists = & $dockerPath ps -a --filter "name=$containerName" --format "{{.Names}}"
    return $containerExists -eq $containerName
}

# Function to check if volume exists
function Check-Volume {
    $volumeExists = & $dockerPath volume ls --filter "name=$volumeName" --format "{{.Name}}"
    return $volumeExists -eq $volumeName
}

# Function to clean up environment
function Clean-Environment {
    Write-Host "Cleaning up Docker environment..." -ForegroundColor Cyan
    
    # Remove container if exists
    if (Check-Container) {
        & $dockerPath rm -f $containerName
    }
    
    # Remove volume if exists
    if (Check-Volume) {
        & $dockerPath volume rm $volumeName
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
    Write-Host "2. Enter a password when prompted (e.g., 'testpassword')"
    Write-Host
    Write-Host "TESTING PROCESS:" -ForegroundColor Cyan
    Write-Host "1. Launch the app: TrueFA-Py.exe --vault-dir C:\vault_data"
    Write-Host "2. Add secrets (option 1 or 2 from the menu)"
    Write-Host "3. Type 'exit' to close the container"
    Write-Host "4. Run the script with -Resume to test persistence"
    Write-Host "5. Launch the app again and verify secrets are still available"
    Write-Host
    Write-Host "TIPS:" -ForegroundColor Yellow
    Write-Host "- Use Ctrl+C to stop TOTP code generation"
    Write-Host "- Type 'exit' to stop the container"
    Write-Host
}

# Main execution
if ($Clean) {
    Clean-Environment
}

Build-TrueFA

if ($Resume) {
    if (Check-Container) {
        Show-Instructions
        Resume-Container
    } else {
        Write-Host "No existing container found. Starting fresh..." -ForegroundColor Yellow
        Build-Image
        Create-Volume
        Show-Instructions
        Start-Container
    }
} else {
    Build-Image
    Create-Volume
    Show-Instructions
    Start-Container
}

Write-Host "Test session complete. Thank you for testing!" -ForegroundColor Green 