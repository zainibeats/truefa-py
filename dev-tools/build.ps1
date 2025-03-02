# TrueFA Build Script for Windows
# This script builds TrueFA application packages

[CmdletBinding()]
param (
    [Parameter(Mandatory=$false)]
    [switch]$Portable,
    
    [Parameter(Mandatory=$false)]
    [switch]$Installer,
    
    [Parameter(Mandatory=$false)]
    [switch]$Console,
    
    [Parameter(Mandatory=$false)]
    [switch]$Fallback,
    
    [Parameter(Mandatory=$false)]
    [switch]$BuildRust,
    
    [Parameter(Mandatory=$false)]
    [switch]$Clean
)

# Set the error action preference
$ErrorActionPreference = "Stop"

# Function to check if Python is installed
function Check-Python {
    try {
        $pythonVersion = python --version 2>&1
        Write-Host "✅ Found $pythonVersion"
        return $true
    }
    catch {
        Write-Host "❌ Python not found. Please install Python 3.10 or later."
        return $false
    }
}

# Function to check if Rust is installed
function Check-Rust {
    try {
        $rustVersion = rustc --version 2>&1
        Write-Host "✅ Found $rustVersion"
        return $true
    }
    catch {
        Write-Host "❌ Rust not found. Install from https://rustup.rs/ if you want to build the Rust cryptography backend."
        return $false
    }
}

# Function to create virtual environment
function Setup-VirtualEnvironment {
    if (-not (Test-Path "venv")) {
        Write-Host "📦 Creating virtual environment..."
        python -m venv venv
    }
    
    # Activate the virtual environment
    Write-Host "🔄 Activating virtual environment..."
    & .\venv\Scripts\Activate.ps1
    
    # Install requirements
    Write-Host "📦 Installing requirements..."
    pip install -r requirements.txt
    
    # Install PyInstaller if not already installed
    if (-not (pip show pyinstaller)) {
        Write-Host "📦 Installing PyInstaller..."
        pip install pyinstaller
    }
    
    return $true
}

# Function to build Rust cryptography backend
function Build-RustBackend {
    Write-Host "🔨 Building Rust cryptography backend..."
    python secure_build_fix.py
    
    # Check if the DLL was built successfully
    if (-not (Test-Path "src\truefa_crypto\truefa_crypto.dll")) {
        Write-Host "❌ Failed to build Rust cryptography backend."
        return $false
    }
    
    Write-Host "✅ Rust cryptography backend built successfully."
    return $true
}

# Function to clean build artifacts
function Clean-BuildArtifacts {
    Write-Host "🧹 Cleaning build artifacts..."
    
    # Remove Python build artifacts
    if (Test-Path "build") { Remove-Item -Recurse -Force "build" }
    if (Test-Path "dist") { Remove-Item -Recurse -Force "dist" }
    
    # Remove PyInstaller artifacts
    Get-ChildItem -Path "." -Filter "*.spec" | Where-Object { $_.Name -ne "truefa.spec" } | ForEach-Object {
        Remove-Item $_.FullName -Force
    }
    
    # Remove __pycache__ directories
    Get-ChildItem -Path "." -Filter "__pycache__" -Recurse | ForEach-Object {
        Remove-Item $_.FullName -Recurse -Force
    }
    
    Write-Host "✅ Build artifacts cleaned."
    return $true
}

# Main function
function Main {
    Write-Host "========================================================"
    Write-Host "  TrueFA Build Script"
    Write-Host "========================================================"
    
    # Check requirements
    if (-not (Check-Python)) { return 1 }
    
    # Clean build artifacts if requested
    if ($Clean) {
        if (-not (Clean-BuildArtifacts)) { return 1 }
    }
    
    # Setup virtual environment
    if (-not (Setup-VirtualEnvironment)) { return 1 }
    
    # Build Rust backend if requested or if BuildRust flag is set
    if ($BuildRust) {
        if (-not (Check-Rust)) { 
            Write-Host "⚠️ Cannot build Rust backend without Rust installed."
            $Fallback = $true
        }
        elseif (-not (Build-RustBackend)) {
            Write-Host "⚠️ Failed to build Rust backend, using fallback implementation."
            $Fallback = $true
        }
    }
    
    # Construct build command
    $buildCmd = "python build_package.py"
    
    if ($Portable) { $buildCmd += " --portable" }
    if ($Installer) { $buildCmd += " --installer" }
    if ($Console) { $buildCmd += " --console" }
    if ($Fallback) { $buildCmd += " --fallback" }
    
    # Run the build command
    Write-Host "🔨 Building TrueFA with command: $buildCmd"
    Invoke-Expression $buildCmd
    
    # Deactivate virtual environment
    deactivate
    
    Write-Host "========================================================"
    Write-Host "  Build process completed!"
    Write-Host "========================================================"
    
    return 0
}

# Run the main function
$exitCode = Main
exit $exitCode 