# TrueFA Build Script for Windows
# This is a simplified build script that calls the Python build process
# It includes support for various build options: portable, installer, no-console, fallback, etc.

[CmdletBinding()]
param (
    [Parameter(Mandatory=$false)]
    [switch]$Portable,
    
    [Parameter(Mandatory=$false)]
    [switch]$Installer,
    
    [Parameter(Mandatory=$false)]
    [switch]$NoConsole,
    
    [Parameter(Mandatory=$false)]
    [switch]$Fallback,
    
    [Parameter(Mandatory=$false)]
    [switch]$BuildRust,
    
    [Parameter(Mandatory=$false)]
    [switch]$Clean
)

# Set the error action preference
$ErrorActionPreference = "Stop"

Write-Host "=================================================="
Write-Host "  TrueFA Build Script"
Write-Host "=================================================="

# Clean build artifacts if requested
if ($Clean) {
    Write-Host "Cleaning build artifacts..."
    if (Test-Path "build") { Remove-Item -Recurse -Force "build" }
    if (Test-Path "dist") { Remove-Item -Recurse -Force "dist" }
}

# Build Rust backend if requested
if ($BuildRust) {
    Write-Host "Building Rust cryptography backend..."
    python "$PSScriptRoot\build_rust.py"
}

# Construct build command
$buildCmd = "python $PSScriptRoot\build_package.py"

if ($Portable) { $buildCmd += " --portable" }
if ($Installer) { $buildCmd += " --installer" }
if ($NoConsole) { $buildCmd += " --no-console" }
if ($Fallback) { $buildCmd += " --fallback" }

# Run the build command
Write-Host "Building TrueFA with command: $buildCmd"
Invoke-Expression $buildCmd

Write-Host "=================================================="
Write-Host "  Build process completed!"
Write-Host "==================================================" 
