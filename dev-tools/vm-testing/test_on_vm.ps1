# TrueFA-Py VM Testing Script
# This script helps prepare a clean VM environment for testing TrueFA-Py on a fresh Windows installation

Write-Host "TrueFA-Py VM Testing Script" -ForegroundColor Green
Write-Host "===========================" -ForegroundColor Green
Write-Host ""

# Check if the VM Test package exists
$vmTestDir = Join-Path (Get-Location) "TrueFA-Py-VM-Test"
if (-not (Test-Path $vmTestDir)) {
    Write-Host "VM Test package not found at: $vmTestDir" -ForegroundColor Red
    Write-Host "Running prepare_vm_test.ps1 to create it..." -ForegroundColor Yellow
    
    # Run prepare_vm_test.ps1
    & powershell -ExecutionPolicy Bypass -File .\prepare_vm_test.ps1
    
    if (-not (Test-Path $vmTestDir)) {
        Write-Host "Failed to create VM Test package. Please check prepare_vm_test.ps1" -ForegroundColor Red
        exit 1
    }
}

# Copy our launcher to the VM test directory
$sourceLauncher = Join-Path (Get-Location) "TrueFA-Py-Launcher.bat"
$targetLauncher = Join-Path $vmTestDir "TrueFA-Py-Launcher.bat"
if (Test-Path $sourceLauncher) {
    Copy-Item -Path $sourceLauncher -Destination $targetLauncher -Force
    Write-Host "Copied launcher script to VM test package" -ForegroundColor Green
} else {
    Write-Host "Launcher script not found: $sourceLauncher" -ForegroundColor Red
    # Create a new launcher in the VM test directory
    $launcherContent = @"
@echo off
REM TrueFA-Py Enhanced Launcher
REM This script ensures proper DLL paths and environment are set before launching the application

echo TrueFA-Py Launcher
echo =================
echo.

REM Set portable mode to avoid permission issues
set "TRUEFA_PORTABLE=1"

REM Check if we have the python-embed directory
if exist "%~dp0python-embed" (
    echo Found Python Embed directory
    REM Add python-embed directory to PATH temporarily
    set "PATH=%~dp0python-embed;%PATH%"
) else (
    echo Python Embed directory not found
    echo This may cause the application to fail if Python DLLs are missing
)

REM Check for the truefa_crypto directory and DLL
if exist "%~dp0truefa_crypto\truefa_crypto.dll" (
    echo Found TrueFA Crypto DLL
    REM Add truefa_crypto directory to PATH
    set "PATH=%~dp0truefa_crypto;%PATH%"
) else (
    echo TrueFA Crypto DLL not found
    echo Using fallback Python crypto implementation
)

REM Check for the executable
if exist "%~dp0TrueFA-Py.exe" (
    echo Found TrueFA-Py executable
    echo Launching application...
    echo.
    
    REM Launch the application
    start "" "%~dp0TrueFA-Py.exe"
) else if exist "%~dp0TrueFA-Py_console.exe" (
    echo Found TrueFA-Py console executable
    echo Launching application...
    echo.
    
    REM Launch the console version
    start "" "%~dp0TrueFA-Py_console.exe"
) else (
    echo ERROR: Could not find TrueFA-Py executable
    echo Please make sure you have built the application
    pause
    exit /b 1
)

echo.
echo Application started. You can close this window.
timeout /t 10
"@
    Set-Content -Path $targetLauncher -Value $launcherContent
    Write-Host "Created new launcher script in VM test package" -ForegroundColor Green
}

# Copy the executable if it doesn't exist in the VM test directory
$exeSource = Join-Path (Get-Location) "dist\TrueFA-Py.exe"
$exeTarget = Join-Path $vmTestDir "TrueFA-Py.exe"
if (Test-Path $exeSource) {
    Copy-Item -Path $exeSource -Destination $exeTarget -Force
    Write-Host "Copied TrueFA-Py executable to VM test package" -ForegroundColor Green
} else {
    $exeConsoleSource = Join-Path (Get-Location) "dist\TrueFA-Py_console.exe"
    if (Test-Path $exeConsoleSource) {
        Copy-Item -Path $exeConsoleSource -Destination $exeTarget -Force
        Write-Host "Copied TrueFA-Py console executable to VM test package" -ForegroundColor Green
    } else {
        Write-Host "TrueFA-Py executable not found" -ForegroundColor Red
        Write-Host "Please build the application first" -ForegroundColor Red
    }
}

# Copy the Python embed directory if needed
$pythonEmbedSource = Join-Path (Get-Location) "python-embed"
$pythonEmbedTarget = Join-Path $vmTestDir "python-embed"
if (Test-Path $pythonEmbedSource) {
    if (-not (Test-Path $pythonEmbedTarget)) {
        Copy-Item -Path $pythonEmbedSource -Destination $pythonEmbedTarget -Recurse -Force
        Write-Host "Copied Python embed directory to VM test package" -ForegroundColor Green
    }
} else {
    Write-Host "Python embed directory not found" -ForegroundColor Yellow
    Write-Host "The application may not run properly without this" -ForegroundColor Yellow
}

# Verify test package contents
$requiredFiles = @(
    "TrueFA-Py.exe",
    "TrueFA-Py-Launcher.bat",
    "install_dependencies.ps1",
    "windows_compatibility_check.ps1",
    "README.md"
)

$missingFiles = @()
foreach ($file in $requiredFiles) {
    $filePath = Join-Path $vmTestDir $file
    if (-not (Test-Path $filePath)) {
        $missingFiles += $file
    }
}

if ($missingFiles.Count -gt 0) {
    Write-Host "The following required files are missing from the VM Test package:" -ForegroundColor Red
    foreach ($file in $missingFiles) {
        Write-Host "  - $file" -ForegroundColor Red
    }
    Write-Host "Please regenerate the VM Test package" -ForegroundColor Red
    exit 1
}

# Create a cleaner README guide for the VM test package
$readmePath = Join-Path $vmTestDir "README.md"
$readmeContent = @"
# TrueFA-Py Windows Testing Guide

## Overview
This package contains everything needed to test TrueFA-Py on a fresh Windows installation.

## Quick Start
1. Run `windows_compatibility_check.ps1` to verify your system meets the requirements
2. Run `install_dependencies.ps1` if any dependencies are missing
3. Launch the application using `TrueFA-Py-Launcher.bat`

## Testing Steps

### 1. System Compatibility Check
```
powershell -ExecutionPolicy Bypass -File .\windows_compatibility_check.ps1
```
This script will check if your system has all required components:
- Windows 10 or higher
- Visual C++ Redistributable 2015-2022
- Required DLLs

### 2. Install Dependencies (if needed)
```
powershell -ExecutionPolicy Bypass -File .\install_dependencies.ps1
```
This script will help you install missing dependencies:
- Visual C++ Redistributable 2015-2022
- Python 3.10 embeddable package for required DLLs

### 3. Launch TrueFA-Py
```
.\TrueFA-Py-Launcher.bat
```
The launcher ensures all dependencies are properly loaded.

### 4. Report Issues
If you encounter any issues, please document:
- Operating system version
- Steps to reproduce the issue
- Any error messages displayed
- Screenshots if applicable

## Common Issues and Solutions

### Application Crashes Immediately
- Try running with the launcher batch file instead of directly
- Make sure Visual C++ Redistributable is installed
- Check if Python DLLs are properly located

### Permission Issues
- The application may need to write to specific directories
- By default it uses the portable mode to store data locally

### Missing or Corrupt Files
- Redownload the test package
- Verify all files are present
"@

# Update the README in the VM Test package
Set-Content -Path $readmePath -Value $readmeContent

# Offer to run a local test
Write-Host "VM Test package is ready at: $vmTestDir" -ForegroundColor Green
Write-Host ""
Write-Host "You can now:" -ForegroundColor Cyan
Write-Host "1. Copy this entire folder to a fresh Windows VM for testing" -ForegroundColor Cyan
Write-Host "2. Run a local test using the compatibility check script" -ForegroundColor Cyan
Write-Host ""

$runTest = Read-Host "Would you like to run a local compatibility test? (y/n)"
if ($runTest -eq 'y') {
    # Check compatibility
    Write-Host "Running compatibility check..." -ForegroundColor Cyan
    & powershell -ExecutionPolicy Bypass -File .\windows_compatibility_check.ps1
}

# Check if the launcher exists
$launcherPath = Join-Path (Get-Location) "TrueFA-Py-Launcher.bat"
if (Test-Path $launcherPath) {
    $runLauncher = Read-Host "Would you like to run TrueFA-Py with the launcher? (y/n)"
    if ($runLauncher -eq 'y') {
        # Run the launcher
        Write-Host "Running TrueFA-Py with the launcher..." -ForegroundColor Cyan
        & cmd /c $launcherPath
    }
}

Write-Host ""
Write-Host "VM Testing Script Complete" -ForegroundColor Green
Write-Host "=======================" -ForegroundColor Green
