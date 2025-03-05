# TrueFA-Py - Prepare VM Testing Package
# This script prepares a complete package for testing on a fresh Windows VM

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

Write-Host "TrueFA-Py VM Test Package Preparation" -ForegroundColor Cyan
Write-Host "======================================" -ForegroundColor Cyan
Write-Host ""

# Prepare timestamp for package
$timestamp = Get-Date -Format "yyyyMMdd"
$packageName = "TrueFA-Py-VM-Test-$timestamp"
$packageDir = ".\$packageName"

# Clean up previous builds
Write-Host "Cleaning old build artifacts..." -ForegroundColor Yellow
if (Test-Path ".\build") { Remove-Item -Path ".\build" -Recurse -Force -ErrorAction SilentlyContinue }
if (Test-Path ".\dist") { Remove-Item -Path ".\dist" -Recurse -Force -ErrorAction SilentlyContinue }
if (Test-Path $packageDir) { Remove-Item -Path $packageDir -Recurse -Force -ErrorAction SilentlyContinue }

# Building the executable
Write-Host "Building TrueFA-Py console executable..." -ForegroundColor Yellow
$pyinstallerArgs = @(
    "--clean",
    "--onefile",
    "--console",
    "--icon=assets\truefa.ico",
    "--add-data=assets;assets",
    "--name=TrueFA-Py",
    "main.py"
)
python -m PyInstaller $pyinstallerArgs

if (-not (Test-Path ".\dist\TrueFA-Py.exe")) {
    Write-Host "Error: Build failed - executable not found!" -ForegroundColor Red
    exit 1
}

# Create package directory structure
Write-Host "Creating package directory structure..." -ForegroundColor Yellow
New-Item -Path $packageDir -ItemType Directory -Force | Out-Null
New-Item -Path "$packageDir\images" -ItemType Directory -Force | Out-Null
New-Item -Path "$packageDir\dependencies" -ItemType Directory -Force | Out-Null

# Copy executable and assets
Copy-Item -Path ".\dist\TrueFA-Py.exe" -Destination $packageDir -Force
Copy-Item -Path ".\assets" -Destination $packageDir -Recurse -Force

# Copy test QR code
if (Test-Path ".\assets\test\test_qr.png") {
    Copy-Item -Path ".\assets\test\test_qr.png" -Destination "$packageDir\images" -Force
} else {
    # Create dummy image if test QR doesn't exist
    $qrContent = @"
<svg xmlns="http://www.w3.org/2000/svg" width="200" height="200" viewBox="0 0 200 200">
  <rect width="200" height="200" fill="white"/>
  <text x="40" y="100" font-family="Arial" font-size="12">Test QR Code</text>
  <text x="40" y="120" font-family="Arial" font-size="12">Secret: TESTINGKEY123456</text>
</svg>
"@
    Set-Content -Path "$packageDir\images\test_qr.svg" -Value $qrContent
}

# Create a launcher script
$batchContent = @"
@echo off
echo TrueFA-Py Launcher
echo =================
echo.

:: Check for dependencies
if not exist "%~dp0dependencies\VC_redist.x64.exe" (
    echo Warning: Visual C++ Redistributable installer not found.
    echo Please run setup.bat first to install dependencies.
    echo.
    pause
)

:: Set environment for portable operation
set TRUEFA_PORTABLE=1
set TRUEFA_HOME=%~dp0data

:: Run the application
"%~dp0TrueFA-Py.exe"

:: Reset environment
set TRUEFA_PORTABLE=
set TRUEFA_HOME=

echo.
pause
"@
Set-Content -Path "$packageDir\TrueFA-Py.bat" -Value $batchContent

# Create setup script for dependencies
$setupContent = @"
@echo off
echo TrueFA-Py Setup
echo ==============
echo.
echo This script will install the required dependencies for TrueFA-Py.
echo.

:: Check if running with admin privileges
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Please run this script as Administrator.
    echo Right-click on setup.bat and select "Run as administrator".
    echo.
    pause
    exit /b 1
)

echo Installing Visual C++ Redistributable...
echo.
start /wait "%~dp0dependencies\VC_redist.x64.exe" /install /quiet /norestart

echo.
echo Setup complete!
echo You can now run TrueFA-Py.bat to start the application.
echo.
pause
"@
Set-Content -Path "$packageDir\setup.bat" -Value $setupContent

# Download Visual C++ Redistributable
Write-Host "Downloading Visual C++ Redistributable..." -ForegroundColor Yellow
$vcRedistUrl = "https://aka.ms/vs/17/release/vc_redist.x64.exe"
$vcRedistPath = "$packageDir\dependencies\VC_redist.x64.exe"
try {
    Invoke-WebRequest -Uri $vcRedistUrl -OutFile $vcRedistPath
    Write-Host "Visual C++ Redistributable downloaded successfully." -ForegroundColor Green
} catch {
    Write-Host "Warning: Failed to download Visual C++ Redistributable." -ForegroundColor Yellow
    Write-Host "URL: $vcRedistUrl" -ForegroundColor Yellow
    Write-Host "Error: $_" -ForegroundColor Yellow
}

# Create compatibility check script
$checkScript = @"
param (
    [switch]`$Silent
)

`$isCompatible = `$true
`$issues = @()

function Write-Status {
    param (
        [string]`$Message,
        [string]`$Status,
        [string]`$Color
    )
    
    if (-not `$Silent) {
        Write-Host `$Message -NoNewline
        Write-Host `$Status -ForegroundColor `$Color
    }
}

# Check Windows version
`$osInfo = Get-CimInstance Win32_OperatingSystem
`$windowsVersion = [System.Environment]::OSVersion.Version
`$minVersion = [System.Version]::new(10, 0, 0, 0)

if (`$windowsVersion -lt `$minVersion) {
    `$isCompatible = `$false
    `$issues += "Windows version must be Windows 10 or newer."
    Write-Status "Windows version... " "FAILED" "Red"
} else {
    Write-Status "Windows version... " "OK" "Green"
}

# Check for Visual C++ Redistributable
`$vcRedistName = "Microsoft Visual C++ 2015-2022 Redistributable (x64)"
`$vcRegPath = "HKLM:\\SOFTWARE\\Microsoft\\VisualStudio\\14.0\\VC\\Runtimes\\X64"
`$vcRedistInstalled = (Test-Path `$vcRegPath) -and ((Get-ItemProperty `$vcRegPath).Installed -eq 1)

if (-not `$vcRedistInstalled) {
    `$isCompatible = `$false
    `$issues += "Visual C++ Redistributable not found. Run setup.bat to install it."
    Write-Status "Visual C++ Redistributable... " "MISSING" "Yellow"
} else {
    Write-Status "Visual C++ Redistributable... " "OK" "Green"
}

# Check filesystem permissions
`$testDir = Join-Path ([System.IO.Path]::GetTempPath()) "TrueFA-Test"
`$testFile = Join-Path `$testDir "test.txt"
try {
    if (-not (Test-Path `$testDir)) {
        New-Item -Path `$testDir -ItemType Directory -Force | Out-Null
    }
    Set-Content -Path `$testFile -Value "Test" -ErrorAction Stop
    Remove-Item -Path `$testFile -Force -ErrorAction SilentlyContinue
    Write-Status "Filesystem permissions... " "OK" "Green"
} catch {
    `$isCompatible = `$false
    `$issues += "Cannot write to temporary directory. Application may not work correctly."
    Write-Status "Filesystem permissions... " "FAILED" "Red"
}

# Check admin privileges
`$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not `$isAdmin) {
    Write-Status "Admin privileges... " "NOT ADMIN" "Yellow"
} else {
    Write-Status "Admin privileges... " "ADMIN" "Green"
}

# Output summary
if (`$isCompatible) {
    if (-not `$Silent) {
        Write-Host "`nSystem is compatible with TrueFA-Py." -ForegroundColor Green
    }
    return 0
} else {
    if (-not `$Silent) {
        Write-Host "`nSystem is NOT fully compatible with TrueFA-Py:" -ForegroundColor Red
        foreach (`$issue in `$issues) {
            Write-Host "- `$issue" -ForegroundColor Red
        }
    }
    return 1
}
"@
Set-Content -Path "$packageDir\windows_compatibility_check.ps1" -Value $checkScript

# Create a README file
$readmeContent = @"
# TrueFA-Py Test Package

This package contains everything needed to test TrueFA-Py on a fresh Windows installation.

## Installation

1. Run `setup.bat` as Administrator to install dependencies
2. Run `TrueFA-Py.bat` to start the application

## Testing

1. Create a new vault with a master password
2. Add a TOTP secret manually or use the test QR code in the `images` folder
   - Test QR Code Secret: TESTINGKEY123456
3. Generate TOTP codes
4. Save and reload your vault

## Compatibility

Windows 10 or newer is required. Run `windows_compatibility_check.ps1` to check
if your system meets all the requirements:

```
powershell -ExecutionPolicy Bypass -File windows_compatibility_check.ps1
```

## Reporting Issues

When reporting issues, please include:
- Windows version and build number
- Error messages (if any)
- Steps to reproduce the issue
- Screenshots if possible

## Known Issues

- If you encounter "DLL not found" errors, make sure you've run setup.bat
- Admin privileges might be required for first-time setup
"@
Set-Content -Path "$packageDir\README.md" -Value $readmeContent

# Create ZIP package
Write-Host "Creating ZIP package..." -ForegroundColor Yellow
$zipPath = ".\$packageName.zip"
if (Test-Path $zipPath) { Remove-Item -Path $zipPath -Force }

Add-Type -AssemblyName System.IO.Compression.FileSystem
[System.IO.Compression.ZipFile]::CreateFromDirectory($packageDir, $zipPath)

# Clean up package directory
Remove-Item -Path $packageDir -Recurse -Force

Write-Host "`nVM test package created successfully:" -ForegroundColor Green
Write-Host $zipPath -ForegroundColor Green
Write-Host "`nThis package contains everything needed to test TrueFA-Py on a fresh Windows VM." -ForegroundColor Green
