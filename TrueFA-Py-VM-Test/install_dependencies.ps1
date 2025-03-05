# TrueFA-Py Dependency Installer
# This script installs required dependencies for TrueFA-Py to run properly on Windows

Write-Host "TrueFA-Py Dependency Installer" -ForegroundColor Green
Write-Host "=============================" -ForegroundColor Green
Write-Host ""

# Check if running as administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "This script requires administrator privileges to install system dependencies." -ForegroundColor Red
    Write-Host "Please run this script as an administrator." -ForegroundColor Red
    Write-Host ""
    Write-Host "Press any key to exit..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    exit
}

# Function to check if a specific Visual C++ Redistributable is installed
function Test-VCRedist {
    param (
        [string]$DisplayNamePattern
    )
    
    $vcRedist = Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -like $DisplayNamePattern }
    return $null -ne $vcRedist
}

# Function to install Visual C++ Redistributable
function Install-VCRedist {
    $tempFile = Join-Path $env:TEMP "vc_redist.x64.exe"
    Write-Host "Downloading Visual C++ Redistributable 2015-2022..." -ForegroundColor Cyan
    
    try {
        Invoke-WebRequest -Uri "https://aka.ms/vs/17/release/vc_redist.x64.exe" -OutFile $tempFile
        
        Write-Host "Installing Visual C++ Redistributable 2015-2022..." -ForegroundColor Cyan
        $process = Start-Process -FilePath $tempFile -ArgumentList "/quiet", "/norestart" -Wait -PassThru
        
        if ($process.ExitCode -eq 0) {
            Write-Host "[SUCCESS] Visual C++ Redistributable installed successfully" -ForegroundColor Green
        } else {
            Write-Host "[WARN] Visual C++ Redistributable installer returned exit code: $($process.ExitCode)" -ForegroundColor Yellow
            Write-Host "       The installation might not have been completed successfully" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "[ERROR] Failed to download or install Visual C++ Redistributable" -ForegroundColor Red
    } finally {
        # Clean up
        if (Test-Path $tempFile) {
            Remove-Item $tempFile -Force
        }
    }
}

# Function to check and install Python 3.10 embeddable package if needed
function Install-PythonEmbeddable {
    $pythonEmbedDir = Join-Path (Get-Location) "python-embed"
    $pythonZip = Join-Path $env:TEMP "python310.zip"
    
    if (Test-Path $pythonEmbedDir) {
        Write-Host "Python embeddable package already exists at: $pythonEmbedDir" -ForegroundColor Cyan
        return
    }
    
    Write-Host "Downloading Python 3.10 embeddable package..." -ForegroundColor Cyan
    
    try {
        # Download Python 3.10 embeddable package
        Invoke-WebRequest -Uri "https://www.python.org/ftp/python/3.10.11/python-3.10.11-embed-amd64.zip" -OutFile $pythonZip
        
        # Create directory and extract
        New-Item -Path $pythonEmbedDir -ItemType Directory -Force | Out-Null
        Expand-Archive -Path $pythonZip -DestinationPath $pythonEmbedDir -Force
        
        Write-Host "[SUCCESS] Python 3.10 embeddable package installed to: $pythonEmbedDir" -ForegroundColor Green
        
        # Create a README file to explain what this is
        @"
This directory contains a Python 3.10 embeddable package that's required for TrueFA-Py to run properly.
It provides necessary DLLs like python310.dll that the application depends on.

DO NOT DELETE THIS DIRECTORY if you want TrueFA-Py to work.
"@ | Out-File -FilePath (Join-Path $pythonEmbedDir "README.txt") -Encoding UTF8
        
    } catch {
        Write-Host "[ERROR] Failed to download or extract Python embeddable package" -ForegroundColor Red
    } finally {
        # Clean up
        if (Test-Path $pythonZip) {
            Remove-Item $pythonZip -Force
        }
    }
}

# Function to copy required DLLs if needed
function Copy-RequiredDLLs {
    $distDir = Join-Path (Get-Location) "dist"
    $pythonEmbedDir = Join-Path (Get-Location) "python-embed"
    
    if (-not (Test-Path $pythonEmbedDir)) {
        Write-Host "[ERROR] Python embeddable package not found. Please install it first." -ForegroundColor Red
        return
    }
    
    if (-not (Test-Path $distDir)) {
        Write-Host "[ERROR] Distribution directory not found. Please build the application first." -ForegroundColor Red
        return
    }
    
    Write-Host "Copying required DLLs to distribution directory..." -ForegroundColor Cyan
    
    # List of DLLs to copy
    $dllsToCopy = @(
        "python310.dll",
        "pythoncom310.dll",
        "pywintypes310.dll"
    )
    
    foreach ($dll in $dllsToCopy) {
        $sourcePath = Join-Path $pythonEmbedDir $dll
        $destPath = Join-Path $distDir $dll
        
        if (Test-Path $sourcePath) {
            try {
                Copy-Item -Path $sourcePath -Destination $destPath -Force
                Write-Host "  [SUCCESS] Copied $dll to distribution directory" -ForegroundColor Green
            } catch {
                Write-Host "  [ERROR] Failed to copy $dll" -ForegroundColor Red
            }
        } else {
            Write-Host "  [WARN] Could not find $dll in Python embeddable package" -ForegroundColor Yellow
        }
    }
}

# Start of main script
Write-Host "Checking for Visual C++ Redistributable 2015-2022..." -ForegroundColor Cyan
$vc2015to2022 = Test-VCRedist -DisplayNamePattern "*Microsoft Visual C++ 201* Redistributable*"

if ($vc2015to2022) {
    Write-Host "[PASS] Visual C++ Redistributable 2015-2022 is already installed" -ForegroundColor Green
} else {
    $installVC = Read-Host "Visual C++ Redistributable 2015-2022 is not installed. Do you want to install it now? (y/n)"
    if ($installVC -eq 'y') {
        Install-VCRedist
    } else {
        Write-Host "[WARN] Skipping Visual C++ Redistributable installation" -ForegroundColor Yellow
        Write-Host "       TrueFA-Py may not run without this dependency" -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "Checking for Python 3.10 embeddable package..." -ForegroundColor Cyan
$installPython = Read-Host "Would you like to download the Python 3.10 embeddable package for required DLLs? (y/n)"

if ($installPython -eq 'y') {
    Install-PythonEmbeddable
    
    # Ask to copy DLLs
    $copyDlls = Read-Host "Would you like to copy required Python DLLs to the distribution directory? (y/n)"
    if ($copyDlls -eq 'y') {
        Copy-RequiredDLLs
    }
} else {
    Write-Host "[WARN] Skipping Python 3.10 embeddable package installation" -ForegroundColor Yellow
    Write-Host "       TrueFA-Py may not run properly if python310.dll is missing" -ForegroundColor Yellow
}

# Create a .bat file launcher that sets PATH to include the python-embed directory
Write-Host ""
Write-Host "Creating launcher script..." -ForegroundColor Cyan
$launcherContent = @"
@echo off
REM TrueFA-Py Launcher
REM This script ensures proper DLL paths are set before launching the application

echo Starting TrueFA-Py...

REM Add python-embed directory to PATH temporarily
set "PATH=%~dp0python-embed;%PATH%"

REM Launch the application
start "" "%~dp0dist\TrueFA-Py.exe"
"@

$launcherPath = Join-Path (Get-Location) "TrueFA-Py-Launcher.bat"
$launcherContent | Out-File -FilePath $launcherPath -Encoding ASCII

Write-Host "[SUCCESS] Created launcher script at: $launcherPath" -ForegroundColor Green
Write-Host "          Use this launcher to ensure all dependencies are available" -ForegroundColor Green

Write-Host ""
Write-Host "Dependency Installation Complete" -ForegroundColor Green
Write-Host "===============================" -ForegroundColor Green
Write-Host ""
Write-Host "To launch TrueFA-Py with all dependencies, use:" -ForegroundColor Cyan
Write-Host "  TrueFA-Py-Launcher.bat" -ForegroundColor Cyan
Write-Host ""

# Ask to run the launcher
$runLauncher = Read-Host "Would you like to run TrueFA-Py now using the launcher? (y/n)"
if ($runLauncher -eq 'y') {
    Write-Host "Starting TrueFA-Py with the launcher..." -ForegroundColor Cyan
    & $launcherPath
}

# Keep console open
Write-Host "Press any key to exit..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
