# TrueFA-Py Windows Package Creator
# This script creates a standalone Windows package with all dependencies included

Write-Host "TrueFA-Py Windows Package Creator" -ForegroundColor Green
Write-Host "================================" -ForegroundColor Green
Write-Host ""

# Define directories
$scriptDir = Get-Location
$distDir = Join-Path $scriptDir "dist"
$packageDir = Join-Path $scriptDir "TrueFA-Py-Windows"
$pythonEmbedDir = Join-Path $scriptDir "python-embed"

# Check if required directories exist
if (-not (Test-Path $distDir)) {
    Write-Host "[ERROR] Distribution directory not found at: $distDir" -ForegroundColor Red
    Write-Host "         Please build the application first." -ForegroundColor Red
    Write-Host "Press any key to exit..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    exit
}

# Create package directory
Write-Host "Creating package directory: $packageDir" -ForegroundColor Cyan
if (Test-Path $packageDir) {
    Write-Host "Package directory already exists. Cleaning up..." -ForegroundColor Yellow
    Remove-Item -Path $packageDir -Recurse -Force
}
New-Item -Path $packageDir -ItemType Directory | Out-Null

# Download Python embeddable package if needed
if (-not (Test-Path $pythonEmbedDir)) {
    Write-Host "Downloading Python 3.10 embeddable package..." -ForegroundColor Cyan
    $pythonZip = Join-Path $env:TEMP "python310.zip"
    
    try {
        Invoke-WebRequest -Uri "https://www.python.org/ftp/python/3.10.11/python-3.10.11-embed-amd64.zip" -OutFile $pythonZip
        
        # Create directory and extract
        New-Item -Path $pythonEmbedDir -ItemType Directory -Force | Out-Null
        Expand-Archive -Path $pythonZip -DestinationPath $pythonEmbedDir -Force
        
        Write-Host "[SUCCESS] Python 3.10 embeddable package downloaded and extracted" -ForegroundColor Green
    } catch {
        Write-Host "[ERROR] Failed to download or extract Python embeddable package: $_" -ForegroundColor Red
        Write-Host "Press any key to exit..."
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        exit
    } finally {
        # Clean up
        if (Test-Path $pythonZip) {
            Remove-Item $pythonZip -Force
        }
    }
}

# Copy executable and relevant files
Write-Host "Copying executable and dependencies..." -ForegroundColor Cyan

# Create subdirectories
New-Item -Path (Join-Path $packageDir "dist") -ItemType Directory | Out-Null
New-Item -Path (Join-Path $packageDir "python-embed") -ItemType Directory | Out-Null

# Copy the executable
Copy-Item -Path (Join-Path $distDir "TrueFA-Py.exe") -Destination (Join-Path $packageDir "dist") -Force
Write-Host "  [SUCCESS] Copied TrueFA-Py.exe" -ForegroundColor Green

# Copy Python DLLs
$dllsToCopy = @(
    "python310.dll",
    "pythoncom310.dll", 
    "pywintypes310.dll",
    "*.dll", # Copy all DLLs to be safe
    "*.pyd"  # Copy Python extensions
)

foreach ($pattern in $dllsToCopy) {
    $files = Get-ChildItem -Path $pythonEmbedDir -Filter $pattern
    foreach ($file in $files) {
        Copy-Item -Path $file.FullName -Destination (Join-Path $packageDir "python-embed") -Force
        Write-Host "  [SUCCESS] Copied $($file.Name)" -ForegroundColor Green
    }
}

# Also copy the DLLs directly to the dist directory as a fallback
foreach ($pattern in $dllsToCopy) {
    $files = Get-ChildItem -Path $pythonEmbedDir -Filter $pattern
    foreach ($file in $files) {
        Copy-Item -Path $file.FullName -Destination (Join-Path $packageDir "dist") -Force
    }
}

# Download Visual C++ Redistributable installer
$vcRedistPath = Join-Path $packageDir "vc_redist.x64.exe"
Write-Host "Downloading Visual C++ Redistributable installer..." -ForegroundColor Cyan
try {
    Invoke-WebRequest -Uri "https://aka.ms/vs/17/release/vc_redist.x64.exe" -OutFile $vcRedistPath
    Write-Host "  [SUCCESS] Downloaded Visual C++ Redistributable installer" -ForegroundColor Green
} catch {
    Write-Host "  [ERROR] Failed to download Visual C++ Redistributable installer: $_" -ForegroundColor Red
    Write-Host "          The package will be created without it, but users will need to install it separately." -ForegroundColor Yellow
}

# Create launcher script
Write-Host "Creating launcher scripts..." -ForegroundColor Cyan
$launcherBat = @"
@echo off
REM TrueFA-Py Launcher
REM This script ensures proper DLL paths are set before launching the application

echo Starting TrueFA-Py...

REM Add python-embed directory to PATH temporarily
set "PATH=%~dp0python-embed;%PATH%"

REM Launch the application
start "" "%~dp0dist\TrueFA-Py.exe"
"@

$launcherPath = Join-Path $packageDir "TrueFA-Py.bat"
$launcherBat | Out-File -FilePath $launcherPath -Encoding ASCII
Write-Host "  [SUCCESS] Created launcher batch file" -ForegroundColor Green

# Create setup script
$setupBat = @"
@echo off
REM TrueFA-Py Setup
REM This script installs required dependencies

echo TrueFA-Py Windows Setup
echo =====================
echo.

echo Installing Visual C++ Redistributable (required)...
echo This may take a moment. A confirmation dialog may appear.
start /wait "" "%~dp0vc_redist.x64.exe" /quiet /norestart
if %ERRORLEVEL% EQU 0 (
    echo [SUCCESS] Visual C++ Redistributable installed successfully.
) else (
    echo [WARNING] Visual C++ Redistributable installation may have failed.
    echo           You may need to install it manually to run TrueFA-Py.
)

echo.
echo Setup complete! You can now run TrueFA-Py.bat to start the application.
echo.
pause
"@

$setupPath = Join-Path $packageDir "setup.bat"
$setupBat | Out-File -FilePath $setupPath -Encoding ASCII
Write-Host "  [SUCCESS] Created setup batch file" -ForegroundColor Green

# Create README
$readmeContent = @"
# TrueFA-Py for Windows

This package contains TrueFA-Py, a two-factor authentication vault system, optimized for Windows.

## Installation Instructions

1. Run `setup.bat` to install required dependencies.
2. After setup completes, run `TrueFA-Py.bat` to start the application.

## System Requirements

- Windows 10 or higher (64-bit)
- Visual C++ Redistributable 2015-2022 (installed by setup.bat)
- Approximately 100MB of disk space

## Troubleshooting

If the application doesn't start:

1. Make sure you've run `setup.bat` first
2. Try running the application directly from `dist\TrueFA-Py.exe`
3. If it still doesn't work, reinstall Visual C++ Redistributable manually:
   - Download from: https://aka.ms/vs/17/release/vc_redist.x64.exe

## Feedback and Support

If you encounter issues, please report them on the project's GitHub repository.
"@

$readmePath = Join-Path $packageDir "README.md"
$readmeContent | Out-File -FilePath $readmePath -Encoding UTF8
Write-Host "  [SUCCESS] Created README file" -ForegroundColor Green

# Create ZIP package
$timestamp = Get-Date -Format "yyyyMMdd"
$zipPath = Join-Path $scriptDir "TrueFA-Py-Windows-$timestamp.zip"
Write-Host "Creating ZIP package: $zipPath" -ForegroundColor Cyan

try {
    if (Test-Path $zipPath) {
        Remove-Item $zipPath -Force
    }
    
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::CreateFromDirectory($packageDir, $zipPath)
    
    Write-Host "[SUCCESS] Created ZIP package at: $zipPath" -ForegroundColor Green
} catch {
    Write-Host "[ERROR] Failed to create ZIP package: $_" -ForegroundColor Red
    Write-Host "         You can manually zip the contents of: $packageDir" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Package Creation Complete" -ForegroundColor Green
Write-Host "=========================" -ForegroundColor Green
Write-Host ""
Write-Host "Package directory: $packageDir" -ForegroundColor Cyan
if (Test-Path $zipPath) {
    Write-Host "ZIP package: $zipPath" -ForegroundColor Cyan
}
Write-Host ""
Write-Host "To distribute TrueFA-Py to Windows users:" -ForegroundColor Cyan
Write-Host "1. Share the ZIP package" -ForegroundColor Cyan
Write-Host "2. Instruct users to extract the ZIP and run 'setup.bat' followed by 'TrueFA-Py.bat'" -ForegroundColor Cyan
Write-Host ""

# Keep console open
Write-Host "Press any key to exit..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
