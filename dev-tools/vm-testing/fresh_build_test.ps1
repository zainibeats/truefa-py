# TrueFA-Py Fresh Build and Test
# This script builds TrueFA-Py and prepares a testing environment

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

Write-Host "TrueFA-Py Fresh Build and Test" -ForegroundColor Cyan
Write-Host "============================" -ForegroundColor Cyan
Write-Host ""

# Cleanup previous builds
Write-Host "Cleaning up previous builds..." -ForegroundColor Yellow
if (Test-Path ".\build") { Remove-Item -Path ".\build" -Recurse -Force -ErrorAction SilentlyContinue }
if (Test-Path ".\dist") { Remove-Item -Path ".\dist" -Recurse -Force -ErrorAction SilentlyContinue }
if (Test-Path ".\fresh_test") { Remove-Item -Path ".\fresh_test" -Recurse -Force -ErrorAction SilentlyContinue }

# Build console version for testing
Write-Host "Building console version for testing..." -ForegroundColor Yellow
$pyinstallerArgs = @(
    "--onefile",
    "--console",
    "--name=TrueFA-Py_console",
    "--add-data=assets;assets",
    "main.py"
)

python -m PyInstaller $pyinstallerArgs

if (-not (Test-Path ".\dist\TrueFA-Py_console.exe")) {
    Write-Host "Error: Build failed - executable not found!" -ForegroundColor Red
    exit 1
}

# Create test directory structure
Write-Host "Setting up test environment..." -ForegroundColor Yellow
$testDir = ".\fresh_test"
New-Item -Path $testDir -ItemType Directory -Force | Out-Null
New-Item -Path "$testDir\images" -ItemType Directory -Force | Out-Null
New-Item -Path "$testDir\data" -ItemType Directory -Force | Out-Null

# Copy executable and assets
Copy-Item -Path ".\dist\TrueFA-Py_console.exe" -Destination $testDir -Force
Copy-Item -Path ".\assets" -Destination $testDir -Recurse -Force

# Create test QR code image (placeholder for testing)
$qrContent = @"
<svg xmlns="http://www.w3.org/2000/svg" width="200" height="200" viewBox="0 0 200 200">
  <rect width="200" height="200" fill="white"/>
  <text x="40" y="100" font-family="Arial" font-size="12">Test QR Code</text>
  <text x="40" y="120" font-family="Arial" font-size="12">Add real QR for testing</text>
</svg>
"@
Set-Content -Path "$testDir\images\testqr.svg" -Value $qrContent

# Create test runner batch file
$batchContent = @"
@echo off
echo TrueFA-Py Test Launcher
echo =====================
echo.
echo Running in a simulated clean environment...
echo.

:: Set environment variables for test
set TRUEFA_TEST_MODE=1
set PYTHONPATH=%~dp0
set TRUEFA_HOME=%~dp0data

:: Run the application
"%~dp0TrueFA-Py_console.exe" 2>&1

:: Reset environment
set TRUEFA_TEST_MODE=
set PYTHONPATH=
set TRUEFA_HOME=

echo.
echo Test complete!
pause
"@
Set-Content -Path "$testDir\run_test.bat" -Value $batchContent

# Create a test configuration file
$testConfig = @"
{
    "test_mode": true,
    "test_secrets": [
        {
            "secret": "TESTSECRET12345",
            "issuer": "TestIssuer",
            "account": "test@example.com"
        }
    ],
    "logging": {
        "level": "DEBUG",
        "console": true,
        "file": false
    }
}
"@
Set-Content -Path "$testDir\test_config.json" -Value $testConfig

# Create a README for testers
$readmeContent = @"
# TrueFA-Py Test Environment

This is a clean testing environment for TrueFA-Py.

## Running Tests

1. Run `run_test.bat` to start the application
2. To test QR code functionality, add QR code images to the `images` folder
3. Use the test secret "TESTSECRET12345" or create your own

## Test Scenarios

- Create a new vault with a master password
- Add a TOTP secret manually
- Generate TOTP codes
- Save and reload secrets
- Export secrets

## Reporting Issues

Document any issues encountered with:
- Screenshots
- Error messages
- Steps to reproduce
"@
Set-Content -Path "$testDir\README.txt" -Value $readmeContent

Write-Host "Test environment prepared!" -ForegroundColor Green
Write-Host "Test directory: $((Get-Item $testDir).FullName)" -ForegroundColor Green
Write-Host "To test the application in a simulated clean environment, run:" -ForegroundColor Green
Write-Host "  $((Get-Item $testDir).FullName)\run_test.bat" -ForegroundColor Yellow
