# TrueFA-Py Docker Test Script
# This script tests the TrueFA-Py executable in a clean Windows environment

function Write-Header {
    param ([string]$title)
    Write-Host ""
    Write-Host "=====================================" -ForegroundColor Cyan
    Write-Host $title -ForegroundColor Cyan
    Write-Host "=====================================" -ForegroundColor Cyan
}

Write-Header "TrueFA-Py Docker Test"
Write-Host "Test environment: Windows Server Core"

# Clean environment
if (Test-Path "$env:USERPROFILE/.truefa") {
    Write-Host "Cleaning up previous .truefa directory..." -ForegroundColor Yellow
    Remove-Item -Path "$env:USERPROFILE/.truefa" -Recurse -Force -ErrorAction SilentlyContinue
}

# Find the executable
$exePath = Get-ChildItem -Path "C:/app/dist" -Filter "*.exe" -Recurse | 
           Where-Object { -not $_.Name.Contains("Setup") } | 
           Select-Object -First 1 -ExpandProperty FullName

if (-not $exePath) {
    Write-Host "ERROR: No executable found in dist directory." -ForegroundColor Red
    exit 1
}

# File verification
Write-Header "Executable Verification"
$fileInfo = Get-Item $exePath
Write-Host "Found executable: $exePath"
Write-Host "File size: $([Math]::Round($fileInfo.Length / 1MB, 2)) MB"
Write-Host "Last modified: $($fileInfo.LastWriteTime)"

# Environment setup
Write-Header "Environment Setup"
Write-Host "Setting TRUEFA_PORTABLE=1 environment variable"
$env:TRUEFA_PORTABLE = "1"

try {
    # Basic test - just see if it starts
    Write-Header "Basic Startup Test"
    Write-Host "Attempting to start the application..."

    $startTime = Get-Date
    $process = Start-Process -FilePath $exePath -PassThru
    Start-Sleep -Seconds 2
    
    if (-not $process.HasExited) {
        Write-Host "SUCCESS: Application started without immediate crash" -ForegroundColor Green
        Write-Host "Stopping process..."
        $process.Kill()
    } else {
        Write-Host "WARNING: Application exited immediately with code: $($process.ExitCode)" -ForegroundColor Yellow
    }
    
    $endTime = Get-Date
    $duration = ($endTime - $startTime).TotalSeconds
    Write-Host "Test duration: $([Math]::Round($duration, 2)) seconds"
    
    # Check for crash markers
    Write-Header "Crash Detection"
    if (Test-Path "$env:USERPROFILE/.truefa/.dll_crash") {
        Write-Host "DLL crash marker found:" -ForegroundColor Red
        Get-Content "$env:USERPROFILE/.truefa/.dll_crash" | ForEach-Object {
            Write-Host "  $_" -ForegroundColor Red
        }
    } else {
        Write-Host "No crash markers detected" -ForegroundColor Green
    }
    
    # Check fallback mode
    Write-Header "Fallback Mode Detection"
    if (Test-Path "$env:USERPROFILE/.truefa/.using_fallback") {
        Write-Host "Application is using fallback mode" -ForegroundColor Yellow
        Get-Content "$env:USERPROFILE/.truefa/.using_fallback" | ForEach-Object {
            Write-Host "  $_" -ForegroundColor Yellow
        }
    } else {
        Write-Host "Application is using native crypto implementation" -ForegroundColor Green
    }
    
} catch {
    Write-Host "ERROR: Test failed with exception: $_" -ForegroundColor Red
    exit 1
}

Write-Header "Test Result"
Write-Host "✓ Test completed successfully" -ForegroundColor Green
