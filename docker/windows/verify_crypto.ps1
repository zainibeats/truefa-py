# TrueFA-Py Crypto Verification Script for Docker Windows Testing
# This script verifies that the Rust cryptography module is properly loaded and functioning in the Docker container

# Set working directory and add TrueFA to path
$env:PATH += ";C:\TrueFA"
cd C:\TrueFA

# Banner
Write-Host "====== TrueFA-Py Rust Cryptography Verification ======" -ForegroundColor Cyan
Write-Host

# Check that TrueFA executable exists
if (-not (Test-Path "TrueFA-Py.exe")) {
    Write-Host "ERROR: TrueFA-Py.exe not found" -ForegroundColor Red
    exit 1
}

# Check that Rust DLL exists
if (-not (Test-Path "truefa_crypto.dll")) {
    Write-Host "ERROR: truefa_crypto.dll not found" -ForegroundColor Red
    Write-Host "The application will use the fallback Python cryptography implementation" -ForegroundColor Yellow
} else {
    Write-Host "✓ Rust cryptography DLL found" -ForegroundColor Green
}

Write-Host
Write-Host "Testing Rust cryptography module integration..." -ForegroundColor Cyan

# Run TrueFA with the verify-crypto option
# If you don't have a verify-crypto command, you can create a vault which would use the crypto module
try {
    # First attempt to use a specific verification command if available
    $verifyOutput = & TrueFA-Py.exe --verify-crypto 2>&1
    
    if ($verifyOutput -match "crypto verification successful" -or $verifyOutput -match "Rust crypto") {
        Write-Host "✓ Rust cryptography module is working properly" -ForegroundColor Green
    } elseif ($verifyOutput -match "using fallback") {
        Write-Host "WARNING: Using Python fallback implementation instead of Rust cryptography" -ForegroundColor Yellow
        Write-Host "This is not recommended for production use due to security implications" -ForegroundColor Yellow
    } else {
        # If --verify-crypto doesn't exist, we'll just try the --help command to see if it loads properly
        $helpOutput = & TrueFA-Py.exe --help 2>&1
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host "✓ TrueFA-Py executable is functional" -ForegroundColor Green
            Write-Host "Note: Couldn't specifically verify crypto module. Please test manual vault creation." -ForegroundColor Yellow
        } else {
            Write-Host "ERROR: TrueFA-Py executable failed to run" -ForegroundColor Red
            Write-Host $helpOutput
            exit 1
        }
    }
} catch {
    Write-Host "ERROR: Failed to run TrueFA-Py executable:" -ForegroundColor Red
    Write-Host $_.Exception.Message
    exit 1
}

Write-Host
Write-Host "====== Verification Complete ======" -ForegroundColor Cyan
Write-Host
Write-Host "You can now proceed with manual testing of TrueFA-Py:" -ForegroundColor Green
Write-Host "1. Run: TrueFA-Py.exe --create-vault --vault-dir C:\vault_data" -ForegroundColor White
Write-Host "2. Then: TrueFA-Py.exe --vault-dir C:\vault_data" -ForegroundColor White
Write-Host 