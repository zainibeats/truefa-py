# TrueFA-Py Clean-up Script
# This script removes all build artifacts, temporary files, and test directories

Write-Host "TrueFA-Py Clean-up Script" -ForegroundColor Cyan
Write-Host "==========================" -ForegroundColor Cyan
Write-Host ""

# Stop any running processes that might be using our files
$processesToStop = @("TrueFA-Py_console", "TrueFA-Py", "python")
foreach ($proc in $processesToStop) {
    $running = Get-Process -Name $proc -ErrorAction SilentlyContinue
    if ($running) {
        Write-Host "Stopping process: $proc" -ForegroundColor Yellow
        Stop-Process -Name $proc -Force -ErrorAction SilentlyContinue
    }
}

# Clean build directories
$dirsToRemove = @(
    ".\build",
    ".\dist",
    ".\fresh_test",
    ".\__pycache__",
    ".\.pytest_cache",
    ".\vm_test_package"
)

foreach ($dir in $dirsToRemove) {
    if (Test-Path $dir) {
        Write-Host "Removing directory: $dir" -ForegroundColor Yellow
        Remove-Item -Path $dir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# Clean up spec files and other build artifacts
$filesToRemove = @(
    ".\*.spec",
    ".\*.pyc",
    ".\TrueFA-Py-VM-Test-*.zip"
)

foreach ($filePattern in $filesToRemove) {
    $files = Get-ChildItem -Path $filePattern -ErrorAction SilentlyContinue
    foreach ($file in $files) {
        Write-Host "Removing file: $($file.FullName)" -ForegroundColor Yellow
        Remove-Item -Path $file.FullName -Force -ErrorAction SilentlyContinue
    }
}

# Clean up .truefa directory in user profile if requested
$cleanUserData = Read-Host "Do you want to clean application data in your user profile? (y/n)"
if ($cleanUserData -eq "y") {
    $truefaDir = Join-Path $env:USERPROFILE ".truefa"
    if (Test-Path $truefaDir) {
        Write-Host "Removing application data: $truefaDir" -ForegroundColor Yellow
        Remove-Item -Path $truefaDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Write-Host ""
Write-Host "Clean-up complete!" -ForegroundColor Green
Write-Host "Run fresh_build_test.ps1 to build and test TrueFA-Py again." -ForegroundColor Green
