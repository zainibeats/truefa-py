# Windows Compatibility Check for TrueFA-Py
# This script checks if the current Windows system has the necessary prerequisites
# for running the TrueFA-Py executable

Write-Host "TrueFA-Py Windows Compatibility Check" -ForegroundColor Green
Write-Host "===================================" -ForegroundColor Green
Write-Host ""

# Function to check if a certain Windows version or higher is present
function Test-WindowsVersion {
    param (
        [int]$MajorVersion,
        [int]$MinorVersion = 0,
        [int]$BuildNumber = 0
    )
    
    $osInfo = Get-WmiObject -Class Win32_OperatingSystem
    $versionString = $osInfo.Version
    $versionParts = $versionString.Split('.')
    
    $currentMajor = [int]$versionParts[0]
    $currentMinor = [int]$versionParts[1]
    $currentBuild = [int]$versionParts[2]
    
    if ($currentMajor -gt $MajorVersion) {
        return $true
    }
    elseif ($currentMajor -eq $MajorVersion -and $currentMinor -gt $MinorVersion) {
        return $true
    }
    elseif ($currentMajor -eq $MajorVersion -and $currentMinor -eq $MinorVersion -and $currentBuild -ge $BuildNumber) {
        return $true
    }
    else {
        return $false
    }
}

# Function to check for a specific Visual C++ Redistributable
function Test-VCRedist {
    param (
        [string]$DisplayNamePattern
    )
    
    $vcRedist = Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -like $DisplayNamePattern }
    return $null -ne $vcRedist
}

# Function to test DLL compatibility
function Test-DllCompatibility {
    param (
        [string]$DllName
    )
    
    $dllPaths = @(
        [System.Environment]::GetFolderPath('System'),
        [System.Environment]::GetFolderPath('SystemX86'),
        [System.Environment]::GetFolderPath('Windows')
    )
    
    foreach ($path in $dllPaths) {
        $dllPath = Join-Path $path $DllName
        if (Test-Path $dllPath) {
            return $true
        }
    }
    
    # Check in PATH
    $envPaths = $env:PATH -split ';'
    foreach ($path in $envPaths) {
        if (Test-Path $path) {
            $dllPath = Join-Path $path $DllName
            if (Test-Path $dllPath) {
                return $true
            }
        }
    }
    
    return $false
}

# Check if TrueFA-Py executable exists
$exePath = Join-Path (Get-Location) "dist\TrueFA-Py.exe"
$exeExists = Test-Path $exePath

Write-Host "System Information:" -ForegroundColor Yellow
$osInfo = Get-WmiObject -Class Win32_OperatingSystem
Write-Host "  Windows Version: $($osInfo.Caption) ($($osInfo.Version))"
Write-Host "  Architecture: $($env:PROCESSOR_ARCHITECTURE)"
Write-Host "  PowerShell Version: $($PSVersionTable.PSVersion)"
Write-Host ""

# Check Windows version
Write-Host "Windows Version Check:" -ForegroundColor Yellow
$win10OrHigher = Test-WindowsVersion -MajorVersion 10
if ($win10OrHigher) {
    Write-Host "  [PASS] Windows 10 or higher detected" -ForegroundColor Green
} else {
    Write-Host "  [WARN] Windows version older than Windows 10 detected" -ForegroundColor Yellow
    Write-Host "         The application may not work correctly on this older Windows version" -ForegroundColor Yellow
}
Write-Host ""

# Check for VC++ Redistributables
Write-Host "Visual C++ Redistributable Check:" -ForegroundColor Yellow
$vc2015to2022 = Test-VCRedist -DisplayNamePattern "*Microsoft Visual C++ 201* Redistributable*"
if ($vc2015to2022) {
    Write-Host "  [PASS] Visual C++ 2015-2022 Redistributable found" -ForegroundColor Green
} else {
    Write-Host "  [FAIL] Visual C++ 2015-2022 Redistributable not found" -ForegroundColor Red
    Write-Host "         TrueFA-Py may not run without this dependency" -ForegroundColor Red
    Write-Host "         Download from: https://aka.ms/vs/17/release/vc_redist.x64.exe" -ForegroundColor Cyan
}
Write-Host ""

# Check for critical DLLs
Write-Host "Critical DLL Check:" -ForegroundColor Yellow
$dllsToCheck = @(
    "VCRUNTIME140.dll",
    "MSVCP140.dll",
    "python310.dll"
)

$missingDlls = @()
foreach ($dll in $dllsToCheck) {
    $dllFound = Test-DllCompatibility -DllName $dll
    if ($dllFound) {
        Write-Host "  [PASS] $dll found in system paths" -ForegroundColor Green
    } else {
        Write-Host "  [WARN] $dll not found in system paths" -ForegroundColor Yellow
        $missingDlls += $dll
    }
}

if ($missingDlls.Count -gt 0) {
    Write-Host ""
    Write-Host "Some system DLLs might be missing. These may be needed by TrueFA-Py." -ForegroundColor Yellow
    Write-Host "If the application fails to start, consider installing Visual C++ Redistributable" -ForegroundColor Yellow
    Write-Host "and/or Python 3.10 if they are not already installed." -ForegroundColor Yellow
}
Write-Host ""

# Check if executable exists and attempt to run
Write-Host "TrueFA-Py Executable Check:" -ForegroundColor Yellow
if ($exeExists) {
    Write-Host "  [PASS] TrueFA-Py.exe found at: $exePath" -ForegroundColor Green
    
    # Get file details
    $exeFile = Get-Item $exePath
    Write-Host "  File Size: $([Math]::Round($exeFile.Length / 1MB, 2)) MB" -ForegroundColor Cyan
    Write-Host "  Created: $($exeFile.CreationTime)" -ForegroundColor Cyan
    Write-Host "  Last Modified: $($exeFile.LastWriteTime)" -ForegroundColor Cyan
    
    # Ask to run the executable
    Write-Host ""
    $runTest = Read-Host "Would you like to test run the executable? (y/n)"
    if ($runTest -eq 'y') {
        Write-Host "Starting TrueFA-Py.exe..." -ForegroundColor Cyan
        Write-Host "The application window should appear shortly. Close it when done testing." -ForegroundColor Cyan
        Write-Host ""
        
        try {
            $process = Start-Process -FilePath $exePath -PassThru
            
            # Wait a bit to see if it crashes immediately
            Start-Sleep -Seconds 3
            
            if (-not $process.HasExited) {
                Write-Host "[SUCCESS] Application started successfully and is running" -ForegroundColor Green
                
                # Ask user to confirm they can see the application
                $confirmation = Read-Host "Can you see the TrueFA-Py application window? (y/n)"
                if ($confirmation -eq 'y') {
                    Write-Host "[PASS] User can see and interact with the application" -ForegroundColor Green
                } else {
                    Write-Host "[WARN] User cannot see the application window" -ForegroundColor Yellow
                    Write-Host "The process is running but may not be displaying correctly" -ForegroundColor Yellow
                }
                
                # Ask user if they want to close the application
                $closeApp = Read-Host "Would you like to close the application now? (y/n)"
                if ($closeApp -eq 'y') {
                    Write-Host "Closing application..." -ForegroundColor Cyan
                    $process.CloseMainWindow() | Out-Null
                    
                    # Give it a few seconds, then force kill if needed
                    if (-not $process.WaitForExit(5000)) {
                        $process.Kill()
                    }
                    
                    Write-Host "Application closed." -ForegroundColor Cyan
                } else {
                    Write-Host "Leaving application running. You can close it manually when done testing." -ForegroundColor Cyan
                }
            } else {
                Write-Host "[FAIL] Application crashed immediately with exit code: $($process.ExitCode)" -ForegroundColor Red
                Write-Host "This suggests an incompatibility with this system." -ForegroundColor Red
            }
        } catch {
            Write-Host "[ERROR] Failed to launch application: $_" -ForegroundColor Red
        }
    }
} else {
    Write-Host "  [FAIL] TrueFA-Py.exe not found at: $exePath" -ForegroundColor Red
    Write-Host "  Make sure you run this script from the project root directory" -ForegroundColor Red
    Write-Host "  or build the executable first" -ForegroundColor Red
}

Write-Host ""
Write-Host "Windows Compatibility Check Complete" -ForegroundColor Green
Write-Host "===================================" -ForegroundColor Green

# Keep console open
Write-Host "Press any key to exit..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
