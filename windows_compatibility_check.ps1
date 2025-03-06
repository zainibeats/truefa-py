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
    
    try {
        # First try using Win32_Product, but this can be slow and sometimes unreliable
        $vcRedist = Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -like $DisplayNamePattern }
        if ($null -ne $vcRedist) {
            return $true
        }
        
        # Try alternative method using registry check which is faster
        $uninstallKeys = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
        )
        
        foreach ($key in $uninstallKeys) {
            if (Test-Path $key) {
                $vcItems = Get-ItemProperty $key | Where-Object { $_.DisplayName -like $DisplayNamePattern }
                if ($null -ne $vcItems) {
                    return $true
                }
            }
        }
        
        return $false
    }
    catch {
        Write-Host "  [WARN] Error checking for Visual C++ Redistributable" -ForegroundColor Yellow
        # Return false instead of failing completely
        return $false
    }
}

# Function to test DLL compatibility
function Test-DllCompatibility {
    param (
        [string]$DllName
    )
    
    try {
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
        
        # Check in application directory and python-embed directory
        $localDllPaths = @(
            ".",
            ".\python-embed",
            "..\python-embed",
            ".\dist",
            "..\dist",
            ".\rust_crypto\target\release",
            "..\rust_crypto\target\release"
        )
        
        foreach ($path in $localDllPaths) {
            if (Test-Path $path) {
                $dllPath = Join-Path $path $DllName
                if (Test-Path $dllPath) {
                    return $true
                }
            }
        }
        
        return $false
    }
    catch {
        Write-Host "  [WARN] Error checking for DLL $DllName" -ForegroundColor Yellow
        return $false
    }
}

# Function to check for Python installation
function Test-PythonInstallation {
    param (
        [string]$Version = "3.10"
    )
    
    try {
        # Check for Python in PATH
        $pythonCommand = Get-Command python -ErrorAction SilentlyContinue
        if ($null -ne $pythonCommand) {
            # Check version
            $versionOutput = python -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>$null
            if ($versionOutput -like "$Version*") {
                return @{
                    Found = $true
                    Path = $pythonCommand.Source
                    Version = $versionOutput
                }
            }
        }
        
        # Check for Python in common install locations
        $possiblePythonPaths = @(
            "${env:LOCALAPPDATA}\Programs\Python\Python$($Version.Replace('.', ''))\python.exe",
            "C:\Python$($Version.Replace('.', ''))\python.exe",
            "C:\Program Files\Python$($Version.Replace('.', ''))\python.exe",
            "C:\Program Files (x86)\Python$($Version.Replace('.', ''))\python.exe"
        )
        
        foreach ($path in $possiblePythonPaths) {
            if (Test-Path $path) {
                # Check version
                $versionOutput = & $path -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>$null
                if ($versionOutput -like "$Version*") {
                    return @{
                        Found = $true
                        Path = $path
                        Version = $versionOutput
                    }
                }
            }
        }
        
        # Check registry for Python installations
        $regPaths = @(
            "HKLM:\SOFTWARE\Python\PythonCore\$Version\InstallPath",
            "HKCU:\SOFTWARE\Python\PythonCore\$Version\InstallPath"
        )
        
        foreach ($regPath in $regPaths) {
            if (Test-Path $regPath) {
                $installPath = (Get-ItemProperty -Path $regPath -Name "(Default)" -ErrorAction SilentlyContinue)."(Default)"
                if ($null -ne $installPath) {
                    $pythonPath = Join-Path $installPath "python.exe"
                    if (Test-Path $pythonPath) {
                        $versionOutput = & $pythonPath -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>$null
                        return @{
                            Found = $true
                            Path = $pythonPath
                            Version = $versionOutput
                        }
                    }
                }
            }
        }
        
        # Look for embedded Python in the application directory
        $embeddedPythonPaths = @(
            ".\python-embed\python.exe",
            "..\python-embed\python.exe",
            ".\dist\python-embed\python.exe",
            "..\dist\python-embed\python.exe"
        )
        
        foreach ($path in $embeddedPythonPaths) {
            if (Test-Path $path) {
                return @{
                    Found = $true
                    Path = (Get-Item $path).FullName
                    Version = "Embedded Python"
                    Embedded = $true
                }
            }
        }
        
        return @{
            Found = $false
        }
    }
    catch {
        Write-Host "  [WARN] Error checking for Python installation" -ForegroundColor Yellow
        return @{
            Found = $false
            Error = $_
        }
    }
}

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
    
    # Check if the redistributable installer is in common locations
    $vcRedistPaths = @(
        ".\dependencies\VC_redist.x64.exe",
        ".\tools\VC_redist.x64.exe",
        ".\dev-tools\VC_redist.x64.exe",
        "..\dependencies\VC_redist.x64.exe",
        "..\tools\VC_redist.x64.exe",
        "..\dev-tools\VC_redist.x64.exe"
    )
    
    $vcRedistFound = $false
    foreach($vcPath in $vcRedistPaths) {
        if (Test-Path $vcPath) {
            $vcRedistFound = $true
            $vcRedistPath = $vcPath
            break
        }
    }
    
    if ($vcRedistFound) {
        Write-Host "  [INFO] Visual C++ Redistributable installer found at: $vcRedistPath" -ForegroundColor Cyan
        $installNow = Read-Host "  Would you like to install it now? (y/n)"
        if ($installNow -eq 'y') {
            try {
                Write-Host "  [INFO] Installing Visual C++ Redistributable..." -ForegroundColor Cyan
                $process = Start-Process -FilePath $vcRedistPath -ArgumentList "/quiet", "/norestart" -Wait -PassThru
                
                if ($process.ExitCode -eq 0 -or $process.ExitCode -eq 3010) {
                    if ($process.ExitCode -eq 3010) {
                        Write-Host "  [SUCCESS] Visual C++ Redistributable installed but requires a system restart" -ForegroundColor Yellow
                    } else {
                        Write-Host "  [SUCCESS] Visual C++ Redistributable installed successfully" -ForegroundColor Green
                    }
                } else {
                    Write-Host "  [WARN] Visual C++ Redistributable installer returned exit code: $($process.ExitCode)" -ForegroundColor Yellow
                }
            } catch {
                Write-Host "  [ERROR] Failed to install Visual C++ Redistributable" -ForegroundColor Red
            }
        }
    } else {
        Write-Host "  [INFO] Would you like to download and install the Visual C++ Redistributable now? (y/n)" -ForegroundColor Cyan
        $downloadNow = Read-Host
        if ($downloadNow -eq 'y') {
            try {
                $tempDir = [System.IO.Path]::GetTempPath()
                $vcRedistTempPath = Join-Path $tempDir "vc_redist.x64.exe"
                Write-Host "  [INFO] Downloading Visual C++ Redistributable..." -ForegroundColor Cyan
                
                # Download using .NET WebClient
                $webClient = New-Object System.Net.WebClient
                $webClient.DownloadFile("https://aka.ms/vs/17/release/vc_redist.x64.exe", $vcRedistTempPath)
                
                if (Test-Path $vcRedistTempPath) {
                    Write-Host "  [INFO] Installing Visual C++ Redistributable..." -ForegroundColor Cyan
                    $process = Start-Process -FilePath $vcRedistTempPath -ArgumentList "/quiet", "/norestart" -Wait -PassThru
                    
                    if ($process.ExitCode -eq 0 -or $process.ExitCode -eq 3010) {
                        if ($process.ExitCode -eq 3010) {
                            Write-Host "  [SUCCESS] Visual C++ Redistributable installed but requires a system restart" -ForegroundColor Yellow
                        } else {
                            Write-Host "  [SUCCESS] Visual C++ Redistributable installed successfully" -ForegroundColor Green
                        }
                    } else {
                        Write-Host "  [WARN] Visual C++ Redistributable installer returned exit code: $($process.ExitCode)" -ForegroundColor Yellow
                    }
                } else {
                    Write-Host "  [ERROR] Failed to download Visual C++ Redistributable" -ForegroundColor Red
                }
            } catch {
                Write-Host "  [ERROR] Failed to download/install Visual C++ Redistributable: $_" -ForegroundColor Red
            }
        }
    }
}
Write-Host ""

# Check for Python 3.10
Write-Host "Python Installation Check:" -ForegroundColor Yellow
$pythonCheck = Test-PythonInstallation -Version "3.10"

if ($pythonCheck.Found) {
    if ($pythonCheck.Embedded) {
        Write-Host "  [PASS] Embedded Python found at: $($pythonCheck.Path)" -ForegroundColor Green
        Write-Host "         This is suitable for the portable application" -ForegroundColor Green
    } else {
        Write-Host "  [PASS] Python $($pythonCheck.Version) found at: $($pythonCheck.Path)" -ForegroundColor Green
    }
} else {
    Write-Host "  [WARN] Python 3.10 not found on this system" -ForegroundColor Yellow
    Write-Host "         This may not be an issue if you're using the bundled application" -ForegroundColor Yellow
    Write-Host "         If you're running from source, you need Python 3.10+" -ForegroundColor Yellow
    Write-Host "         Download from: https://www.python.org/downloads/" -ForegroundColor Cyan
}
Write-Host ""

# Check for environment variables used by TrueFA-Py
Write-Host "TrueFA-Py Environment Variable Check:" -ForegroundColor Yellow
$envVarsToCheck = @(
    "TRUEFA_PORTABLE",
    "TRUEFA_DATA_DIR",
    "TRUEFA_EXPORTS_DIR",
    "TRUEFA_CRYPTO_DIR",
    "TRUEFA_VAULT_FILE",
    "TRUEFA_SECURE_DIR",
    "TRUEFA_USE_FALLBACK"
)

foreach ($envVar in $envVarsToCheck) {
    $varValue = [Environment]::GetEnvironmentVariable($envVar)
    
    if ($null -ne $varValue) {
        Write-Host "  [INFO] $envVar is set to: $varValue" -ForegroundColor Cyan
    } else {
        Write-Host "  [INFO] $envVar is not set (will use defaults)" -ForegroundColor Gray
    }
}
Write-Host ""

# Check for critical DLLs
Write-Host "Critical DLL Check:" -ForegroundColor Yellow
$dllsToCheck = @(
    "VCRUNTIME140.dll",
    "MSVCP140.dll",
    "python310.dll",
    "truefa_crypto.dll"
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

# Check for Rust crypto component
Write-Host "Rust Crypto Component Check:" -ForegroundColor Yellow
$cryptoDll = "truefa_crypto.dll"
$rustCryptoFound = $false

$possibleCryptoPaths = @(
    ".\rust_crypto\target\release\$cryptoDll",
    "..\rust_crypto\target\release\$cryptoDll",
    ".\dist\$cryptoDll",
    "..\dist\$cryptoDll",
    ".\$cryptoDll",
    "..\$cryptoDll"
)

foreach ($path in $possibleCryptoPaths) {
    if (Test-Path $path) {
        $rustCryptoFound = $true
        $cryptoPath = (Get-Item $path).FullName
        Write-Host "  [PASS] Rust crypto component found at: $cryptoPath" -ForegroundColor Green
        break
    }
}

if (-not $rustCryptoFound) {
    Write-Host "  [WARN] Rust crypto component ($cryptoDll) not found" -ForegroundColor Yellow
    Write-Host "         TrueFA-Py may attempt to use Python fallback crypto implementation" -ForegroundColor Yellow
}
Write-Host ""

# Check if executable exists and attempt to run
Write-Host "TrueFA-Py Executable Check:" -ForegroundColor Yellow

# Look for executable in multiple possible locations
$possibleExePaths = @(
    ".\dist\TrueFA-Py.exe",
    ".\dist\TrueFA-Py_console.exe",
    ".\TrueFA-Py.exe",
    "..\dist\TrueFA-Py.exe",
    "..\dist\TrueFA-Py_console.exe",
    "..\TrueFA-Py.exe"
)

$exePath = $null
foreach ($path in $possibleExePaths) {
    if (Test-Path $path) {
        $exePath = (Get-Item $path).FullName
        break
    }
}

if ($exePath) {
    Write-Host "  [PASS] TrueFA-Py executable found at: $exePath" -ForegroundColor Green
    
    # Get file details
    $exeFile = Get-Item $exePath
    Write-Host "  File Size: $([Math]::Round($exeFile.Length / 1MB, 2)) MB" -ForegroundColor Cyan
    Write-Host "  Created: $($exeFile.CreationTime)" -ForegroundColor Cyan
    Write-Host "  Last Modified: $($exeFile.LastWriteTime)" -ForegroundColor Cyan
    
    # Check for launcher batch file
    $launcherExists = $false
    $launcherPath = $null
    $possibleLaunchers = @(
        ".\TrueFA-Py-Launcher.bat",
        ".\TrueFA-Py.bat",
        "..\TrueFA-Py-Launcher.bat",
        "..\TrueFA-Py.bat"
    )
    
    foreach ($launcher in $possibleLaunchers) {
        if (Test-Path $launcher) {
            $launcherExists = $true
            $launcherPath = (Get-Item $launcher).FullName
            Write-Host "  [INFO] Launcher script found: $launcherPath" -ForegroundColor Cyan
            Write-Host "         For best results, use the launcher instead of the executable directly" -ForegroundColor Cyan
            break
        }
    }
    
    # Ask to run the executable
    Write-Host ""
    $runTest = Read-Host "Would you like to test run the executable? (y/n)"
    if ($runTest -eq 'y') {
        Write-Host "Starting TrueFA-Py..." -ForegroundColor Cyan
        Write-Host "The application window should appear shortly. Close it when done testing." -ForegroundColor Cyan
        Write-Host ""
        
        try {
            # Use launcher if available, otherwise run exe directly
            if ($launcherExists -and $launcherPath) {
                $process = Start-Process -FilePath $launcherPath -PassThru
            } else {
                # Set portable mode to avoid issues with permissions
                $env:TRUEFA_PORTABLE = 1
                $process = Start-Process -FilePath $exePath -PassThru
            }
            
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
                Write-Host "Try using the launcher batch file instead of the executable directly." -ForegroundColor Yellow
            }
        } catch {
            Write-Host "[ERROR] Failed to launch application" -ForegroundColor Red
        } finally {
            # Clean up environment
            $env:TRUEFA_PORTABLE = $null
        }
    }
} else {
    Write-Host "  [FAIL] TrueFA-Py executable not found" -ForegroundColor Red
    Write-Host "  Make sure you run this script from the project root directory" -ForegroundColor Red
    Write-Host "  or build the executable first" -ForegroundColor Red
}
Write-Host ""

Write-Host "Windows Compatibility Check Complete" -ForegroundColor Green
Write-Host "===================================" -ForegroundColor Green

# Keep console open
Write-Host "Press any key to exit..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
