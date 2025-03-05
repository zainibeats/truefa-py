param (
    [switch]$Silent
)

$isCompatible = $true
$issues = @()

function Write-Status {
    param (
        [string]$Message,
        [string]$Status,
        [string]$Color
    )
    
    if (-not $Silent) {
        Write-Host $Message -NoNewline
        Write-Host $Status -ForegroundColor $Color
    }
}

# Check Windows version
$osInfo = Get-CimInstance Win32_OperatingSystem
$windowsVersion = [System.Environment]::OSVersion.Version
$minVersion = [System.Version]::new(10, 0, 0, 0)

if ($windowsVersion -lt $minVersion) {
    $isCompatible = $false
    $issues += "Windows version must be Windows 10 or newer."
    Write-Status "Windows version... " "FAILED" "Red"
} else {
    Write-Status "Windows version... " "OK" "Green"
}

# Check for Visual C++ Redistributable
$vcRedistName = "Microsoft Visual C++ 2015-2022 Redistributable (x64)"
$vcRegPath = "HKLM:\\SOFTWARE\\Microsoft\\VisualStudio\\14.0\\VC\\Runtimes\\X64"
$vcRedistInstalled = (Test-Path $vcRegPath) -and ((Get-ItemProperty $vcRegPath).Installed -eq 1)

if (-not $vcRedistInstalled) {
    $isCompatible = $false
    $issues += "Visual C++ Redistributable not found. Run setup.bat to install it."
    Write-Status "Visual C++ Redistributable... " "MISSING" "Yellow"
} else {
    Write-Status "Visual C++ Redistributable... " "OK" "Green"
}

# Check filesystem permissions
$testDir = Join-Path ([System.IO.Path]::GetTempPath()) "TrueFA-Test"
$testFile = Join-Path $testDir "test.txt"
try {
    if (-not (Test-Path $testDir)) {
        New-Item -Path $testDir -ItemType Directory -Force | Out-Null
    }
    Set-Content -Path $testFile -Value "Test" -ErrorAction Stop
    Remove-Item -Path $testFile -Force -ErrorAction SilentlyContinue
    Write-Status "Filesystem permissions... " "OK" "Green"
} catch {
    $isCompatible = $false
    $issues += "Cannot write to temporary directory. Application may not work correctly."
    Write-Status "Filesystem permissions... " "FAILED" "Red"
}

# Check admin privileges
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Status "Admin privileges... " "NOT ADMIN" "Yellow"
} else {
    Write-Status "Admin privileges... " "ADMIN" "Green"
}

# Output summary
if ($isCompatible) {
    if (-not $Silent) {
        Write-Host "
System is compatible with TrueFA-Py." -ForegroundColor Green
    }
    return 0
} else {
    if (-not $Silent) {
        Write-Host "
System is NOT fully compatible with TrueFA-Py:" -ForegroundColor Red
        foreach ($issue in $issues) {
            Write-Host "- $issue" -ForegroundColor Red
        }
    }
    return 1
}
