param (
    [Parameter(Mandatory=$false)]
    [ValidateSet("major", "minor", "patch", "none")]
    [string]$VersionType = "none",
    
    [Parameter(Mandatory=$false)]
    [switch]$NoSign,
    
    [Parameter(Mandatory=$false)]
    [switch]$NoBuild
)

Write-Host "===== TrueFA-Py Release Script ====="
Write-Host ""

# Configuration
$PROJECT_NAME = "TrueFA-Py"
$VERSION_FILE = "src\__init__.py"
$GPG_KEY_ID = "C751CFA279B38C6B55D5BC738910ACB66A475A28"
$CURRENT_VERSION = "0.1.0" # Default version if not found

# Step 1: Determine current version
if (Test-Path $VERSION_FILE) {
    $versionPattern = "__version__ = '([0-9]+\.[0-9]+\.[0-9]+)'"
    $versionMatch = Select-String -Path $VERSION_FILE -Pattern $versionPattern
    if ($versionMatch) {
        $CURRENT_VERSION = $versionMatch.Matches.Groups[1].Value
        Write-Host "[INFO] Current version: $CURRENT_VERSION"
    } else {
        Write-Host "[WARNING] Could not detect version from $VERSION_FILE, using default: $CURRENT_VERSION"
    }
} else {
    Write-Host "[WARNING] Version file not found, using default version: $CURRENT_VERSION"
}

# Step 2: Build executables (if not skipped)
if (-not $NoBuild) {
    Write-Host "[INFO] Building executables using build.ps1..."
    
    # Clean build artifacts
    if (Test-Path "build") { Remove-Item -Recurse -Force "build" }
    if (Test-Path "dist") { Remove-Item -Recurse -Force "dist" }
    
    # Run the build script with both portable and installer options
    # Ensure logging is enabled but debug is disabled in release builds
    & .\dev-tools\build.ps1 -Clean -Portable -Installer -DisableLogging:$False
    
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[ERROR] Build failed with code $LASTEXITCODE"
        exit $LASTEXITCODE
    }
    
    Write-Host "[INFO] Build completed successfully."
} else {
    Write-Host "[INFO] Build skipped as requested."
}

# Step 3: Create release directories
Write-Host "[INFO] Creating release directories..."
$releaseBaseDir = "release"
$portableReleaseDir = Join-Path $releaseBaseDir "portable"
$installerReleaseDir = Join-Path $releaseBaseDir "installer"

if (Test-Path $releaseBaseDir) { Remove-Item -Recurse -Force $releaseBaseDir }
New-Item -Path $releaseBaseDir -ItemType Directory -Force | Out-Null
New-Item -Path $portableReleaseDir -ItemType Directory -Force | Out-Null
New-Item -Path $installerReleaseDir -ItemType Directory -Force | Out-Null

# Documentation files to include in both packages
$docFiles = @("README.md", "LICENSE", "SECURITY.md", "CRYPTO.md")

# Step 4: Prepare portable package
Write-Host "[INFO] Preparing portable release package..."
# Find portable executable
$portableExe = Get-ChildItem -Path "dist" -Filter "TrueFA-Py.exe" | Where-Object { $_.Name -notmatch "Setup" } | Select-Object -First 1
if ($portableExe) {
    # Copy portable executable
    Copy-Item $portableExe.FullName $portableReleaseDir -Force
    Write-Host "[INFO] Copied portable executable to release directory."
    
    # Copy documentation files
    foreach ($file in $docFiles) {
        if (Test-Path $file) {
            Copy-Item $file $portableReleaseDir -Force
            Write-Host "[INFO] Copied $file to portable release directory."
        }
    }
    
    # Copy launcher batch file
    if (Test-Path "TrueFA-Py-Launcher.bat") {
        Copy-Item "TrueFA-Py-Launcher.bat" $portableReleaseDir -Force
        Write-Host "[INFO] Copied TrueFA-Py-Launcher.bat to portable release directory."
    } else {
        Write-Host "[WARNING] TrueFA-Py-Launcher.bat not found, creating a simple launcher..."
        @"
@echo off
start "" "%~dp0TrueFA-Py.exe"
"@ | Set-Content -Path (Join-Path $portableReleaseDir "TrueFA-Py-Launcher.bat") -Encoding ASCII
    }
} else {
    Write-Host "[WARNING] Portable executable not found in dist directory."
}

# Step 5: Prepare installer package
Write-Host "[INFO] Preparing installer release package..."
# Find installer executable
$installerExe = Get-ChildItem -Path "dist" -Filter "*Setup*.exe" | Select-Object -First 1
if ($installerExe) {
    # Copy installer executable
    Copy-Item $installerExe.FullName $installerReleaseDir -Force
    Write-Host "[INFO] Copied installer executable to release directory."
    
    # Copy documentation files
    foreach ($file in $docFiles) {
        if (Test-Path $file) {
            Copy-Item $file $installerReleaseDir -Force
            Write-Host "[INFO] Copied $file to installer release directory."
        }
    }
} else {
    Write-Host "[WARNING] Installer executable not found in dist directory."
}

# Step 6: Sign executables (unless skipped)
if (-not $NoSign) {
    Write-Host "[INFO] Signing executables..."
    
    # Sign all executables in both release directories
    $allExes = @(
        (Get-ChildItem -Path $portableReleaseDir -Filter "*.exe"),
        (Get-ChildItem -Path $installerReleaseDir -Filter "*.exe")
    )
    
    foreach ($exe in $allExes) {
        Write-Host "[INFO] Signing $($exe.Name)..."
        & gpg --batch --yes --default-key $GPG_KEY_ID --detach-sign $exe.FullName
        if ($LASTEXITCODE -ne 0) {
            Write-Host "[WARNING] GPG signing failed for $($exe.Name). Error: $LASTEXITCODE"
        } else {
            Write-Host "[INFO] $($exe.Name) signed successfully."
        }
    }
} else {
    Write-Host "[INFO] Signing skipped as requested."
}

# Step 7: Create ZIP archives
$PORTABLE_PACKAGE = "$PROJECT_NAME-$CURRENT_VERSION-Portable.zip"
$INSTALLER_PACKAGE = "$PROJECT_NAME-$CURRENT_VERSION-Installer.zip"

# Create portable package if files exist
if (Test-Path "$portableReleaseDir\*.exe") {
    Write-Host "[INFO] Creating portable release package: $PORTABLE_PACKAGE"
    Compress-Archive -Path "$portableReleaseDir\*" -DestinationPath $PORTABLE_PACKAGE -Force
    Write-Host "[INFO] Portable package created successfully."
} else {
    Write-Host "[WARNING] No portable executables found, skipping portable package creation."
}

# Create installer package if files exist
if (Test-Path "$installerReleaseDir\*.exe") {
    Write-Host "[INFO] Creating installer release package: $INSTALLER_PACKAGE"
    Compress-Archive -Path "$installerReleaseDir\*" -DestinationPath $INSTALLER_PACKAGE -Force
    Write-Host "[INFO] Installer package created successfully."
} else {
    Write-Host "[WARNING] No installer executables found, skipping installer package creation."
}

Write-Host ""
Write-Host "===== Release process completed successfully! ====="
Write-Host ""
Write-Host "Release packages:"
if (Test-Path $PORTABLE_PACKAGE) {
    Write-Host "- Portable: $(Get-Location)\$PORTABLE_PACKAGE"
}
if (Test-Path $INSTALLER_PACKAGE) {
    Write-Host "- Installer: $(Get-Location)\$INSTALLER_PACKAGE"
}
Write-Host ""
Write-Host "Output files can be found in:"
Write-Host "- Portable release directory: $(Get-Location)\$portableReleaseDir\"
Write-Host "- Installer release directory: $(Get-Location)\$installerReleaseDir\"