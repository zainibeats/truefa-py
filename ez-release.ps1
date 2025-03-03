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
    Write-Host "[INFO] Building executables..."
    
    # Clean build artifacts
    if (Test-Path "build") { Remove-Item -Recurse -Force "build" }
    if (Test-Path "dist") { Remove-Item -Recurse -Force "dist" }
    
    # Run the build script with both portable and installer options
    & .\dev-tools\build.ps1 -Clean -Portable -Installer
    
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[ERROR] Build failed with code $LASTEXITCODE"
        exit $LASTEXITCODE
    }
    
    Write-Host "[INFO] Build completed successfully."
} else {
    Write-Host "[INFO] Build skipped as requested."
}

# Step 3: Create release directory
Write-Host "[INFO] Creating release directory..."
if (Test-Path "release") { Remove-Item -Recurse -Force "release" }
New-Item -Path "release" -ItemType Directory -Force | Out-Null

# Step 4: Copy files to release directory
Write-Host "[INFO] Copying files to release directory..."

# Executables
if (Test-Path "dist\*.exe") {
    Copy-Item "dist\*.exe" "release\" -Force
    Write-Host "[INFO] Copied executables to release directory."
} else {
    Write-Host "[WARNING] No executables found in dist directory."
}

# Documentation
$docFiles = @("README.md", "LICENSE", "SECURITY.md", "CRYPTO.md")
foreach ($file in $docFiles) {
    if (Test-Path $file) {
        Copy-Item $file "release\" -Force
        Write-Host "[INFO] Copied $file to release directory."
    } else {
        Write-Host "[WARNING] $file not found, skipping."
    }
}

# Step 5: Sign executables (unless skipped)
if (-not $NoSign) {
    Write-Host "[INFO] Signing executables..."
    Get-ChildItem "release\*.exe" | ForEach-Object {
        Write-Host "[INFO] Signing $_..."
        & gpg --batch --yes --default-key $GPG_KEY_ID --detach-sign $_.FullName
        if ($LASTEXITCODE -ne 0) {
            Write-Host "[WARNING] GPG signing failed for $_. Error: $LASTEXITCODE"
        } else {
            Write-Host "[INFO] $_ signed successfully."
            # Signature files are already created in the release directory
        }
    }
} else {
    Write-Host "[INFO] Signing skipped as requested."
}

# Step 6: Create ZIP archive
$RELEASE_PACKAGE = "$PROJECT_NAME-$CURRENT_VERSION-Release.zip"
Write-Host "[INFO] Creating release package: $RELEASE_PACKAGE"
Compress-Archive -Path "release\*" -DestinationPath $RELEASE_PACKAGE -Force

Write-Host ""
Write-Host "===== Release process completed successfully! ====="
Write-Host ""
Write-Host "Release package: $RELEASE_PACKAGE"
Write-Host ""
Write-Host "Output files can be found in:"
Write-Host "- Release directory: $(Get-Location)\release\"
Write-Host "- Release package: $(Get-Location)\$RELEASE_PACKAGE"
Write-Host "" 