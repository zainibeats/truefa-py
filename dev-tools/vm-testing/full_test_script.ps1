Write-Host 'Starting TrueFA Full Test Run'
Write-Host '==============================='
Write-Host 'Test environment: Windows Server Core'
Write-Host "Python version: $(python --version 2>&1)"

# Create user directories
$userProfile = 'C:\Users\testuser'
if (!(Test-Path "$userProfile\.truefa")) {
    mkdir "$userProfile\.truefa" | Out-Null
}

# Ensure proper permissions
icacls "$userProfile\.truefa" /grant testuser:F

Write-Host 'Testing executable:'
$exePath = 'C:\app\dist\TrueFA-Py.exe'
Write-Host "Found executable: $exePath"

# Test executable
Write-Host 'Starting executable...'
try {
    # Run with a timeout (GUI app won't show output)
    $process = Start-Process -FilePath $exePath -PassThru
    
    # Wait a bit to see if it crashes
    Start-Sleep -Seconds 5
    
    if (-not $process.HasExited) {
        Write-Host 'Executable is running without immediate crashes'
        
        # Wait longer to check stability
        Start-Sleep -Seconds 10
        
        if (-not $process.HasExited) {
            Write-Host 'Executable appears stable after 15 seconds of runtime'
            
            # Try to gracefully terminate
            $process.CloseMainWindow() | Out-Null
            if (-not $process.WaitForExit(5000)) {
                Write-Host 'Stopping process...'
                $process.Kill()
            }
        } else {
            Write-Host "Process exited with code: $($process.ExitCode)"
        }
    } else {
        Write-Host "Process crashed immediately with exit code: $($process.ExitCode)"
    }
} catch {
    Write-Host "Error running executable: $_"
}

# Check for crash markers or log files
if (Test-Path "$userProfile\.truefa\.dll_crash") {
    Write-Host 'DLL crash marker found. Contents:'
    Get-Content "$userProfile\.truefa\.dll_crash"
} else {
    Write-Host 'No DLL crash markers found'
}

# Check for created vault directory
if (Test-Path "$userProfile\.truefa\.vault") {
    Write-Host 'Vault directory was created successfully'
} else {
    Write-Host 'No vault directory was created'
}

Write-Host 'Test completed'
