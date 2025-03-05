Write-Host "Starting TrueFA Test Run (Direct)"
Write-Host "=============================="
Write-Host "Testing environment: Windows Directly"
Write-Host "Current directory: $(Get-Location)"

# Clean environment
if (Test-Path "$env:USERPROFILE\.truefa") {
    Write-Host "Cleaning up previous .truefa directory"
    Remove-Item -Path "$env:USERPROFILE\.truefa" -Recurse -Force -ErrorAction SilentlyContinue
}

# Find and run the executable
$exePath = Get-ChildItem -Path ".\dist" -Filter "*.exe" -Recurse | Where-Object { -not $_.Name.Contains("Setup") } | Select-Object -First 1 -ExpandProperty FullName

if ($exePath) {
    Write-Host "Found executable: $exePath"
    Write-Host "Running executable..."
    
    try {
        # Run the executable with a timeout (since it might be a GUI app)
        $process = Start-Process -FilePath $exePath -PassThru
        
        # Wait a few seconds to see if it crashes immediately
        Start-Sleep -Seconds 5
        
        if (-not $process.HasExited) {
            Write-Host "Executable appears to be running successfully"
            
            # Wait a bit longer for any potential delayed errors
            Start-Sleep -Seconds 10
            
            if (-not $process.HasExited) {
                Write-Host "Executable is still running after 15 seconds - considering it a success"
                
                # Try to gracefully terminate the process
                try {
                    $process.CloseMainWindow() | Out-Null
                    if (-not $process.WaitForExit(5000)) {
                        Write-Host "Forcefully stopping the process..."
                        $process.Kill()
                    }
                } catch {
                    Write-Host "Error closing process: $_"
                }
            } else {
                $exitCode = $process.ExitCode
                Write-Host "Process exited with code: $exitCode"
            }
        } else {
            Write-Host "Process exited immediately with code: $($process.ExitCode)"
        }
    } catch {
        Write-Host "Error running executable: $_"
    }
} else {
    Write-Host "No executable found in dist directory."
}

# Check for crash marker
if (Test-Path "$env:USERPROFILE\.truefa\.dll_crash") {
    Write-Host "DLL crash marker found. Contents:"
    Get-Content "$env:USERPROFILE\.truefa\.dll_crash"
}

Write-Host "Test completed"
