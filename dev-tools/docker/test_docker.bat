@echo off
REM Script to test TrueFA-Py in a clean Windows Docker container
REM This requires Docker Desktop with Windows containers enabled

echo TrueFA-Py Docker Test
echo ===========================
echo.

REM Check if Docker is available
docker --version > nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Docker not found. Please install Docker Desktop with Windows containers.
    goto :end
)

REM Check if Windows containers are enabled
docker info | findstr "windows" > nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Windows containers not enabled. Please switch Docker Desktop to Windows containers.
    echo Right-click the Docker icon in the system tray and select "Switch to Windows containers..."
    goto :end
)

REM Check if executable exists
if not exist "dist\*.exe" (
    echo ERROR: No executable found in the dist directory.
    echo Please build the executable first using PyInstaller or the build scripts.
    goto :end
)

echo Building Docker test container...
echo This may take several minutes for the first build.
echo.

REM Build the Windows container
docker build -t truefa-py-docker-test -f dev-tools\docker\Dockerfile.windows .
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Failed to build the Docker container. See above for errors.
    goto :end
)

echo.
echo Container built successfully!
echo.
echo Running the container to test the TrueFA-Py executable...
echo.

REM Run the container (remove it if it already exists)
docker rm -f truefa-py-test > nul 2>&1
docker run --name truefa-py-test truefa-py-docker-test

echo.
echo Test completed.
echo.
echo To inspect the container further, you can:
echo - Run 'docker exec -it truefa-py-test powershell' to open a PowerShell prompt
echo - Run 'docker cp truefa-py-test:C:\Users\testuser\.truefa .' to copy the .truefa directory

:end
pause
