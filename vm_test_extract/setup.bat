@echo off
echo TrueFA-Py Setup
echo ==============
echo.
echo This script will install the required dependencies for TrueFA-Py.
echo.

:: Check if running with admin privileges
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Please run this script as Administrator.
    echo Right-click on setup.bat and select "Run as administrator".
    echo.
    pause
    exit /b 1
)

echo Installing Visual C++ Redistributable...
echo.
start /wait "%~dp0dependencies\VC_redist.x64.exe" /install /quiet /norestart

echo.
echo Setup complete!
echo You can now run TrueFA-Py.bat to start the application.
echo.
pause
