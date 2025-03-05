@echo off
REM TrueFA-Py Enhanced Launcher
REM This script ensures proper DLL paths and environment are set before launching the application

echo TrueFA-Py Launcher
echo =================
echo.

REM Set portable mode to avoid permission issues
set "TRUEFA_PORTABLE=1"

REM Check if we have the python-embed directory
if exist "%~dp0python-embed" (
    echo Found Python Embed directory
    REM Add python-embed directory to PATH temporarily
    set "PATH=%~dp0python-embed;%PATH%"
) else (
    echo Python Embed directory not found
    echo This may cause the application to fail if Python DLLs are missing
)

REM Check for the truefa_crypto directory and DLL
if exist "%~dp0truefa_crypto\truefa_crypto.dll" (
    echo Found TrueFA Crypto DLL
    REM Add truefa_crypto directory to PATH
    set "PATH=%~dp0truefa_crypto;%PATH%"
) else (
    echo TrueFA Crypto DLL not found
    echo Using fallback Python crypto implementation
)

REM Check for the executable
if exist "%~dp0dist\TrueFA-Py.exe" (
    echo Found TrueFA-Py executable
    echo Launching application...
    echo.
    
    REM Launch the application
    start "" "%~dp0dist\TrueFA-Py.exe"
) else if exist "%~dp0dist\TrueFA-Py_console.exe" (
    echo Found TrueFA-Py console executable
    echo Launching application...
    echo.
    
    REM Launch the console version
    start "" "%~dp0dist\TrueFA-Py_console.exe"
) else if exist "%~dp0TrueFA-Py.exe" (
    echo Found TrueFA-Py executable in root directory
    echo Launching application...
    echo.
    
    REM Launch the application
    start "" "%~dp0TrueFA-Py.exe"
) else (
    echo ERROR: Could not find TrueFA-Py executable
    echo Please make sure you have built the application
    pause
    exit /b 1
)

echo.
echo Application started. You can close this window.
timeout /t 10
