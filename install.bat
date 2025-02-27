@echo off
echo TrueFA Installation Script
echo.

REM Check if Python is installed
python --version > nul 2>&1
if errorlevel 1 (
    echo Error: Python is not installed or not in PATH
    echo Please install Python 3.8 or later from python.org
    pause
    exit /b 1
)

REM Check if Rust/Cargo is installed
cargo --version > nul 2>&1
if errorlevel 1 (
    echo Error: Rust is not installed or not in PATH
    echo Please install Rust from rustup.rs
    pause
    exit /b 1
)

REM Run the setup script
echo Running setup script...
python setup.py
if errorlevel 1 (
    echo.
    echo Installation failed. Please check the error messages above.
    pause
    exit /b 1
)

echo.
echo Installation completed successfully!
echo.
echo You can now:
echo 1. Run the program directly with: python src/main_opencv.py
echo 2. Build the executable with: pyinstaller TrueFA.spec
echo.
pause 