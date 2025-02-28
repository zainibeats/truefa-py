@echo off
REM TrueFA Packaging Script
echo TrueFA Packaging Tool
echo ====================
echo.

REM Create release directory
set RELEASE_DIR=release
echo Creating release directory: %RELEASE_DIR%...
if not exist %RELEASE_DIR% mkdir %RELEASE_DIR%

REM Copy executables and their dependencies
echo Copying TrueFA executable files...
xcopy /E /I /Y dist\truefa %RELEASE_DIR%\truefa

REM Copy sample QR codes
echo Copying sample QR code images...
if not exist %RELEASE_DIR%\truefa\images mkdir %RELEASE_DIR%\truefa\images
if exist images\*.* xcopy /Y images\*.* %RELEASE_DIR%\truefa\images\

REM Create README file
echo Creating README file...
set README=%RELEASE_DIR%\README.txt
echo TrueFA - Two-Factor Authentication Tool > %README%
echo =================================== >> %README%
echo. >> %README%
echo This package contains TrueFA, a tool for secure two-factor authentication: >> %README%
echo. >> %README%
echo truefa\truefa.exe - Two-factor authentication tool >> %README%
echo. >> %README%
echo Usage: >> %README%
echo ------ >> %README%
echo 1. Run the TrueFA application >> %README%
echo 2. Choose option 1 to load a QR code image >> %README%
echo 3. Enter the path to your QR code image (can be placed in the 'images' directory) >> %README%
echo 4. Follow the on-screen instructions >> %README%
echo. >> %README%
echo Note: This application uses OpenCV for QR code scanning and includes >> %README%
echo a fallback implementation for secure memory handling. >> %README%

echo.
echo Packaging complete! The release is available in the '%RELEASE_DIR%' directory.
echo.
