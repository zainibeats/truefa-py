@echo off
echo TrueFA-Py VM Test Launcher
echo ======================
echo.

:: Set environment variables for portable mode
set TRUEFA_PORTABLE=1
set TRUEFA_HOME=%~dp0data
set TRUEFA_CONFIG=%~dp0config.json

:: Run the application
echo Running TrueFA-Py...
"%~dp0TrueFA-Py.exe" %*

echo.
pause
