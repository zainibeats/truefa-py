# TrueFA-Py Windows Testing Guide

## Overview
This package contains everything needed to test TrueFA-Py on a fresh Windows installation.

## Quick Start
1. Run windows_compatibility_check.ps1 to verify your system meets the requirements
2. Run install_dependencies.ps1 if any dependencies are missing
3. Launch the application using TrueFA-Py-Launcher.bat

## Testing Steps

### 1. System Compatibility Check
`
powershell -ExecutionPolicy Bypass -File .\windows_compatibility_check.ps1
`
This script will check if your system has all required components:
- Windows 10 or higher
- Visual C++ Redistributable 2015-2022
- Required DLLs

### 2. Install Dependencies (if needed)
`
powershell -ExecutionPolicy Bypass -File .\install_dependencies.ps1
`
This script will help you install missing dependencies:
- Visual C++ Redistributable 2015-2022
- Python 3.10 embeddable package for required DLLs

### 3. Launch TrueFA-Py
`
.\TrueFA-Py-Launcher.bat
`
The launcher ensures all dependencies are properly loaded.

### 4. Report Issues
If you encounter any issues, please document:
- Operating system version
- Steps to reproduce the issue
- Any error messages displayed
- Screenshots if applicable

## Common Issues and Solutions

### Application Crashes Immediately
- Try running with the launcher batch file instead of directly
- Make sure Visual C++ Redistributable is installed
- Check if Python DLLs are properly located

### Permission Issues
- The application may need to write to specific directories
- By default it uses the portable mode to store data locally

### Missing or Corrupt Files
- Redownload the test package
- Verify all files are present
