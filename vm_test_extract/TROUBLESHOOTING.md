# TrueFA-Py Executable Troubleshooting

If you encounter issues running TrueFA-Py from this directory, try the following solutions:

## Common Issues and Solutions

### "Could not load PyInstaller's embedded PKG archive from the executable"

This error occurs when a PyInstaller executable is moved from its original build location.

Solutions:
1. Use the launcher script (launch_test.bat) which runs the executable from its original location
2. Copy the entire dist folder instead of just the executable
3. Rebuild the application in portable mode

### "DLL not found" or "The application was unable to start correctly"

This error indicates missing dependencies.

Solutions:
1. Ensure Visual C++ Redistributable 2015-2022 is installed (run setup.bat as Administrator)
2. Check if any antivirus software is blocking the application
3. Try running as Administrator the first time

### Vault Access Issues

Solutions:
1. Use the --portable flag or set TRUEFA_PORTABLE=1 environment variable to store data in the application directory
2. Check folder permissions in %USERPROFILE%\.truefa

## For VM Testing

When testing in a VM, use the following steps:
1. Extract the entire VM test package to the VM
2. Run setup.bat as Administrator
3. Run TrueFA-Py.bat to start the application

## Building from Source

If you need to rebuild the application:
1. Run prepare_vm_test.ps1 in the project root directory
2. Use the newly created ZIP package for testing
