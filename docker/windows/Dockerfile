# escape=`
# TrueFA Windows Docker Test Environment
# This container is used to test the TrueFA-Py executable in a clean Windows environment

FROM mcr.microsoft.com/windows/servercore:ltsc2022

SHELL ["cmd", "/S", "/C"]

# Install Visual C++ Redistributable (required for many Python C extensions and Rust DLLs)
ADD https://aka.ms/vs/17/release/vc_redist.x64.exe C:/vc_redist.x64.exe
RUN C:/vc_redist.x64.exe /install /quiet /norestart

# Setup a testing environment
RUN mkdir C:\TrueFA
RUN mkdir C:\TrueFA\images
RUN mkdir C:\vault_data

# Copy the TrueFA executable and associated files
COPY dist\TrueFA-Py.exe C:\TrueFA\
COPY dist\TrueFA-Py_Setup_0.1.0.exe C:\TrueFA\
COPY truefa_crypto\truefa_crypto.dll C:\TrueFA\
COPY images C:\TrueFA\images
COPY docker\windows\verify_crypto.ps1 C:\TrueFA\

# Add TrueFA to the PATH for easy access
RUN setx /M PATH "%PATH%;C:\TrueFA"

# Set the working directory
WORKDIR C:\TrueFA

# Keep the container running in interactive mode with instructions
CMD ["cmd", "/k", "echo TrueFA Test Environment && echo. && echo To verify the crypto module: powershell -ExecutionPolicy Bypass -File C:\\TrueFA\\verify_crypto.ps1 && echo. && echo Run TrueFA-Py.exe to start the application && echo Use TrueFA-Py.exe --vault-dir C:\\vault_data to use persistent storage && echo Type 'TrueFA-Py_Setup_0.1.0.exe /S' to run the installer in silent mode && echo Type 'exit' when done testing to close the container && echo."] 