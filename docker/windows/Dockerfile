# escape=`
# TrueFA Windows Docker Test Environment
# This container is used to test the TrueFA-Py executable in a clean Windows environment

FROM mcr.microsoft.com/windows/servercore:ltsc2022

SHELL ["cmd", "/S", "/C"]

# Install Visual C++ Redistributable (required for many Python C extensions)
ADD https://aka.ms/vs/17/release/vc_redist.x64.exe C:/vc_redist.x64.exe
RUN C:/vc_redist.x64.exe /install /quiet /norestart

# Setup a simple user environment
RUN mkdir C:\TrueFA

# Copy the TrueFA executable and associated files
COPY dist\TrueFA-Py.exe C:\TrueFA\
COPY images C:\TrueFA\images

# Add TrueFA to the PATH for easy access
RUN setx /M PATH "%PATH%;C:\TrueFA"

# Set the working directory to a simple location
WORKDIR C:\

# Keep the container running in interactive mode
CMD ["cmd", "/k", "echo TrueFA Test Environment && echo. && echo Just run TrueFA-Py.exe to start the application && echo Type 'exit' when done testing to close the container && echo."] 