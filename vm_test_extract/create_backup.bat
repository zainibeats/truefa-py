@echo off
echo TrueFA-Py VM Backup Creator
echo =======================
echo.

:: Create backup directory
if not exist "%~dp0backups" mkdir "%~dp0backups"

:: Get current date and time for backup name
for /f "tokens=2 delims==" %%a in ('wmic OS Get localdatetime /value') do set dt=%%a
set backupname=TrueFA-Backup-%dt:~0,8%-%dt:~8,6%

:: Create backup
echo Creating backup in %~dp0backups\%backupname%...
mkdir "%~dp0backups\%backupname%"

:: Only backup the data folder, not the executable
if exist "%~dp0data" xcopy /E /I /Y "%~dp0data" "%~dp0backups\%backupname%\data"

echo.
echo Backup created successfully at: %~dp0backups\%backupname%
echo.
pause
