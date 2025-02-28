@echo off
echo Testing TrueFA with QR code scanning...

REM Start the application and feed it inputs
(
echo 1
ping -n 2 127.0.0.1 > nul
echo assets\qrtest.png
) | dist\truefa.exe
