@echo off
echo Testing TrueFA with manual TOTP setup...

REM Start the application and feed it inputs for manual entry
(
echo 2
ping -n 2 127.0.0.1 > nul
echo RV2URZLXM46UUR4NA54E7Y3JIH2XS3HZ
ping -n 2 127.0.0.1 > nul
echo Test Provider
ping -n 2 127.0.0.1 > nul
echo Test Account
) | dist\truefa.exe
