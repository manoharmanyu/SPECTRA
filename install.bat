@echo off
setlocal enabledelayedexpansion

title SPECTRA - Cross-Platform Installer (Windows)

echo.
echo ======================================================================
echo   SPECTRA - Truth Beyond Appearance
echo   Digital Media Forensics ^& Secure Device Pairing
echo ======================================================================
echo.

REM 1. Verify Node.js is installed
where node >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] Node.js is not found in your system PATH.
    echo Please download and install Node.js (version 18 or newer) from:
    echo   https://nodejs.org/
    echo.
    pause
    exit /b 1
)

REM 2. Verify npm is installed
where npm >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] npm is not found in your system PATH.
    echo Please reinstall Node.js with npm included.
    echo.
    pause
    exit /b 1
)

echo [INFO] Node.js and npm verified.
echo [INFO] Launching SPECTRA Universal Setup Engine...
echo.

REM 3. Run the universal setup script
node setup.js

if %errorlevel% neq 0 (
    echo.
    echo [ERROR] SPECTRA setup encountered an error.
    echo Review the logs above for troubleshooting.
    echo.
    pause
    exit /b %errorlevel%
)

echo.
echo Setup finished successfully.
pause
