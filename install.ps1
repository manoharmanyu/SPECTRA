# ==============================================================================
# SPECTRA - Windows PowerShell Installer
# Truth Beyond Appearance - Digital Media Forensics & Secure Device Pairing
# ==============================================================================

Write-Host ""
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "  SPECTRA - Digital Media Forensics & Secure Device Pairing" -ForegroundColor Cyan
Write-Host "  PowerShell Universal Setup Engine for Windows" -ForegroundColor Magenta
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host ""

# 1. Check for Node.js
if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
    Write-Host "[ERROR] Node.js is not installed or not in your PATH." -ForegroundColor Red
    Write-Host "Please download and install Node.js (v18 or newer) from: https://nodejs.org/" -ForegroundColor Yellow
    Exit 1
}

# 2. Check for npm
if (-not (Get-Command npm -ErrorAction SilentlyContinue)) {
    Write-Host "[ERROR] npm is not installed or not in your PATH." -ForegroundColor Red
    Exit 1
}

$nodeVer = (node -v).Trim()
Write-Host "[INFO] Detected Node.js runtime: $nodeVer" -ForegroundColor Green
Write-Host "[INFO] Launching SPECTRA Universal Setup Engine..." -ForegroundColor Cyan
Write-Host ""

# 3. Execute setup.js
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Push-Location $scriptDir

try {
    node setup.js $args
    if ($LASTEXITCODE -ne 0) {
        Write-Host ""
        Write-Host "[ERROR] SPECTRA setup failed with exit code $LASTEXITCODE." -ForegroundColor Red
        Exit $LASTEXITCODE
    }
}
finally {
    Pop-Location
}
