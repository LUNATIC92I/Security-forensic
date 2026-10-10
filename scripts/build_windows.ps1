# Build a standalone Windows executable with PyInstaller (run on Windows).
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")
& .\.venv\Scripts\python.exe -m pip install ".[build]"
& .\.venv\Scripts\python.exe -m PyInstaller --noconfirm packaging\lunatic_forensics.spec
Write-Host "Executable folder: dist\LunaticMobileForensics\  (start LunaticMobileForensics.exe)"
Write-Host "Optional: sign the executable (signtool) and compute its SHA-256 for the lab tool register."
