# Installation script (Windows PowerShell)
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")
py -3 -c "import sys; assert sys.version_info >= (3, 11), 'Python 3.11+ required'"
py -3 -m venv .venv
& .\.venv\Scripts\python.exe -m pip install --upgrade pip
& .\.venv\Scripts\python.exe -m pip install -e ".[api,dev]"
Write-Host "Installed. Run scripts\run.bat (GUI) or .venv\Scripts\python -m pytest"
Write-Host "Recommended: setx LUNATIC_MASTER_PASSPHRASE <passphrase> and enable BitLocker on the data volume."
