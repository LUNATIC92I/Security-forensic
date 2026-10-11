# Build the one-file Windows executable locally (run on Windows), then self-test it.
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")
py -3 -m pip install ".[build]"
py -3 -m PyInstaller --noconfirm packaging\lunatic_forensics.spec
$p = Start-Process -FilePath "dist\LunaticMobileForensics.exe" -ArgumentList "self-test","--output","selftest.txt" -Wait -PassThru
Get-Content selftest.txt
if ($p.ExitCode -ne 0) { throw "Self-test failed" }
Get-FileHash dist\LunaticMobileForensics.exe -Algorithm SHA256
Write-Host "Ready: dist\LunaticMobileForensics.exe (double-click to start)"
