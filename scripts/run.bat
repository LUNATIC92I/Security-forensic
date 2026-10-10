@echo off
REM Launch LUNATIC MOBILE FORENSICS (GUI). Use "run.bat cli <args>" for the command line.
cd /d "%~dp0\.."
if exist .venv\Scripts\activate.bat call .venv\Scripts\activate.bat
if "%1"=="cli" (
  shift
  python -m lunatic_forensics %*
) else (
  python -m lunatic_forensics gui
)
