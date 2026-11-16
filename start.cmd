@echo off
setlocal
cd /d "%~dp0"
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%~dp0bootstrap.ps1" start
if errorlevel 1 (
  echo.
  echo Startup failed. Follow README and docs before retrying. No service was installed.
  pause
)
