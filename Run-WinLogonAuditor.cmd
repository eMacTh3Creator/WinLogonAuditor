@echo off
REM WinLogonAuditor launcher - runs the GUI in a single-threaded apartment.
REM Right-click -> "Run as administrator" for full Security-log access.
setlocal
set "PS=powershell.exe"
where pwsh.exe >nul 2>&1 && set "PS=pwsh.exe"
"%PS%" -NoProfile -ExecutionPolicy Bypass -Sta -File "%~dp0src\WinLogonAuditor.ps1" %*
endlocal
