@echo off
:: Process Destroyer - Kills unwanted processes and disables services
:: SAFE MODE: Suppresses errors if process is not running.
echo [SO] Destroying Unwanted Processes...

:: Helper function to kill silently
set "kill=taskkill /F /T /IM"

%kill% "OneDrive.exe" >nul 2>&1
%kill% "Skype.exe" >nul 2>&1
%kill% "Teams.exe" >nul 2>&1
%kill% "Cortana.exe" >nul 2>&1
%kill% "SearchApp.exe" >nul 2>&1
%kill% "YourPhone.exe" >nul 2>&1
%kill% "Widgets.exe" >nul 2>&1
%kill% "MicrosoftEdgeUpdate.exe" >nul 2>&1

echo [SO] Process Destruction Complete.
pause
