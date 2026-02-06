@echo off
:: Update Disabler - Disables Windows Update
echo [SO] Disabling Windows Update Services...

net stop wuauserv >nul 2>&1
sc config wuauserv start= disabled >nul 2>&1
net stop bits >nul 2>&1
sc config bits start= disabled >nul 2>&1
net stop dosvc >nul 2>&1
sc config dosvc start= disabled >nul 2>&1

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoUpdate /t REG_DWORD /d 1 /f >nul 2>&1

echo [SO] Updates Disabled.
pause
