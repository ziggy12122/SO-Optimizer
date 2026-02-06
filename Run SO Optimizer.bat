@echo off
:: SO Optimizer Launcher
:: Automatically elevates to Administrator and runs the PowerShell script

cd /d "%~dp0"

:: Check for Admin
net session >nul 2>&1
if %errorLevel% == 0 (
    goto :RunScript
) else (
    echo [SO] Requesting Administrator Privileges...
    goto :GetAdmin
)

:GetAdmin
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
    echo UAC.ShellExecute "cmd.exe", "/c ""%~s0""", "", "runas", 1 >> "%temp%\getadmin.vbs"
    "%temp%\getadmin.vbs"
    del "%temp%\getadmin.vbs"
    exit /B

:RunScript
    echo [SO] Launching Optimizer...
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File "SO Optimizer.ps1"
    
    if %errorLevel% neq 0 (
        echo.
        echo [ERROR] The script failed to launch.
        echo Please ensure you have PowerShell installed and 'SO Optimizer.ps1' is in this folder.
        pause
    )
