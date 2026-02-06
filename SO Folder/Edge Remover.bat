@echo off
:: Edge Remover
:: Requires setup.exe from Edge installer in the same folder
echo [SO] Attempting to remove Microsoft Edge...
if exist "%~dp0setup.exe" (
    "%~dp0setup.exe" --uninstall --system-level --verbose-logging --force-uninstall
    echo [SO] Edge removal command executed.
) else (
    echo [ERROR] setup.exe not found in %~dp0
    echo Please place the Edge Setup executable in this folder.
)
pause
