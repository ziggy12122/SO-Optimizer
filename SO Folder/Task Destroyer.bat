@echo off
:: Task Destroyer - Removes Telemetry & Bloatware Scheduled Tasks
:: SAFE VERSION: Does not delete critical system tasks.
echo [SO] Destroying Telemetry & Bloat Tasks...

:: Helper to disable silently
set "dis=schtasks /Change /Disable /TN"

:: Telemetry
%dis% "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator" >nul 2>&1
%dis% "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" >nul 2>&1
%dis% "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" >nul 2>&1
%dis% "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" >nul 2>&1
%dis% "\Microsoft\Windows\Application Experience\ProgramDataUpdater" >nul 2>&1
%dis% "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" >nul 2>&1
%dis% "\Microsoft\Windows\Feedback\Siuf\DmClient" >nul 2>&1
%dis% "\Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" >nul 2>&1
%dis% "\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" >nul 2>&1
%dis% "\Microsoft\Windows\Windows Error Reporting\QueueReporting" >nul 2>&1

:: Maps & Location
%dis% "\Microsoft\Windows\Maps\MapsUpdateTask" >nul 2>&1
%dis% "\Microsoft\Windows\Maps\MapsToastTask" >nul 2>&1

:: Xbl (Xbox) - Only disable if you don't use Xbox features, but we will leave them enabled by default for compatibility as requested.
:: %dis% "\Microsoft\XblGameSave\XblGameSaveTask" >nul 2>&1

echo [SO] Task Destruction Complete.
pause
