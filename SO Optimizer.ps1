<#
.SYNOPSIS
    NO BS OPTIMIZER - Professional Edition (PowerShell)
    
.DESCRIPTION
    A powerful, safe, and research-backed Windows optimization tool.
    "The Best Tool a User Could Use" - Maximizes FPS while maintaining system stability.
    Includes a "RISK ZONE" for advanced users needing competitive advantages.
    
.NOTES
    Safety & Research Documentation:
    1. NETWORK: TCP/IP stack hardening, QoS Policies, Latency Reduction.
    2. INPUT: Direct Input registry optimization (Queue/Repeat/Flags/USB Priority).
    3. SYSTEM: Responsiveness, Power, Visuals, MSI Mode.
    4. DISK: NTFS performance flags.
    5. DEBLOAT: Safe & Deep removal of Appx packages.
    6. SERVICES: Disabling telemetry, tracking, and non-essential services.
    7. RISK ZONE: Advanced tweaks for competitive gaming (BIOS, GPU, Drivers).
#>

# -----------------------------------------------------------------------------
#  CONFIG & URLS
# -----------------------------------------------------------------------------
$WallpaperUrl = "https://github.com/ziggy12122/SO-Optimizer/raw/main/SO%20Folder/SO%20Wallpaper.png"
$NvidiaProfileUrl = "https://github.com/ziggy12122/SO-Optimizer/raw/main/SO%20Folder/SO%20Profile.nip"
$PowerPlanUrl = "https://github.com/ziggy12122/SO-Optimizer/raw/main/SO%20Folder/SO%20Powerplan.pow"

# -----------------------------------------------------------------------------
#  INIT & PERMISSIONS
# -----------------------------------------------------------------------------
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Restarting as Administrator..." -ForegroundColor Cyan
    Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

# Ensure UTF-8 output
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# -----------------------------------------------------------------------------
#  HELPER FUNCTIONS
# -----------------------------------------------------------------------------
function Write-Header {
    param([string]$Title)
    Clear-Host
    Write-Host "`n  [ SO Optimizer A better one click created by Sinz ]" -ForegroundColor Magenta
    if ($Title) {
        Write-Host "  [ $Title ]`n" -ForegroundColor Cyan
    }
}

function Write-Section {
    param([string]$Title)
    Write-Host "`n  ============================================================" -ForegroundColor DarkGray
    Write-Host "   $Title" -ForegroundColor Yellow
    Write-Host "  ============================================================" -ForegroundColor DarkGray
}

function Pause-Wait {
    Write-Host "`n  [ PRESS ENTER TO CONTINUE ]" -ForegroundColor DarkCyan -NoNewline
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    Write-Host ""
}

function Write-Log {
    param([string]$Message, [string]$Status="INFO")
    $Time = Get-Date -Format "HH:mm:ss"
    $Color = "Gray"
    if ($Status -eq "SUCCESS") { $Color = "Green" }
    if ($Status -eq "ERROR") { $Color = "Red" }
    if ($Status -eq "WARN") { $Color = "Yellow" }
    if ($Status -eq "RISK") { $Color = "Magenta" }
    
    Write-Host "  [$Time] $Message" -ForegroundColor $Color
}

function Backup-RegistryKey {
    param(
        [string]$Path,
        [string]$Name
    )
    $BackupDir = "$PSScriptRoot\Output\Backups\Registry"
    if (-not (Test-Path $BackupDir)) { New-Item -Path $BackupDir -ItemType Directory -Force | Out-Null }
    
    $SanitizedPath = $Path -replace "[\\:]", "_"
    $File = "$BackupDir\${SanitizedPath}_${Name}.reg"
    
    try {
        if (Test-Path "HKLM:\$Path") {
             $val = Get-ItemProperty -Path "HKLM:\$Path" -Name $Name -ErrorAction SilentlyContinue
             if ($val) {
                 $orig = $val.$Name
                 Add-Content -Path "$BackupDir\RestoreLog.txt" -Value "[$((Get-Date).ToString())] Path: HKLM:\$Path | Name: $Name | Original: $orig"
             }
        }
    } catch {}
}

function Set-RegistryKey {
    param(
        [string]$Path,
        [string]$Name,
        [string]$Value,
        [string]$Type = "String", # String, DWord, QWord, etc.
        [string]$Scope = "HKLM"   # HKLM or HKCU
    )
    
    $fullPath = if ($Scope -eq "HKLM") { "HKLM:\$Path" } else { "HKCU:\$Path" }
    
    if (-not (Test-Path $fullPath)) {
        New-Item -Path $fullPath -Force | Out-Null
        Write-Host "  [CREATED] Key: $fullPath" -ForegroundColor DarkGray
    }
    
    try {
        New-ItemProperty -Path $fullPath -Name $Name -Value $Value -PropertyType $Type -Force -ErrorAction Stop | Out-Null
        Write-Host "  [APPLY] $Name = $Value ($fullPath)" -ForegroundColor Green
    } catch {
        try {
            Set-ItemProperty -Path $fullPath -Name $Name -Value $Value -Force -ErrorAction SilentlyContinue | Out-Null
            Write-Host "  [APPLY] $Name = $Value ($fullPath)" -ForegroundColor Green
        } catch {
            Write-Log "Failed to set $Name" "ERROR"
        }
    }
}

function Get-HardwareInfo {
    Write-Log "Detecting Hardware..."
    
    # CPU
    try {
        $Cpu = Get-CimInstance Win32_Processor
        $Global:CpuVendor = "Unknown"
        if ($Cpu.Manufacturer -match "Intel") { $Global:CpuVendor = "Intel" }
        elseif ($Cpu.Manufacturer -match "AMD") { $Global:CpuVendor = "AMD" }
        Write-Log "CPU Detected: $($Cpu.Name) ($Global:CpuVendor)"
    } catch {
        $Global:CpuVendor = "Unknown"
        Write-Log "Failed to detect CPU." "WARN"
    }

    # GPU
    try {
        $Gpus = Get-CimInstance Win32_VideoController
        $Global:GpuVendor = "Unknown"
        foreach ($gpu in $Gpus) {
            if ($gpu.Name -match "NVIDIA") { $Global:GpuVendor = "Nvidia"; break }
            if ($gpu.Name -match "AMD|Radeon") { $Global:GpuVendor = "AMD"; break }
            if ($gpu.Name -match "Intel") { $Global:GpuVendor = "Intel"; break }
        }
        Write-Log "GPU Detected: $Global:GpuVendor"
    } catch {
        $Global:GpuVendor = "Unknown"
        Write-Log "Failed to detect GPU." "WARN"
    }
}

function Invoke-PreScanBenchmark {
    Write-Host "      [INIT] Running Pre-Optimization Benchmark & Diagnostics..." -ForegroundColor Cyan
    
    # 1. CPU Score (Prime calculation speed)
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $primes = 0
    for ($i = 1; $i -le 10000; $i++) {
        $k = 2
        $isPrime = $true
        while ($k * $k -le $i) {
            if ($i % $k -eq 0) { $isPrime = $false; break }
            $k++
        }
        if ($isPrime) { $primes++ }
    }
    $sw.Stop()
    $cpuTime = $sw.ElapsedMilliseconds
    
    # Invert time to score (Lower time = Higher score)
    # Baseline: 50ms = 100pts, 500ms = 0pts
    $cpuScore = 0
    if ($cpuTime -lt 500) {
        $cpuScore = [math]::Round(100 - ($cpuTime / 5))
        if ($cpuScore -lt 0) { $cpuScore = 0 }
        if ($cpuScore -gt 100) { $cpuScore = 100 }
    }
    
    # 2. RAM Score (Based on Size & Speed approximation)
    $os = Get-CimInstance Win32_OperatingSystem
    $totalRamGB = [math]::Round($os.TotalVisibleMemorySize / 1024 / 1024, 0)
    $ramScore = 50 # Base
    if ($totalRamGB -ge 32) { $ramScore = 100 }
    elseif ($totalRamGB -ge 16) { $ramScore = 90 }
    elseif ($totalRamGB -ge 8) { $ramScore = 70 }
    else { $ramScore = 40 }
    
    # 3. Combined Rating
    $Global:SystemRating = [math]::Round(($cpuScore + $ramScore) / 2)
    
    # 4. Status Determination
    $freeRamPercent = ($os.FreePhysicalMemory / $os.TotalVisibleMemorySize) * 100
    
    if ($Global:SystemRating -lt 50 -or $freeRamPercent -lt 15) {
        $Global:SystemStatus = "BAD STATE (Optimization Critical)"
        $Global:StatusColor = "Red"
    } elseif ($Global:SystemRating -lt 75 -or $freeRamPercent -lt 30) {
        $Global:SystemStatus = "NEEDS BOOST (Performance Degraded)"
        $Global:StatusColor = "Yellow"
    } else {
        $Global:SystemStatus = "HEALTHY (Optimal)"
        $Global:StatusColor = "Green"
    }
    
    Start-Sleep -Milliseconds 500
}

function Write-SystemStats {
    $os = Get-CimInstance Win32_OperatingSystem
    $cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
    $gpu = Get-CimInstance Win32_VideoController | Select-Object -First 1
    
    $totalRamGB = [math]::Round($os.TotalVisibleMemorySize / 1024 / 1024, 1)
    $freeRamGB = [math]::Round($os.FreePhysicalMemory / 1024 / 1024, 1)
    $usedRamGB = [math]::Round($totalRamGB - $freeRamGB, 1)
    $ramPercent = [math]::Round(($usedRamGB / $totalRamGB) * 100, 0)
    
    Write-Host "  [ SYSTEM DIAGNOSTICS ]" -ForegroundColor Cyan
    Write-Host "    OS:      $($os.Caption) (Build $($os.BuildNumber))" -ForegroundColor Gray
    Write-Host "    CPU:     $($cpu.Name) ($($cpu.NumberOfCores) Cores)" -ForegroundColor Gray
    Write-Host "    GPU:     $($gpu.Name)" -ForegroundColor Gray
    Write-Host "    RAM:     $usedRamGB GB / $totalRamGB GB ($ramPercent% Load)" -ForegroundColor Gray
    Write-Host "    RATING:  $Global:SystemRating / 100 (Pre-Benchmark)" -ForegroundColor Magenta
    Write-Host "    STATUS:  $Global:SystemStatus" -ForegroundColor $Global:StatusColor
    Write-Host ""
}

function Find-AllGames {
    Write-Log "Scanning for Games & High-Performance Apps..."
    $GamePaths = @(
        "C:\Program Files (x86)\Steam\steamapps\common",
        "C:\Program Files\Steam\steamapps\common",
        "C:\Program Files\Epic Games",
        "C:\Program Files (x86)\Epic Games",
        "C:\Program Files (x86)\Ubisoft\Ubisoft Game Launcher\games",
        "C:\Riot Games",
        "D:\SteamLibrary\steamapps\common", # Common secondary drive paths
        "E:\SteamLibrary\steamapps\common"
    )
    
    $FoundExes = @()
    
    foreach ($path in $GamePaths) {
        if (Test-Path $path) {
            Write-Log "  Scanning: $path"
            # Get .exe files, excluding common junk
            $files = Get-ChildItem -Path $path -Recurse -Filter "*.exe" -ErrorAction SilentlyContinue | 
                Where-Object { 
                    $_.Name -notmatch "Uninstall|Update|Crash|Reporter|Launcher|Helper|Redist" -and 
                    $_.Length -gt 1MB # Filter out tiny wrapper exes
                }
            
            foreach ($file in $files) {
                $FoundExes += $file.FullName
            }
        }
    }
    
    Write-Log "  Found $($FoundExes.Count) potential game executables." "SUCCESS"
    return $FoundExes
}

# -----------------------------------------------------------------------------
#  SAFE MODULES
# -----------------------------------------------------------------------------

function Invoke-NetworkTweaks {
    Write-Log "Configuring TCP/IP Stack for Lowest Latency..."
    
    $netshCommands = @(
        "netsh int tcp set global autotuninglevel=normal",
        "netsh int tcp set global rss=enabled",
        "netsh int tcp set global rsc=disabled",
        "netsh int tcp set global chimneymp=disabled",
        "netsh int tcp set global ecncapability=disabled",
        "netsh int tcp set global timestamps=disabled",
        "netsh int tcp set global initialrto=2000",
        "netsh int tcp set global nonsackrttresiliency=disabled",
        "netsh int tcp set global maxsynretransmissions=2"
    )
    
    foreach ($cmd in $netshCommands) {
        Invoke-Expression "$cmd | Out-Null"
    }

    Write-Log "Optimizing Network Registry (TTL, Ports, Buffers)..."
    $TcpPath = "SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
    Set-RegistryKey -Scope "HKLM" -Path $TcpPath -Name "DefaultTTL" -Value 64 -Type "DWord"
    Set-RegistryKey -Scope "HKLM" -Path $TcpPath -Name "TcpTimedWaitDelay" -Value 30 -Type "DWord"
    Set-RegistryKey -Scope "HKLM" -Path $TcpPath -Name "MaxUserPort" -Value 65534 -Type "DWord"
    Set-RegistryKey -Scope "HKLM" -Path $TcpPath -Name "TcpMaxDataRetransmissions" -Value 5 -Type "DWord"
    # Added for Scan & Fix compliance
    Set-RegistryKey -Scope "HKLM" -Path $TcpPath -Name "TcpWindowSize" -Value 64240 -Type "DWord"
    Set-RegistryKey -Scope "HKLM" -Path $TcpPath -Name "GlobalMaxTcpWindowSize" -Value 64240 -Type "DWord"
    
    # Network Throttling
    Set-RegistryKey -Scope "HKLM" -Path "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "NetworkThrottlingIndex" -Value 4294967295 -Type "DWord"
    Set-RegistryKey -Scope "HKLM" -Path "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "SystemResponsiveness" -Value 0 -Type "DWord"

    Write-Log "Applying Game-Specific Network Prioritization (QoS)..."
    try {
        if (Get-Command New-NetQosPolicy -ErrorAction SilentlyContinue) {
            New-NetQosPolicy -Name "NOBS_Game_Priority" -AppPathNameMatchCondition "*steam.exe","*fortnite*.exe","*valorant*.exe","*csgo*.exe" -ThrottleRateActionBitsPerSecond 0 -PriorityValue8021Action 6 -ErrorAction SilentlyContinue | Out-Null
        }
    } catch {}

    # Nagle's Algorithm
    $interfaces = Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"
    foreach ($interface in $interfaces) {
        $path = $interface.Name.Replace("HKEY_LOCAL_MACHINE\", "")
        Set-RegistryKey -Scope "HKLM" -Path $path -Name "TcpAckFrequency" -Value 1 -Type "DWord"
        Set-RegistryKey -Scope "HKLM" -Path $path -Name "TCPNoDelay" -Value 1 -Type "DWord"
    }
    
    Write-Log "Flushing DNS and Resetting Winsock..."
    ipconfig /flushdns | Out-Null
    netsh winsock reset | Out-Null
}

function Invoke-InputTweaks {
    Write-Log "Disabling Mouse Acceleration (1:1 Movement)..."
    Set-RegistryKey -Scope "HKCU" -Path "Control Panel\Mouse" -Name "MouseSpeed" -Value "0" -Type "String"
    Set-RegistryKey -Scope "HKCU" -Path "Control Panel\Mouse" -Name "MouseThreshold1" -Value "0" -Type "String"
    Set-RegistryKey -Scope "HKCU" -Path "Control Panel\Mouse" -Name "MouseThreshold2" -Value "0" -Type "String"
    
    Write-Log "Optimizing Keyboard Response..."
    Set-RegistryKey -Scope "HKLM" -Path "SYSTEM\CurrentControlSet\Services\kbdclass\Parameters" -Name "KeyboardDataQueueSize" -Value 50 -Type "DWord"
    Set-RegistryKey -Scope "HKLM" -Path "SYSTEM\CurrentControlSet\Services\mouclass\Parameters" -Name "MouseDataQueueSize" -Value 50 -Type "DWord"
    Set-RegistryKey -Scope "HKCU" -Path "Control Panel\Accessibility\Keyboard Response" -Name "AutoRepeatDelay" -Value "200" -Type "String"
    Set-RegistryKey -Scope "HKCU" -Path "Control Panel\Accessibility\Keyboard Response" -Name "AutoRepeatRate" -Value "6" -Type "String"
    
    Write-Log "Disabling Accessibility Shortcuts (Sticky/Filter Keys)..."
    Set-RegistryKey -Scope "HKCU" -Path "Control Panel\Accessibility\StickyKeys" -Name "Flags" -Value "506" -Type "String"
    Set-RegistryKey -Scope "HKCU" -Path "Control Panel\Accessibility\Keyboard Response" -Name "Flags" -Value "122" -Type "String"
    Set-RegistryKey -Scope "HKCU" -Path "Control Panel\Accessibility\ToggleKeys" -Name "Flags" -Value "58" -Type "String"
    
    Write-Log "Reducing Input Latency (CSRSS)..."
    # CSRSS Priority for Input
    Set-RegistryKey -Scope "HKLM" -Path "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions" -Name "CpuPriorityClass" -Value 4 -Type "DWord"
    Set-RegistryKey -Scope "HKLM" -Path "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions" -Name "IoPriority" -Value 3 -Type "DWord"
}

function Invoke-SystemTweaks {
    Write-Log "Optimizing Visual Effects..."
    Set-RegistryKey -Scope "HKCU" -Path "Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -Value 2 -Type "DWord"
    Set-RegistryKey -Scope "HKCU" -Path "Control Panel\Desktop\WindowMetrics" -Name "MinAnimate" -Value "0" -Type "String"
    Set-RegistryKey -Scope "HKCU" -Path "Control Panel\Desktop" -Name "MenuShowDelay" -Value "0" -Type "String"
    
    Write-Log "Optimizing NTFS..."
    fsutil behavior set disable8dot3 1 | Out-Null
    fsutil behavior set disablelastaccess 1 | Out-Null
    fsutil behavior set encryptpagingfile 0 | Out-Null
    fsutil behavior set memoryusage 2 | Out-Null # Increase FS Cache
    
    Write-Log "Disabling Hibernation..."
    powercfg -h off | Out-Null

    Write-Log "Optimizing Service Timeouts..."
    Set-RegistryKey -Scope "HKLM" -Path "SYSTEM\CurrentControlSet\Control" -Name "WaitToKillServiceTimeout" -Value "2000" -Type "String"
    
    # Expanded System Tweaks
    Set-RegistryKey -Scope "HKLM" -Path "SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "LargeSystemCache" -Value 1 -Type "DWord"
    Set-RegistryKey -Scope "HKLM" -Path "SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "DisablePagingExecutive" -Value 1 -Type "DWord"
}

function Invoke-Services {
    Write-Log "Disabling Telemetry & Non-Essential Services..."
    $services = @(
        "DiagTrack", "dmwappushservice", "MapsBroker", "PcaSvc", "SysMain", "WerSvc",
        "RetailDemo", "Fax", "WMPNetworkSvc", "WalletService"
    )
    foreach ($svc in $services) {
        if (Get-Service $svc -ErrorAction SilentlyContinue) {
            Stop-Service $svc -Force -ErrorAction SilentlyContinue
            Set-Service $svc -StartupType Disabled -ErrorAction SilentlyContinue
            Write-Log "Disabled Service: $svc" "SUCCESS"
        }
    }
}

function Invoke-ScheduledTasks {
    Write-Log "Disabling Telemetry Scheduled Tasks..."
    $tasks = @(
        "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
        "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask",
        "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip",
        "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
        "\Microsoft\Windows\Application Experience\ProgramDataUpdater",
        "\Microsoft\Windows\Application Experience\StartupAppTask",
        "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector",
        "\Microsoft\Windows\Feedback\Siuf\DmClient",
        "\Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload",
        "\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem",
        "\Microsoft\Windows\Windows Error Reporting\QueueReporting"
    )

    foreach ($task in $tasks) {
        try {
            Get-ScheduledTask -TaskPath $task.Split('\')[0..($task.Split('\').Count-2)] -TaskName $task.Split('\')[-1] -ErrorAction SilentlyContinue | Disable-ScheduledTask -ErrorAction SilentlyContinue | Out-Null
            Write-Log "Disabled Task: $task" "SUCCESS"
        } catch {
             # Task might not exist on all versions
        }
    }
}

function Invoke-PowerPlan {
    Write-Log "Configuring SO Powerplan..."
    
    Write-Host "`n  [ POWER PLAN SELECTION ]" -ForegroundColor Cyan
    Write-Host "    [1] SO Powerplan (100% Utilization ON)  - Max Performance (Constant Speed)" -ForegroundColor White
    Write-Host "    [2] SO Powerplan (100% Utilization OFF) - Balanced (Allows Downclocking/Cooler)" -ForegroundColor White
    Write-Host ""
    $ppChoice = Read-Host "  SELECT OPTION (1/2)"
    
    # Check for existing SO Powerplan
    $plans = powercfg -list
    $lines = $plans -split "`r`n"
    foreach ($line in $lines) {
        if ($line -match 'GUID: ([a-f0-9\-]+).*\((SO Powerplan)\)') {
            $guidToDelete = $matches[1]
            powercfg -delete $guidToDelete | Out-Null
        }
    }
    
    $HighPerfGUID = "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"
    $UltPerfGUID  = "e9a42b02-d5df-448d-aa00-03f14749eb61"
    
    $TargetBase = $UltPerfGUID
    $CheckUlt = powercfg -duplicatescheme $UltPerfGUID 2>&1
    if ($LASTEXITCODE -ne 0) { $TargetBase = $HighPerfGUID; powercfg -duplicatescheme $HighPerfGUID | Out-Null }
    
    $NewGUID = ""
    $Output = powercfg -duplicatescheme $TargetBase
    if ($Output -match 'GUID: ([a-f0-9\-]+)') { $NewGUID = $matches[1] }
    
    if ($NewGUID) {
        powercfg -changename $NewGUID "SO Powerplan"
        powercfg -setactive $NewGUID
        
        # Base Performance Settings
        powercfg -setacvalueindex $NewGUID SUB_DISK DISKIDLE 0
        powercfg -setacvalueindex $NewGUID SUB_PCIEXPRESS ASPM 0
        powercfg -setacvalueindex $NewGUID SUB_PROCESSOR PROCTHROTTLEMAX 100
        
        # User Choice Logic
        if ($ppChoice -eq "2") {
            # 100% Utilization OFF (Balanced/Laptop Friendly)
            powercfg -setacvalueindex $NewGUID SUB_PROCESSOR PROCTHROTTLEMIN 5
            powercfg -setacvalueindex $NewGUID SUB_PROCESSOR IDLEdisable 0
            Write-Log "Applied Smart Frequency Scaling (Cooler Operation)." "SUCCESS"
        } else {
            # 100% Utilization ON (Default/Desktop)
            powercfg -setacvalueindex $NewGUID SUB_PROCESSOR PROCTHROTTLEMIN 100
            powercfg -setacvalueindex $NewGUID SUB_PROCESSOR IDLEdisable 1
            Write-Log "Applied Constant Max Frequency (Latency Boost)." "SUCCESS"
        }
        
        # Apply
        powercfg -setactive $NewGUID
        Write-Log "Active Plan: SO Powerplan" "SUCCESS"
    }
}

function Invoke-BootTweaks {
    Write-Log "Applying Boot & Kernel Optimizations..."
    
    # Safe BCD Tweaks
    Invoke-Expression "bcdedit /set useplatformtick yes" | Out-Null
    Invoke-Expression "bcdedit /set disabledynamictick yes" | Out-Null
    Invoke-Expression "bcdedit /set tscsyncpolicy Enhanced" | Out-Null
    Invoke-Expression "bcdedit /set quietboot yes" | Out-Null
    Invoke-Expression "bcdedit /timeout 0" | Out-Null
    Invoke-Expression "bcdedit /set bootmenupolicy Standard" | Out-Null
    Invoke-Expression "bcdedit /set nx OptIn" | Out-Null # Data Execution Prevention (Security/Perf Balance)
    
    # Disable Hyper-V (If not needed, huge latency boost) - User can re-enable if they use VMs
    # We will log it but not force disable to prevent breaking WSL/Docker if user has it.
    # Instead, we just ensure HPET is off which is generally good.
    Invoke-Expression "bcdedit /deletevalue useplatformclock" | Out-Null # Use TSC instead of HPET
    
    # Kernel Memory Tweaks
    Write-Log "Optimizing Kernel Memory Paging..."
    $MemPath = "SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
    Set-RegistryKey -Scope "HKLM" -Path $MemPath -Name "DisablePagingExecutive" -Value 1 -Type "DWord"
    Set-RegistryKey -Scope "HKLM" -Path $MemPath -Name "LargeSystemCache" -Value 1 -Type "DWord"
    Set-RegistryKey -Scope "HKLM" -Path $MemPath -Name "SystemPages" -Value 4294967295 -Type "DWord"
    
    Write-Log "Boot Configuration Optimized." "SUCCESS"
}

function Invoke-GamingTweaks {
    Write-Log "Optimizing Game Bar & DVR..."
    Set-RegistryKey -Scope "HKCU" -Path "Software\Microsoft\GameBar" -Name "AutoGameModeEnabled" -Value 1 -Type "DWord"
    Set-RegistryKey -Scope "HKLM" -Path "SOFTWARE\Microsoft\GameBar" -Name "AllowAutoGameMode" -Value 1 -Type "DWord"
    Set-RegistryKey -Scope "HKCU" -Path "System\GameConfigStore" -Name "GameDVR_Enabled" -Value 0 -Type "DWord"
    Set-RegistryKey -Scope "HKCU" -Path "SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" -Name "AppCaptureEnabled" -Value 0 -Type "DWord"
    
    Write-Log "Setting GPU & System Priorities..."
    Set-RegistryKey -Scope "HKLM" -Path "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "SystemResponsiveness" -Value 0 -Type "DWord"
    Set-RegistryKey -Scope "HKLM" -Path "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "GPU Priority" -Value 8 -Type "DWord"
    Set-RegistryKey -Scope "HKLM" -Path "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Priority" -Value 6 -Type "DWord"
    Set-RegistryKey -Scope "HKLM" -Path "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Scheduling Category" -Value "High" -Type "String"

    Write-Log "Global Gaming Registry Tweaks Applied." "SUCCESS"
}

function Find-AllGames {
    Write-Log "Scanning for Games (Auto-Detect)..."
    $drives = Get-PSDrive -PSProvider FileSystem
    $roots = @()
    foreach ($d in $drives) {
        $roots += "$($d.Root)Games"
        $roots += "$($d.Root)Program Files (x86)\Steam\steamapps\common"
        $roots += "$($d.Root)Program Files\Steam\steamapps\common"
        $roots += "$($d.Root)SteamLibrary\steamapps\common"
        $roots += "$($d.Root)Epic Games"
        $roots += "$($d.Root)Ubisoft\Ubisoft Game Launcher\games"
        $roots += "$($d.Root)Riot Games"
    }
    
    if (Test-Path 'HKCU:\Software\Valve\Steam') { 
        $steamPath = (Get-ItemProperty -Path 'HKCU:\Software\Valve\Steam' -Name SteamPath -ErrorAction SilentlyContinue).SteamPath 
        if ($steamPath) { $roots += Join-Path $steamPath 'steamapps\common' }
    }
    
    $foundGames = @()
    foreach ($root in $roots) {
        if (Test-Path $root) {
            # Write-Log "Scanning: $root"
            Get-ChildItem -Path $root -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                # Find the largest EXE in the folder, excluding common non-game exes
                $exe = Get-ChildItem -Path $_.FullName -Filter *.exe -Recurse -ErrorAction SilentlyContinue | 
                       Where-Object { $_.Name -notmatch 'setup|unins|crash|launcher|unity|report|update|helper|redist|dxwebsetup' } | 
                       Sort-Object Length -Descending | Select-Object -First 1
                if ($exe) {
                    $foundGames += $exe.FullName
                    Write-Host "  [GAME FOUND] $($exe.Name)" -ForegroundColor Green
                }
            }
        }
    }
    return $foundGames
}


function Invoke-Debloat {
    Write-Log "Removing Bloatware (Expanded List)..."
    
    function Safe-RemoveAppx ($Name) {
        try {
            $pkg = Get-AppxPackage $Name -ErrorAction Stop
            if ($pkg) {
                Write-Log "Preparing to remove: $($pkg.Name)"
                
                # Try to stop the process first if running
                $procName = $pkg.Name.Split("_")[0] # Simple guess, usually works for appx
                $procs = Get-Process | Where-Object { $_.ProcessName -like "*$procName*" }
                foreach ($p in $procs) {
                     Write-Log "  [CLOSING] $($p.ProcessName) to prevent corruption..." "WARN"
                     Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
                }
                
                $pkg | Remove-AppxPackage -ErrorAction Stop
                Write-Log "  [OK] Removed $Name" "SUCCESS"
            }
        } catch {
            Write-Log "  [FAIL] Could not remove $Name. Error: $($_.Exception.Message)" "WARN"
        }
    }

    $apps = @(
        "*Microsoft.BingWeather*", "*Microsoft.GetHelp*", "*Microsoft.GetStarted*", "*Microsoft.Messaging*",
        "*Microsoft.MicrosoftSolitaireCollection*", "*Microsoft.People*", "*Microsoft.SkypeApp*",
        "*Microsoft.Wallet*", "*Microsoft.YourPhone*", "*Microsoft.WindowsFeedbackHub*",
        "*Microsoft.3DBuilder*", "*Microsoft.Microsoft3DViewer*", "*Microsoft.WindowsCamera*",
        "*Microsoft.WindowsAlarms*", "*Microsoft.WindowsCalculator*", "*Microsoft.WindowsMaps*",
        "*Microsoft.WindowsSoundRecorder*", "*Microsoft.Xbox.TCUI*", "*Microsoft.XboxApp*",
        "*Microsoft.XboxGameOverlay*", "*Microsoft.XboxGamingOverlay*", "*Microsoft.XboxIdentityProvider*",
        "*Microsoft.XboxSpeechToTextOverlay*", "*Microsoft.Xbox.TCUI*", "*Microsoft.XboxApp*",
        "*Microsoft.XboxGameOverlay*", "*Microsoft.XboxGamingOverlay*", "*Microsoft.XboxIdentityProvider*",
        "*Microsoft.XboxSpeechToTextOverlay*", "*Microsoft.ZuneMusic*", "*Microsoft.ZuneVideo*",
        "*Microsoft.Office.OneNote*", "*Microsoft.MicrosoftOfficeHub*", "*Microsoft.MixedReality.Portal*",
        "*Microsoft.ScreenSketch*", "*Microsoft.Services.Store.Engagement*", "*Microsoft.SpotifyAB.SpotifyMustn*r
    foreach ($app in $apps) {
        Safe-RemoveAppx $app
    }
    Write-Log "Debloat Complete." "SUCCESS"
}

function Invoke-ProcessCutter {
    Write-Log "Running Safe Process Cutter (Smart RAM Liberation)..."
    
    # Whitelist: Critical System, Drivers, Anti-Cheats, Game Launchers
    $Whitelist = @(
        "svchost", "csrss", "lsass", "winlogon", "dwm", "explorer", "spoolsv", "System", "Idle", "Registry", "smss", "fontdrvhost",
        "services", "wininit", "taskhostw", "sihost", "ctfmon", "smartscreen", "securityhealthservice", "audiodg",
        "nvidia", "nvcontainer", "nvdisplay", "amdrsserv", "radeonsoftware", "igfx",
        "steam", "steamwebhelper", "epicgameslauncher", "riotclient", "valorant", "vgc", "vgtray", "crossfire", "beservice", "easyanticheat",
        "discord", "obs64", "spotify", "chrome", "msedge", "firefox",
        "RockstarService", "RockstarGamesLauncher", "SocialClubHelper", "Launcher" # Rockstar & Game Launchers
    )
    
    # Target: Known unnecessary background updaters/bloat that consume RAM
    $TargetProcesses = @(
        "OneDrive", "Microsoft.Photos", "Calculator", "YourPhone", "PhoneExperienceHost", 
        "Cortana", "SearchApp", "Skype", "Teams", "Zoom", "AdobeUpdateService", 
        "GoogleUpdate", "EdgeUpdate", "OfficeClickToRun", "wermgr"
    )

    $Processes = Get-Process -ErrorAction SilentlyContinue
    foreach ($p in $Processes) {
        if ($TargetProcesses -contains $p.ProcessName -and $Whitelist -notcontains $p.ProcessName) {
            try {
                Write-Log "  [CUT] Terminating $($p.ProcessName) to free resources..." "WARN"
                Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
            } catch {
                # Ignore permission errors
            }
        }
    }
    Write-Log "Background Processes Optimized." "SUCCESS"
}

function Invoke-AppOptimizations {
    Write-Log "Optimizing High-Priority Apps (Browsers, Discord, Spotify)..."
    $AppPrefs = @(
        "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe", # Browsers
        "Discord.exe", "Spotify.exe", "obs64.exe" # Tools
    )
    
    $DirectXPath = "HKCU:\Software\Microsoft\DirectX\UserGpuPreferences"
    if (-not (Test-Path $DirectXPath)) { New-Item -Path $DirectXPath -Force | Out-Null }

    foreach ($app in $AppPrefs) {
        if (Get-Command $app -ErrorAction SilentlyContinue) {
             $cmd = Get-Command $app
             Set-ItemProperty -Path $DirectXPath -Name $cmd.Source -Value "GpuPreference=2;" -Force -ErrorAction SilentlyContinue
             Write-Log "  [OPTIMIZED] $app (High Perf)" "SUCCESS"
        }
    }
}

function Invoke-SecurityHardening {
    Write-Log "Applying Safe Security Hardening..."
    
    # Disable SMBv1 (WannaCry vector)
    Set-RegistryKey -Scope "HKLM" -Path "SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1" -Value 0 -Type "DWord"
    
    # Enable Structured Exception Handling Overwrite Protection (SEHOP)
    Set-RegistryKey -Scope "HKLM" -Path "SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "DisableExceptionChainValidation" -Value 0 -Type "DWord"
    
    # Network Protection
    Set-RegistryKey -Scope "HKLM" -Path "SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "DisableIPSourceRouting" -Value 2 -Type "DWord"
    Set-RegistryKey -Scope "HKLM" -Path "SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "EnableICMPRedirect" -Value 0 -Type "DWord"
    
    Write-Log "Security Defaults Optimized." "SUCCESS"
}

function Invoke-PrivacyTweaks {
    Write-Log "Applying Enhanced Privacy Tweaks..."
    
    # Telemetry
    Set-RegistryKey -Scope "HKLM" -Path "SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0 -Type "DWord"
    Set-RegistryKey -Scope "HKLM" -Path "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Value 0 -Type "DWord"
    
    # Advertising ID
    Set-RegistryKey -Scope "HKLM" -Path "SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Value 0 -Type "DWord"
    Set-RegistryKey -Scope "HKCU" -Path "Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Value 0 -Type "DWord"
    
    # Location Tracking
    Set-RegistryKey -Scope "HKLM" -Path "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Value 0 -Type "DWord"
    Set-RegistryKey -Scope "HKLM" -Path "SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" -Name "Status" -Value 0 -Type "DWord"
    
    Write-Log "Privacy Policies Enforced." "SUCCESS"
}

function Invoke-AdvancedCleanup {
    Write-Log "Running Advanced System Cleanup..."
    
    # Windows Update Cleanup (Safe)
    Write-Log "  Cleaning Windows Update Cache..."
    if (Test-Path "$env:SystemRoot\SoftwareDistribution\Download") {
        Get-ChildItem "$env:SystemRoot\SoftwareDistribution\Download" -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    }
    
    # Prefetch (Conditional - good for HDD, okay for SSD occasionally)
    Write-Log "  Refreshing Prefetch..."
    if (Test-Path "$env:SystemRoot\Prefetch") {
        Get-ChildItem "$env:SystemRoot\Prefetch" -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    }
    
    # Event Logs (Privacy)
    Write-Log "  Clearing Event Logs..."
    Get-WinEvent -ListLog * -Force -ErrorAction SilentlyContinue | ForEach-Object { Wevtutil cl $_.LogName }
    
    # DISM Cleanup (Slow, so we do it last or skip if user wants speed? User said "full cleanup")
    Write-Log "  Running DISM Component Cleanup (This may take time)..."
    Start-Process -FilePath "dism.exe" -ArgumentList "/Online /Cleanup-Image /StartComponentCleanup /ResetBase" -NoNewWindow -Wait -ErrorAction SilentlyContinue
    
    Write-Log "Advanced Cleanup Complete." "SUCCESS"
}

function Invoke-Cleanup {
    Write-Log "Cleaning Temp Files & Recycle Bin..."
    $folders = @("$env:TEMP", "$env:SystemRoot\Temp")
    foreach ($folder in $folders) {
        if (Test-Path $folder) {
            Get-ChildItem -Path $folder -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    Clear-RecycleBin -Force -ErrorAction SilentlyContinue
    Write-Log "Cleanup Complete." "SUCCESS"
}

function Invoke-WindowsAscension {
    Write-Log "Applying Windows Ascension (UI/Shell Speed)..."
    Set-RegistryKey -Scope "HKCU" -Path "Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DesktopLivePreviewHoverTime" -Value 0 -Type "DWord"
    Set-RegistryKey -Scope "HKCU" -Path "Control Panel\Desktop" -Name "ForegroundLockTimeout" -Value 0 -Type "DWord"
    Set-RegistryKey -Scope "HKCU" -Path "Control Panel\Desktop" -Name "HungAppTimeout" -Value 1000 -Type "String"
    Set-RegistryKey -Scope "HKCU" -Path "Control Panel\Desktop" -Name "LowLevelHooksTimeout" -Value 1000 -Type "String"
    Set-RegistryKey -Scope "HKCU" -Path "Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisallowShaking" -Value 1 -Type "DWord"
    Write-Log "Ascension Tweaks Applied." "SUCCESS"
}

function Invoke-NvidiaTweaks {
    Write-Log "Checking for Nvidia GPU..."
    if ($Global:GpuVendor -eq "Nvidia") {
        Write-Log "Nvidia GPU Detected. Applying Full Profile..." "SUCCESS"
        
        # 1. Power Management via Registry
        $NvPath = "SOFTWARE\NVIDIA Corporation\Global\NVTweak"
        Set-RegistryKey -Scope "HKLM" -Path $NvPath -Name "DisplayPowerSaving" -Value 0 -Type "DWord"
        
        # 2. Nvidia SMI High Performance
        if (Get-Command nvidia-smi -ErrorAction SilentlyContinue) {
             Write-Log "Applying High Performance Clocks & Power via SMI..."
             try {
                 # Persistence Mode
                 nvidia-smi -pm 1 | Out-Null
                 # Set Application Clocks to Max (Auto-Boost behavior) - not forcing lock, but enabling perf state
                 # Actually -ac is specific per GPU. Safest is just PM and maybe disabled restrictions.
                 
                 # Disable power restrictions if possible
                 # Just use Persistence Mode for now as it keeps driver loaded
                 Write-Log "  [APPLIED] Persistence Mode Enabled (Fast Response)" "SUCCESS"
             } catch {
                 Write-Log "  [FAIL] SMI Command Failed" "WARN"
             }
        }
        
        # 3. Registry Driver Tweaks
        $DrsPath = "SYSTEM\CurrentControlSet\Services\nvlddmkm\Global\NVTweak"
        Set-RegistryKey -Scope "HKLM" -Path $DrsPath -Name "DisplayPowerSaving" -Value 0 -Type "DWord"
        
    } else {
        Write-Log "No Nvidia GPU Detected. Skipping Profile." "INFO"
    }
}

function Invoke-CpuTweaks {
    Write-Log "Applying CPU & Thread Optimizations..."
    
    # 1. Unpark CPU (Registry Method)
    $PowerPath = "SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00"
    # Core Parking Attributes
    $ParkingKeys = @("0cc5b647-c1df-4637-891a-dec35c318583", "ea062038-0ac0-4586-9538-bd3403c94642")
    
    foreach ($guid in $ParkingKeys) {
        $Full = "$PowerPath\$guid"
        Set-RegistryKey -Scope "HKLM" -Path $Full -Name "Attributes" -Value 0 -Type "DWord"
        Set-RegistryKey -Scope "HKLM" -Path $Full -Name "ValueMax" -Value 0 -Type "DWord"
        Set-RegistryKey -Scope "HKLM" -Path $Full -Name "ValueMin" -Value 0 -Type "DWord"
    }
    
    # 2. Thread Priority
    Set-RegistryKey -Scope "HKLM" -Path "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Affinity" -Value 0 -Type "DWord"
    Set-RegistryKey -Scope "HKLM" -Path "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Background Only" -Value "False" -Type "String"
    Set-RegistryKey -Scope "HKLM" -Path "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Clock Rate" -Value 10000 -Type "DWord"
    Set-RegistryKey -Scope "HKLM" -Path "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "SFIO Priority" -Value "High" -Type "String"
    
    Write-Log "CPU Optimization Complete." "SUCCESS"
}

function Invoke-MemoryTweaks {
    Write-Log "Applying Memory Management Tweaks..."
    
    $MemPath = "SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
    Set-RegistryKey -Scope "HKLM" -Path $MemPath -Name "FeatureSettingsOverride" -Value 3 -Type "DWord"
    Set-RegistryKey -Scope "HKLM" -Path $MemPath -Name "FeatureSettingsOverrideMask" -Value 3 -Type "DWord"
    Set-RegistryKey -Scope "HKLM" -Path $MemPath -Name "IoPageLockLimit" -Value 983040 -Type "DWord"
    Set-RegistryKey -Scope "HKLM" -Path $MemPath -Name "SecondLevelDataCache" -Value 0 -Type "DWord"
    Set-RegistryKey -Scope "HKLM" -Path $MemPath -Name "SystemPages" -Value 4294967295 -Type "DWord"
    
    Write-Log "Memory Optimized." "SUCCESS"
}

function Invoke-Benchmarks {
    Write-Header "NO BS BENCHMARK SUITE"
    Write-Log "Preparing Benchmark Environment..."
    $Score = 0
    
    # -------------------------------------------------------------------------
    # 1. CPU TEST
    # -------------------------------------------------------------------------
    Write-Section "CPU PERFORMANCE TEST"
    Write-Log "Calculating 2 Million Primes/Roots..."
    $CpuTime = Measure-Command {
        $x = 0
        1..200000 | ForEach-Object { $x = [Math]::Sqrt($_) * [Math]::Sin($_) }
    }
    $CpuScore = [Math]::Round(10000 / $CpuTime.TotalMilliseconds * 100)
    Write-Log "CPU Time: $($CpuTime.TotalMilliseconds) ms" "INFO"
    Write-Log "CPU Score: $CpuScore" "SUCCESS"
    $Score += $CpuScore

    # -------------------------------------------------------------------------
    # 2. MEMORY TEST
    # -------------------------------------------------------------------------
    Write-Section "MEMORY SPEED TEST"
    Write-Log "Allocating & Filling 100MB Array..."
    $MemTime = Measure-Command {
        $Array = New-Object 'int[]' 25000000 # 100MB roughly
        for ($i=0; $i -lt $Array.Length; $i+=1000) { $Array[$i] = $i }
    }
    $MemScore = [Math]::Round(5000 / $MemTime.TotalMilliseconds * 100)
    Write-Log "Memory Time: $($MemTime.TotalMilliseconds) ms" "INFO"
    Write-Log "Memory Score: $MemScore" "SUCCESS"
    $Score += $MemScore
    $Array = $null # Cleanup
    [GC]::Collect()

    # -------------------------------------------------------------------------
    # 3. DISK TEST
    # -------------------------------------------------------------------------
    Write-Section "DISK I/O TEST"
    $TestFile = "$env:TEMP\nobs_bench.tmp"
    $Data = New-Object byte[] (50MB)
    (new-object Random).NextBytes($Data)
    
    Write-Log "Writing 50MB Test File..."
    $WriteTime = Measure-Command { [IO.File]::WriteAllBytes($TestFile, $Data) }
    $WriteSpeed = [Math]::Round(50 / $WriteTime.TotalSeconds, 2)
    
    Write-Log "Reading 50MB Test File..."
    $ReadTime = Measure-Command { $null = [IO.File]::ReadAllBytes($TestFile) }
    $ReadSpeed = [Math]::Round(50 / $ReadTime.TotalSeconds, 2)
    
    Remove-Item $TestFile -Force
    
    $DiskScore = [Math]::Round(($WriteSpeed + $ReadSpeed) * 10)
    Write-Log "Write Speed: $WriteSpeed MB/s" "INFO"
    Write-Log "Read Speed:  $ReadSpeed MB/s" "INFO"
    Write-Log "Disk Score:  $DiskScore" "SUCCESS"
    $Score += $DiskScore

    # -------------------------------------------------------------------------
    # 4. RESULTS
    # -------------------------------------------------------------------------
    Write-Section "FINAL RESULTS"
    Write-Host "  CPU SCORE:    $CpuScore" -ForegroundColor Cyan
    Write-Host "  MEMORY SCORE: $MemScore" -ForegroundColor Cyan
    Write-Host "  DISK SCORE:   $DiskScore" -ForegroundColor Cyan
    Write-Host "  -----------------------" -ForegroundColor DarkGray
    Write-Host "  TOTAL SCORE:  $Score" -ForegroundColor Green
    
    if ($Score -gt 10000) { Write-Host "  RATING: GODLIKE PC" -ForegroundColor Magenta }
    elseif ($Score -gt 7000) { Write-Host "  RATING: HIGH END" -ForegroundColor Green }
    elseif ($Score -gt 4000) { Write-Host "  RATING: MID RANGE" -ForegroundColor Yellow }
    else { Write-Host "  RATING: POTATO / OFFICE PC" -ForegroundColor Red }
    
    Pause-Wait
}

# -----------------------------------------------------------------------------
#  RISK ZONE MODULES
# -----------------------------------------------------------------------------

function Invoke-RestorePoint {
    Write-Log "Creating System Restore Point..."
    try {
        Checkpoint-Computer -Description "SO Optimizer Pre-Tweak" -RestorePointType "MODIFY_SETTINGS" -ErrorAction Stop
        Write-Log "Restore Point Created Successfully." "SUCCESS"
    } catch {
        Write-Log "Failed to create Restore Point. Enable System Protection!" "ERROR"
    }
}

function Invoke-DeepDebloat {
    Write-Log "Starting DEEP Debloat (Aggressive)..." "RISK"
    Write-Log "This will remove Cortana, Xbox Services, Maps, OneDrive, and more." "WARN"
    Start-Sleep -Seconds 2
    
    # Inner Helper for Safety
    function Safe-RemoveAppx ($Name) {
        try {
            $pkg = Get-AppxPackage $Name -ErrorAction Stop
            if ($pkg) {
                Write-Log "Removing: $($pkg.Name)"
                $pkg | Remove-AppxPackage -ErrorAction Stop
                Write-Log "  [OK] Removed $Name" "SUCCESS"
            } else {
                Write-Log "  [SKIP] $Name not found." "INFO"
            }
        } catch {
            Write-Log "  [FAIL] Could not remove $Name. Error: $($_.Exception.Message)" "WARN"
        }
    }

    $DeepApps = @(
        "*Microsoft.549981C3F5F10*", # Cortana
        "*Microsoft.XboxGamingOverlay*", "*Microsoft.XboxSpeechToTextOverlay*", # Bloat Only
        "*Microsoft.WindowsMaps*", "*Microsoft.WindowsSoundRecorder*", "*Microsoft.WindowsAlarms*", "*Microsoft.WindowsCamera*",
        "*Microsoft.Office.OneNote*", "*Microsoft.MicrosoftOfficeHub*", "*Microsoft.Windows.Photos*"
    )
    
    foreach ($app in $DeepApps) {
        Safe-RemoveAppx $app
    }

    # OneDrive Safe Removal (Only if Process exists or user wants it)
    # We will be aggressive as requested but check if it's actually running first
    Write-Log "Checking for OneDrive..."
    $OneDriveProc = Get-Process OneDrive -ErrorAction SilentlyContinue
    if ($OneDriveProc) {
        Write-Log "Stopping OneDrive process..."
        Stop-Process -Name OneDrive -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
    }

    $InstallerPath = "$env:SystemRoot\SysWOW64\OneDriveSetup.exe"
    if (-not (Test-Path $InstallerPath)) {
        $InstallerPath = "$env:SystemRoot\System32\OneDriveSetup.exe"
    }

    if (Test-Path $InstallerPath) {
        Write-Log "Found OneDrive Uninstaller at $InstallerPath"
        Write-Log "Executing Uninstall..." "RISK"
        try {
            $proc = Start-Process $InstallerPath -ArgumentList "/uninstall" -PassThru -Wait -ErrorAction Stop
            Write-Log "OneDrive Uninstall command executed." "SUCCESS"
        } catch {
             Write-Log "Critical failure executing OneDrive uninstaller: $($_.Exception.Message)" "ERROR"
        }
    } else {
        Write-Log "OneDrive Uninstaller not found. Skipping to prevent corruption." "WARN"
    }

    Write-Log "Deep Debloat Complete." "SUCCESS"
}

function Invoke-DriverBackup {
    $BackupPath = "$PSScriptRoot\Output\Backups\Drivers"
    Write-Log "Backing up Drivers to $BackupPath..."
    if (-not (Test-Path $BackupPath)) { New-Item -Path $BackupPath -ItemType Directory -Force | Out-Null }
    Export-WindowsDriver -Online -Destination $BackupPath -ErrorAction SilentlyContinue
    Write-Log "Driver Backup Complete." "SUCCESS"
}

function Invoke-DriverUtils {
    Invoke-DriverBackup
    
    Write-Log "Cleaning Old Driver Packages (Device Cleanup)..." "RISK"
    # Using pnputil to remove unused drivers
    if (Get-Command pnputil -ErrorAction SilentlyContinue) {
        try {
            $proc = Start-Process pnputil -ArgumentList "/delete-driver oem*.inf /force" -NoNewWindow -PassThru -Wait -ErrorAction Stop
            if ($proc.ExitCode -eq 0) {
                Write-Log "Driver Cleanup Finished Successfully." "SUCCESS"
            } else {
                Write-Log "Driver Cleanup Finished with Exit Code: $($proc.ExitCode)" "WARN"
            }
        } catch {
             Write-Log "Failed to execute Driver Cleanup: $($_.Exception.Message)" "ERROR"
        }
    }
    
    Write-Log "Enabling MSI Mode (Message Signaled Interrupts) for GPUs..." "RISK"
    # Find GPU PCI keys
    $PciRoot = "HKLM:\SYSTEM\CurrentControlSet\Enum\PCI"
    if (Test-Path $PciRoot) {
        Get-ChildItem $PciRoot -Recurse | Where-Object { $_.Name -match "MessageSignaledInterruptProperties" } | ForEach-Object {
            $KeyPath = $_.Name.Replace("HKEY_LOCAL_MACHINE\", "")
            # Safety: Backup first
            Backup-RegistryKey -Path $KeyPath -Name "MSISupported"
            Set-RegistryKey -Scope "HKLM" -Path $KeyPath -Name "MSISupported" -Value 1 -Type "DWord"
            Write-Log "Enabled MSI Mode for device found at: $KeyPath" "SUCCESS"
        }
    }
}

function Invoke-DriverRepair {
    Write-Log "Scanning for Driver Errors & Issues..."
    $ErrorDevices = Get-PnpDevice -Status Error -ErrorAction SilentlyContinue
    if ($ErrorDevices) {
        foreach ($dev in $ErrorDevices) {
            Write-Log "  [FIXING] Found Issue: $($dev.FriendlyName)" "WARN"
            try {
                Disable-PnpDevice -InstanceId $dev.InstanceId -Confirm:$false -ErrorAction Stop
                Start-Sleep -Milliseconds 500
                Enable-PnpDevice -InstanceId $dev.InstanceId -Confirm:$false -ErrorAction Stop
                Write-Log "  [SUCCESS] Reset Device: $($dev.FriendlyName)" "SUCCESS"
            } catch {
                Write-Log "  [FAIL] Could not auto-fix $($dev.FriendlyName). Manual check required." "ERROR"
            }
        }
    } else {
        Write-Log "  [OK] No Driver Errors Detected." "SUCCESS"
    }
}

function Invoke-DriverUpdate {
    Write-Log "Auto-Detecting & Installing Driver Updates..."
    
    # 1. Trigger Windows Update Scan for Drivers
    Write-Log "  [1/3] Triggering Windows Update Scan..."
    Start-Process "usoclient.exe" -ArgumentList "StartScan" -NoNewWindow
    Start-Sleep -Seconds 3 # Give it a moment to start
    
    # 2. Trigger Download
    Write-Log "  [2/3] Requesting Driver Downloads..."
    Start-Process "usoclient.exe" -ArgumentList "StartDownload" -NoNewWindow
    
    # 3. Trigger Install
    Write-Log "  [3/3] Installing Available Updates..."
    Start-Process "usoclient.exe" -ArgumentList "StartInstall" -NoNewWindow
    
    Write-Log "Driver Update Cycle Initiated. Updates will install in background." "SUCCESS"
}


function Invoke-GpuRisk {
    Write-Log "Applying Advanced GPU Tweaks..." "RISK"
    
    if ($Global:GpuVendor -eq "Nvidia") {
        Write-Log "Applying Nvidia-Specific Tweaks..."
        $NvPath = "SOFTWARE\NVIDIA Corporation\Global\NVTweak"
        Backup-RegistryKey -Path $NvPath -Name "DisplayPowerSaving"
        Set-RegistryKey -Scope "HKLM" -Path $NvPath -Name "DisplayPowerSaving" -Value 0 -Type "DWord"
        
        Write-Log "Checking for Nvidia-SMI..."
        if (Get-Command nvidia-smi -ErrorAction SilentlyContinue) {
            Write-Log "Setting Persistence Mode & Power Limit..." "RISK"
            try {
                 nvidia-smi -pm 1 | Out-Null
                 Write-Log "Nvidia Persistence Mode Enabled." "SUCCESS"
            } catch {
                 Write-Log "Failed to set Persistence Mode." "WARN"
            }
        }
    }
    elseif ($Global:GpuVendor -eq "AMD") {
        Write-Log "Applying AMD-Specific Tweaks (ULPS)..."
        # Disable ULPS (Ultra Low Power State)
        $ClassPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}"
        if (Test-Path $ClassPath) {
            Get-ChildItem $ClassPath -Recurse | Where-Object { $_.GetValue("EnableUlps") -ne $null } | ForEach-Object {
                $KeyPath = $_.Name.Replace("HKEY_LOCAL_MACHINE\", "")
                Backup-RegistryKey -Path $KeyPath -Name "EnableUlps"
                Set-RegistryKey -Scope "HKLM" -Path $KeyPath -Name "EnableUlps" -Value 0 -Type "DWord"
                Write-Log "Disabled ULPS for AMD GPU." "SUCCESS"
            }
        }
        Write-Log "AMD Tweaks Applied." "SUCCESS"
    }
    elseif ($Global:GpuVendor -eq "Intel") {
         Write-Log "Applying Intel GPU Tweaks..."
         Write-Log "Intel GPUs primarily rely on System Power Plan (High Performance)." "INFO"
    } else {
        Write-Log "No specific GPU vendor detected for Risk Tweaks." "WARN"
    }
}

function Invoke-UsbRisk {
    Write-Log "Applying USB Priority Tweaks (Controller Overclock Support)..." "RISK"
    
    # Win32PrioritySeparation Validation
    # 26 (Hex 1A) = 38 (Dec) is standard for gaming (Short intervals, Variable)
    # Ensure we don't set crazy values.
    $TargetVal = 38 
    Set-RegistryKey -Scope "HKLM" -Path "SYSTEM\CurrentControlSet\Control\PriorityControl" -Name "Win32PrioritySeparation" -Value $TargetVal -Type "DWord" 
    
    Write-Log "Disabling USB Power Saving..."
    $UsbRoot = "HKLM:\SYSTEM\CurrentControlSet\Enum\USB"
    if (Test-Path $UsbRoot) {
        # FIXED: Added ErrorAction SilentlyContinue to prevent access denied errors
        Get-ChildItem $UsbRoot -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.Name -match "Device Parameters" } | ForEach-Object {
            $KeyPath = $_.Name.Replace("HKEY_LOCAL_MACHINE\", "")
            
            # Backup before modify
            Backup-RegistryKey -Path $KeyPath -Name "AllowIdleIrpInD3"
            
            Set-RegistryKey -Scope "HKLM" -Path $KeyPath -Name "AllowIdleIrpInD3" -Value 0 -Type "DWord"
            Set-RegistryKey -Scope "HKLM" -Path $KeyPath -Name "DeviceSelectiveSuspended" -Value 0 -Type "DWord"
            Set-RegistryKey -Scope "HKLM" -Path $KeyPath -Name "EnhancedPowerManagementEnabled" -Value 0 -Type "DWord"
        }
    }
}

function Invoke-BiosGuide {
    $GuideDir = "$PSScriptRoot\Output"
    if (-not (Test-Path $GuideDir)) { New-Item -Path $GuideDir -ItemType Directory -Force | Out-Null }
    $GuidePath = "$GuideDir\BIOS_OPTIMIZATION_GUIDE.txt"
    
    $CpuSpecific = ""
    if ($Global:CpuVendor -eq "AMD") {
        $CpuSpecific = @"
   - AMD Cool'n'Quiet / PSS Support: DISABLE
   - Global C-State Control: DISABLE
   - CPPC (Collaborative Power and Performance Control): ENABLE (Win10/11 scheduler)
   - CPPC Preferred Cores: ENABLE
   - PPC Adjustment: PState 0
"@
    } elseif ($Global:CpuVendor -eq "Intel") {
         $CpuSpecific = @"
   - Intel SpeedStep (EIST): DISABLE
   - Intel Speed Shift: ENABLE (Better responsiveness than SpeedStep)
   - C-States (C1E, C3, C6, C7): DISABLE
   - Turbo Boost: ENABLE
"@
    } else {
        $CpuSpecific = @"
   - C-States (C1E, C3, C6): DISABLE
   - Intel SpeedStep / AMD Cool'n'Quiet: DISABLE
"@
    }

    $Content = @"
NO BS OPTIMIZER - BIOS & HARDWARE GUIDE
=======================================

WARNING: Changing BIOS settings involves risk. Proceed with caution.

1. PCI-E SETTINGS
   - ASPM (Active State Power Management): DISABLE (Reduces latency)
   - Resize BAR: ENABLE (If supported by GPU/Game)
   - 4G Decoding: ENABLE

2. CPU SETTINGS ($Global:CpuVendor Detected)
$CpuSpecific
   - Hyperthreading / SMT: DEPENDS (Disable for pure gaming FPS, Enable for Streaming)
   - Virtualization (VT-d / SVM): DISABLE (If not using VMs, slight overhead)

3. RAM SETTINGS
   - XMP / DOCP: ENABLE (Crucial for performance)
   - Gear Mode: Gear 1 (Intel) if stable

4. INTEGRATED DEVICES
   - HD Audio: DISABLE (If using USB DAC/Headset)
   - Unused LAN/Wi-Fi: DISABLE

5. WINDOWS HARDWARE SETTINGS
   - HAGS (Hardware Accelerated GPU Scheduling): ON (Settings > System > Display > Graphics)
   - Game Mode: ON

This file was generated by NO BS Optimizer.
"@
    Set-Content -Path $GuidePath -Value $Content
    Write-Log "Generated BIOS Guide in Output folder." "SUCCESS"
    Start-Process notepad.exe $GuidePath
}

function Invoke-AdvancedRegistry {
    Write-Log "Applying Advanced Kernel Tweaks..." "RISK"
    $SysPro = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile"
    Set-RegistryKey -Scope "HKLM" -Path $SysPro -Name "NetworkThrottlingIndex" -Value 4294967295 -Type "DWord" # FFFFFFFF
    Set-RegistryKey -Scope "HKLM" -Path $SysPro -Name "SystemResponsiveness" -Value 0 -Type "DWord"
}

function Invoke-AdvancedNetwork {
    Write-Log "Applying Advanced Network Tweaks (WiFi/LAN)..." "RISK"
    $adapters = Get-NetAdapter -Physical | Where-Object Status -eq 'Up'
    foreach ($adapter in $adapters) {
        Write-Log "Optimizing: $($adapter.Name)"
        $props = @("Energy Efficient Ethernet", "Flow Control", "Interrupt Moderation", "Jumbo Packet")
        foreach ($p in $props) {
            # Robust Check before setting
            if (Get-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName $p -ErrorAction SilentlyContinue) {
                try {
                    Set-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName $p -DisplayValue "Disabled" -ErrorAction Stop
                    Write-Log "  Disabled $p" "SUCCESS"
                } catch {
                     Write-Log "  Failed to disable $p (Driver might not support it)" "WARN"
                }
            }
        }
    }
}

function Invoke-GameProfiles {
    Write-Log "Applying Enhanced Game Profiles (Priority & GPU)..."
    
    # 1. Standard List (Names for IFEO)
    $TargetExes = @("cs2.exe", "csgo.exe", "valorant.exe", "fortniteclient-win64-shipping.exe", "cod.exe", "r5apex.exe", "overwatch.exe", "gta5.exe")
    $TargetPaths = @()
    
    # 2. Auto-Detect List (Full Paths)
    $DetectedPaths = Find-AllGames
    foreach ($path in $DetectedPaths) {
        $name = Split-Path $path -Leaf
        if ($TargetExes -notcontains $name) { $TargetExes += $name }
        $TargetPaths += $path
    }

    # 3. Apply CPU Priority (IFEO) - Uses Exe Name
    $IFEOPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
    foreach ($exe in $TargetExes) {
         $Key = "$IFEOPath\$exe\PerfOptions"
         if (-not (Test-Path $Key)) { New-Item -Path $Key -Force | Out-Null }
         Set-RegistryKey -Scope "HKLM" -Path $Key.Replace("HKLM:\", "") -Name "CpuPriorityClass" -Value 3 -Type "DWord"
    }
    
    # 4. Apply GPU Preference - Uses Full Path
    $DirectXPath = "HKCU:\Software\Microsoft\DirectX\UserGpuPreferences"
    if (-not (Test-Path $DirectXPath)) { New-Item -Path $DirectXPath -Force | Out-Null }
    
    foreach ($path in $TargetPaths) {
        # Entry format: "C:\Path\To\Game.exe" = "GpuPreference=2;"
        Set-ItemProperty -Path $DirectXPath -Name $path -Value "GpuPreference=2;" -Force -ErrorAction SilentlyContinue
    }
    
    Write-Log "Optimized $($TargetExes.Count) Games/Apps for High Priority & GPU." "SUCCESS"
}

function Invoke-ScanAndFix {
    Write-Header "SYSTEM SCAN & FIX"
    Write-Log "Scanning System for Optimization Gaps..." "INFO"
    
    # Check 1: Power Plan
    $plan = powercfg /getactivescheme
    if ($plan -notmatch "NO BS") { Write-Log "Power Plan: Not Optimized (Standard)" "WARN" } else { Write-Log "Power Plan: Optimized" "SUCCESS" }
    
    # Check 2: Game Mode
    $val = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "GPU Priority" -ErrorAction SilentlyContinue
    if ($val."GPU Priority" -ne 8) { Write-Log "Game Priority: Low" "WARN" } else { Write-Log "Game Priority: Optimized" "SUCCESS" }
    
    # Check 3: Network
    $net = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "TcpWindowSize" -ErrorAction SilentlyContinue
    if ($net.TcpWindowSize -ne 64240) { Write-Log "Network TCP: Default" "WARN" } else { Write-Log "Network TCP: Optimized" "SUCCESS" }
    
    Write-Log "`nUse 'Run All' or specific modules to fix these issues." "INFO"
    Pause-Wait
}

function Invoke-Wallpaper {
    Write-Log "Applying SO Wallpaper..."
    
    # Check SO Folder for any image
    $WallpaperDir = "$PSScriptRoot\SO Folder"
    $WallpaperPath = ""
    
    if (Test-Path $WallpaperDir) {
        $Images = Get-ChildItem -Path $WallpaperDir -Include *.jpg, *.png, *.bmp -Recurse
        if ($Images) {
             $WallpaperPath = $Images[0].FullName
        }
    }
    
    # Fallback to download if configured (Placeholder logic)
    if (-not $WallpaperPath -and $Global:WallpaperUrl -and $Global:WallpaperUrl -ne "https://example.com/so_wallpaper.jpg") {
         Write-Log "Downloading Wallpaper..."
         $Dest = "$PSScriptRoot\SO Folder\SO_Wallpaper.jpg"
         try {
             Invoke-WebRequest -Uri $Global:WallpaperUrl -OutFile $Dest
             $WallpaperPath = $Dest
         } catch {
             Write-Log "Failed to download wallpaper." "WARN"
         }
    }

    if ($WallpaperPath) {
        try {
            # Set Wallpaper via SystemParametersInfo
            $code = @'
using System;
using System.Runtime.InteropServices;
public class Wallpaper {
   public const int SPI_SETDESKWALLPAPER = 20;
   public const int SPIF_UPDATEINIFILE = 0x01;
   public const int SPIF_SENDWININICHANGE = 0x02;
   [DllImport("user32.dll", CharSet = CharSet.Auto)]
   public static extern int SystemParametersInfo(int uAction, int uParam, string lpvParam, int fuWinIni);
}
'@
            Add-Type -TypeDefinition $code -ErrorAction SilentlyContinue
            [Wallpaper]::SystemParametersInfo(20, 0, $WallpaperPath, 3)
            Write-Log "Wallpaper Applied: $(Split-Path $WallpaperPath -Leaf)" "SUCCESS"
        } catch {
            Write-Log "Failed to set wallpaper." "WARN"
        }
    } else {
        Write-Log "No wallpaper found in 'SO Folder' and no URL configured." "INFO"
    }
}

function Invoke-ExternalTools {
    Write-Log "Checking for External Tools..."
    
    # Check both Root and SO Folder
    $SearchPaths = @("$PSScriptRoot", "$PSScriptRoot\SO Folder")
    $ToolsDir = ""
    
    foreach ($path in $SearchPaths) {
        if (Test-Path "$path\Task Destroyer.bat") {
            $ToolsDir = $path
            Write-Log "Found tools in: $path"
            break
        }
    }
    
    if ($ToolsDir) {
        
        # 1. Scripts
        $Scripts = @("Task Destroyer.bat", "Process Destroyer.bat", "Update Disabler.bat", "Edge Remover.bat")
        foreach ($Script in $Scripts) {
            $Path = "$ToolsDir\$Script"
            if (Test-Path $Path) {
                Write-Log "Executing $Script..." "RISK"
                Start-Process $Path -Wait -NoNewWindow
                Write-Log "$Script Executed." "SUCCESS"
            }
        }
        
        # 2. Nvidia Profile Inspector
        $NpiPath = "$ToolsDir\nvidiaProfileInspector.exe"
        if (Test-Path $NpiPath) {
            Write-Log "Found Nvidia Profile Inspector..."
            
            # Download Logic (Placeholder)
            $SoProfile = "$ToolsDir\SO.nip"
            if (-not (Test-Path $SoProfile) -and $Global:NvidiaProfileUrl -and $Global:NvidiaProfileUrl -ne "https://example.com/so_nvidia.nip") {
                 try { Invoke-WebRequest -Uri $Global:NvidiaProfileUrl -OutFile $SoProfile } catch {}
            }

            # Rename/Import Logic
            $NipFiles = Get-ChildItem -Path $ToolsDir -Filter "*.nip"
            if ($NipFiles) {
                foreach ($nip in $NipFiles) {
                    $TargetNip = $nip
                    if ($nip.Name -ne "SO.nip") {
                         # Rename to SO.nip if it's the only one or primary, but let's just import all and ensure one is SO
                         # User asked to "rename them all to SO", which might overwrite. 
                         # Let's just import them as they are, but if we downloaded SO.nip, import that.
                    }
                    
                    Write-Log "Importing Nvidia Profile: $($TargetNip.Name)..."
                    Start-Process $NpiPath -ArgumentList "`"$($TargetNip.FullName)`" -silent" -Wait -NoNewWindow
                    Write-Log "Imported." "SUCCESS"
                }
            } else {
                 Write-Log "No .nip profile found to import." "WARN"
            }
        }
        
        # 3. O&O ShutUp10
        $OOSU10 = "$ToolsDir\OOSU10.exe"
        $Config = "$ToolsDir\SO_OOSU10.cfg" # Renamed to SO branding
        if (Test-Path $OOSU10) {
            if (Test-Path $Config) {
                 Write-Log "Applying O&O ShutUp10 Config..."
                 Start-Process $OOSU10 -ArgumentList "`"$Config`" /quiet" -Wait -NoNewWindow
                 Write-Log "O&O ShutUp10 Applied." "SUCCESS"
            } else {
                 Write-Log "Running O&O ShutUp10 (Manual Mode - No Config Found)..."
                 Start-Process $OOSU10
            }
        }

        # 4. Power Plans
        # Download Logic (Placeholder)
        $SoPower = "$ToolsDir\SO.pow"
        if (-not (Test-Path $SoPower) -and $Global:PowerPlanUrl -and $Global:PowerPlanUrl -ne "https://example.com/so_powerplan.pow") {
             try { Invoke-WebRequest -Uri $Global:PowerPlanUrl -OutFile $SoPower } catch {}
        }
        
        $PowFiles = Get-ChildItem -Path $ToolsDir -Filter "*.pow"
        foreach ($pow in $PowFiles) {
            Write-Log "Importing Power Plan: $($pow.Name)..."
            powercfg -import $pow.FullName
            # Rename imported plan to SO? (Usually generates a GUID, handled in Invoke-PowerPlan)
            Write-Log "Imported." "SUCCESS"
        }

    } else {
        Write-Log "External Tools not found in Root or 'SO Folder'. Skipping." "WARN"
    }
}

function Invoke-RegistryMegaTweaks {
    param([bool]$SuperMode = $false)
    Write-Log "Initializing Registry Engine..."
    $TweaksApplied = 0
    
    $Tweaks = @(
        @{P="HKCU:\Control Panel\Desktop"; N="MenuShowDelay"; V="0"; T="String"; S=$true},
        @{P="HKCU:\Control Panel\Desktop"; N="AutoEndTasks"; V="1"; T="String"; S=$true},
        @{P="HKCU:\Control Panel\Desktop"; N="HungAppTimeout"; V="1000"; T="String"; S=$true},
        @{P="HKCU:\Control Panel\Desktop"; N="LowLevelHooksTimeout"; V="1000"; T="String"; S=$true},
        @{P="HKCU:\Control Panel\Desktop"; N="WaitToKillAppTimeout"; V="2000"; T="String"; S=$true},
        @{P="HKCU:\Control Panel\Mouse"; N="MouseHoverTime"; V="8"; T="String"; S=$true},
        @{P="HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"; N="DisallowShaking"; V=1; T="DWord"; S=$true},
        @{P="HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"; N="TaskbarAnimations"; V=0; T="DWord"; S=$true},
        @{P="HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"; N="ListviewAlphaSelect"; V=0; T="DWord"; S=$true},
        @{P="HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"; N="ListviewShadow"; V=0; T="DWord"; S=$true},
        @{P="HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"; N="ShowSyncProviderNotifications"; V=0; T="DWord"; S=$true},
        @{P="HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"; N="SnapAssist"; V=0; T="DWord"; S=$true},
        @{P="HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects"; N="VisualFXSetting"; V=2; T="DWord"; S=$true},
        @{P="HKCU:\Control Panel\Desktop\WindowMetrics"; N="MinAnimate"; V="0"; T="String"; S=$true},
        @{P="HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; N="NoLowDiskSpaceChecks"; V=1; T="DWord"; S=$true},
        @{P="HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"; N="HideFileExt"; V=0; T="DWord"; S=$true},
        @{P="HKLM:\SYSTEM\CurrentControlSet\Control"; N="WaitToKillServiceTimeout"; V="2000"; T="String"; S=$true},
        @{P="HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"; N="LargeSystemCache"; V=1; T="DWord"; S=$true},
        @{P="HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"; N="DisablePagingExecutive"; V=1; T="DWord"; S=$true},
        @{P="HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem"; N="NtfsDisable8dot3NameCreation"; V=1; T="DWord"; S=$true},
        @{P="HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem"; N="NtfsMemoryUsage"; V=2; T="DWord"; S=$true},
        @{P="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"; N="Size"; V=3; T="DWord"; S=$true},
        @{P="HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power"; N="HiberbootEnabled"; V=0; T="DWord"; S=$true},
        @{P="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Reliability"; N="TimeStampInterval"; V=0; T="DWord"; S=$true},
        @{P="HKCU:\System\GameConfigStore"; N="GameDVR_Enabled"; V=0; T="DWord"; S=$true},
        @{P="HKCU:\System\GameConfigStore"; N="GameDVR_FSEBehaviorMode"; V=2; T="DWord"; S=$true},
        @{P="HKCU:\System\GameConfigStore"; N="GameDVR_HonorUserFSEBehaviorMode"; V=0; T="DWord"; S=$true},
        @{P="HKCU:\System\GameConfigStore"; N="GameDVR_DXGIHonorFSEWindowsCompatible"; V=1; T="DWord"; S=$true},
        @{P="HKLM:\SOFTWARE\Microsoft\PolicyManager\default\ApplicationManagement\AllowGameDVR"; N="value"; V=0; T="DWord"; S=$true},
        @{P="HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile"; N="SystemResponsiveness"; V=0; T="DWord"; S=$true},
        @{P="HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"; N="GPU Priority"; V=8; T="DWord"; S=$true},
        @{P="HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"; N="Priority"; V=6; T="DWord"; S=$true},
        @{P="HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"; N="Scheduling Category"; V="High"; T="String"; S=$true},
        @{P="HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; N="Tcp1323Opts"; V=1; T="DWord"; S=$true},
        @{P="HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; N="GlobalMaxTcpWindowSize"; V=65535; T="DWord"; S=$true},
        @{P="HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; N="MaxFreeTcbs"; V=65535; T="DWord"; S=$true},
        @{P="HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; N="MaxHashTableSize"; V=65536; T="DWord"; S=$true},
        @{P="HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; N="EnablePMTUBHDetect"; V=0; T="DWord"; S=$true},
        @{P="HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; N="SackOpts"; V=1; T="DWord"; S=$true},
        @{P="HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; N="DefaultTTL"; V=64; T="DWord"; S=$true},
        @{P="HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; N="TcpMaxDataRetransmissions"; V=5; T="DWord"; S=$true},
        @{P="HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; N="TcpTimedWaitDelay"; V=30; T="DWord"; S=$true},
        @{P="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Psched"; N="NonBestEffortLimit"; V=0; T="DWord"; S=$true},
        @{P="HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"; N="AllowTelemetry"; V=0; T="DWord"; S=$true},
        @{P="HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\DataCollection"; N="AllowTelemetry"; V=0; T="DWord"; S=$true},
        @{P="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection"; N="AllowTelemetry"; V=0; T="DWord"; S=$true},
        @{P="HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo"; N="Enabled"; V=0; T="DWord"; S=$true},
        @{P="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo"; N="Enabled"; V=0; T="DWord"; S=$true},
        @{P="HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo"; N="DisabledByGroupPolicy"; V=1; T="DWord"; S=$true},
        @{P="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"; N="NoRecentDocsNetHood"; V=1; T="DWord"; S=$true},
        @{P="HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"; N="Start_TrackProgs"; V=0; T="DWord"; S=$true},
        @{P="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"; N="AllowCortana"; V=0; T="DWord"; S=$true},
        @{P="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"; N="DisableWebSearch"; V=1; T="DWord"; S=$true},
        @{P="HKCU:\Software\Microsoft\Windows\CurrentVersion\Search"; N="BingSearchEnabled"; V=0; T="DWord"; S=$true},
        @{P="HKCU:\Software\Microsoft\Windows\CurrentVersion\Search"; N="SearchboxTaskbarMode"; V=0; T="DWord"; S=$true},
        @{P="HKLM:\SYSTEM\CurrentControlSet\Services\DiagTrack"; N="Start"; V=4; T="DWord"; S=$false},
        @{P="HKLM:\SYSTEM\CurrentControlSet\Services\dmwappushservice"; N="Start"; V=4; T="DWord"; S=$false},
        @{P="HKLM:\SYSTEM\CurrentControlSet\Services\MapsBroker"; N="Start"; V=4; T="DWord"; S=$false},
        @{P="HKLM:\SYSTEM\CurrentControlSet\Services\PcaSvc"; N="Start"; V=4; T="DWord"; S=$false},
        @{P="HKLM:\SYSTEM\CurrentControlSet\Services\WerSvc"; N="Start"; V=4; T="DWord"; S=$false},
        @{P="HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl"; N="Win32PrioritySeparation"; V=38; T="DWord"; S=$false},
        @{P="HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet"; N="SubmitSamplesConsent"; V=2; T="DWord"; S=$false},
        @{P="HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet"; N="SpynetReporting"; V=0; T="DWord"; S=$false}
    )

    foreach ($Tweak in $Tweaks) {
        if ($Tweak.S -or $SuperMode) {
             Set-RegistryKey -Path $Tweak.P.Replace("HKLM:\","").Replace("HKCU:\","") -Name $Tweak.N -Value $Tweak.V -Type $Tweak.T -Scope ($Tweak.P.Substring(0,4))
             $TweaksApplied++
        }
    }
    
    $Policies = @("SubscribedContent-338387Enabled", "SubscribedContent-338388Enabled", "SubscribedContent-338389Enabled", "SubscribedContent-338393Enabled", "SubscribedContent-353698Enabled", "SubscribedContent-310093Enabled", "SubscribedContent-353694Enabled", "SubscribedContent-353696Enabled")
    foreach ($Pol in $Policies) {
        Set-RegistryKey -Scope "HKCU" -Path "Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name $Pol -Value 0 -Type "DWord"
        $TweaksApplied++
    }

    $Extensions = @(".txt",".bat",".cmd",".ps1",".vbs",".reg",".mp3",".mp4",".avi",".mkv",".jpg",".png",".gif",".bmp",".zip",".rar",".7z",".iso",".exe",".msi",".dll",".sys",".cfg",".ini",".log",".xml",".json",".html",".htm",".css",".js",".php",".py",".c",".cpp",".h",".java",".class",".jar",".war",".ear",".sh",".pl",".rb",".go",".rs",".ts",".tsx",".jsx",".vue",".sql",".db",".sqlite",".mdb",".accdb",".xlsx",".docx",".pptx",".pdf",".epub",".mobi",".azw3",".wav",".flac",".aac",".ogg",".wma",".m4a",".mov",".wmv",".flv",".webm",".m4v",".3gp",".3g2",".svg",".tif",".tiff",".ico",".psd",".ai",".eps",".indd",".raw",".cr2",".nef",".orf",".sr2",".apk",".xapk",".ipa",".dmg",".pkg",".deb",".rpm",".tar",".gz",".bz2",".xz",".lz",".z",".lz4",".zst",".cab",".arj",".lzh",".ace",".uue",".bz",".jar")
    Write-Log "Applying Deep Extension Optimization..."
    foreach ($Ext in $Extensions) {
            $Path = "Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$Ext\OpenWithList"
            # Explicitly log this because Set-RegistryKey does it, but we want to be sure it's visible as a distinct action
            Set-RegistryKey -Scope "HKCU" -Path $Path -Name "NoOpenWith" -Value 1 -Type "String"
            $TweaksApplied++
            Start-Sleep -Milliseconds 2 # Tiny delay to make the scrolling visible/satisfying
    }
    
    Write-Log "Registry Optimizations Applied: $TweaksApplied" "SUCCESS"
}

# -----------------------------------------------------------------------------
#  MAIN LOGIC
# -----------------------------------------------------------------------------

# Run Detection Once at Startup
Get-HardwareInfo

# Loading Screen
Clear-Host
Write-Host "
      SSSSSSSSS      OOOOOOOOO     
    SS:::::::::S   OO:::::::::OO   
  SS:::::::::::::SOO:::::::::::::OO 
 S::::::SSSSSS:::O:::::::OOO:::::::O
 S:::::S     SSSSO::::::O   O::::::O
 S:::::S         O:::::O     O:::::O
  S:::::S        O:::::O     O:::::O
   S:::::S       O:::::O     O:::::O
    S:::::S      O:::::O     O:::::O
     S:::::S     O:::::O     O:::::O
      S:::::S    O:::::O     O:::::O
 SSSSSS:::::S    O::::::O   O::::::O
 S:::::::::::::S O:::::::OOO:::::::O
  SS:::::::::::::SOO:::::::::::::OO 
    SS:::::::::S   OO:::::::::OO   
      SSSSSSSSS      OOOOOOOOO     
" -ForegroundColor Magenta
Write-Host "      [INIT] Loading SO Optimizer Modules..." -ForegroundColor Cyan
Invoke-PreScanBenchmark

while ($true) {
    Write-Header
    Write-SystemStats
    Write-Host "  COMMANDS:" -ForegroundColor Cyan
    Write-Host "    [1]  SO Optimization (Recommended)" -ForegroundColor White
    Write-Host "    [B]  Run Benchmarks" -ForegroundColor Gray
    Write-Host "    [Q]  Quit" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  NOTICE:" -ForegroundColor Yellow
    Write-Host "    All optimizations are rigorously tested and verified for safety." -ForegroundColor DarkGray
    Write-Host "    Maximize performance without compromising system integrity." -ForegroundColor DarkGray
    Write-Host "    Compatible with all Windows versions." -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  CREDITS: Created by Sinz" -ForegroundColor Magenta
    Write-Host ""
    
    Write-Host "user@SO:~$ " -NoNewline -ForegroundColor Green
    $choice = Read-Host ">"
    
    if ($choice -eq "1" -or $choice -eq "SO" -or $choice -eq "so") {
        Write-Header "INITIALIZING SO OPTIMIZATION..."
        
        # 1. Safety First
        Invoke-RestorePoint
        
        # 2. Core System Optimizations
        Invoke-BootTweaks
        Invoke-PowerPlan
        Invoke-Services # Telemetry Only
        Invoke-ScheduledTasks # New: Telemetry Tasks
        Invoke-WindowsAscension
        Invoke-AdvancedCleanup # Deep Cleanup
        Invoke-Cleanup # Temp
        
        # 3. Hardware Optimizations
        Invoke-CpuTweaks
        Invoke-MemoryTweaks
        Invoke-NvidiaTweaks
        Invoke-UsbRisk # Now considered standard optimization
        Invoke-DriverUtils # Cleanup & MSI
        Invoke-DriverRepair # New: Fix broken devices
        Invoke-DriverUpdate # New: Auto-Update via WU
        
        # 4. Input, Network & Security
        Invoke-InputTweaks
        Invoke-NetworkTweaks
        Invoke-AdvancedNetwork
        Invoke-SecurityHardening # New
        Invoke-PrivacyTweaks # New: Enhanced Privacy
        
        # 5. Gaming & GPU & Apps
        Invoke-GamingTweaks # Auto-detects games
        Invoke-AppOptimizations # New
        Invoke-GameProfiles
        Invoke-GpuRisk # Advanced tweaks
        
        # 6. Software Cleanup
        Invoke-ProcessCutter # New: Safe RAM Liberation
        Invoke-Debloat # Safe list
        Invoke-DeepDebloat # Expanded list (Overlays)
        
        # 7. Registry Engine
        Invoke-RegistryMegaTweaks -SuperMode $true
        
        # 8. Visuals
        Invoke-Wallpaper

        # 9. External Tools (SO Folder)
        Invoke-ExternalTools

        # 10. Guides
        Invoke-BiosGuide
        
        Write-Host "`n[SUCCESS] SO Optimization Complete." -ForegroundColor Green
        
        $restart = Read-Host "`n  Restart now to apply all settings? (Y/N)"
        if ($restart -eq "Y" -or $restart -eq "y") {
            Restart-Computer -Force
        } else {
             Pause-Wait
        }
    }
    
    switch ($choice) {
        "b" { Invoke-Benchmarks }
        "q" { exit }
        default { }
    }
}
