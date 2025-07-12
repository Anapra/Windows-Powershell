# Enhanced Windows System Optimizer - Microsoft Account Transition Fix
# Run as Administrator - Creates restore point automatically

param(
    [switch]$CreateRestorePoint = $true,
    [switch]$SkipReboot = $false
)

# Initialize logging
$LogPath = "$env:TEMP\WindowsOptimizer_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
function Write-Log {
    param($Message, $Color = "White")
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogMessage = "[$Timestamp] $Message"
    Write-Host $LogMessage -ForegroundColor $Color
    Add-Content -Path $LogPath -Value $LogMessage
}

Write-Log "Starting Enhanced Windows Optimization..." "Green"
Write-Log "Log file: $LogPath" "Yellow"

# Check if running as administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Log "This script requires Administrator privileges. Please run as Administrator." "Red"
    exit 1
}

# Create System Restore Point
if ($CreateRestorePoint) {
    try {
        Write-Log "Creating system restore point..." "Yellow"
        Enable-ComputerRestore -Drive "C:\"
        Checkpoint-Computer -Description "Before Windows Optimization" -RestorePointType "MODIFY_SETTINGS"
        Write-Log "System restore point created successfully" "Green"
    }
    catch {
        Write-Log "Warning: Could not create restore point - $($_.Exception.Message)" "Yellow"
    }
}

# =============================================================================
# SECTION 1: Microsoft Account Transition Fixes
# =============================================================================
Write-Log "Fixing Microsoft Account transition issues..." "Cyan"

# Fix user profile synchronization issues
try {
    Write-Log "Resetting user profile sync..."
    Stop-Service -Name "wlidsvc" -Force -ErrorAction SilentlyContinue
    Stop-Service -Name "TokenBroker" -Force -ErrorAction SilentlyContinue
    
    # Clear cached credentials that might be causing conflicts
    cmdkey /list | ForEach-Object {
        if ($_ -like "*WindowsLive*" -or $_ -like "*MicrosoftAccount*") {
            $target = ($_ -split " ")[-1]
            cmdkey /delete:$target 2>$null
        }
    }
    
    Start-Service -Name "wlidsvc" -ErrorAction SilentlyContinue
    Start-Service -Name "TokenBroker" -ErrorAction SilentlyContinue
    Write-Log "User profile sync reset completed" "Green"
}
catch {
    Write-Log "Warning: Profile sync reset failed - $($_.Exception.Message)" "Yellow"
}

# Fix mouse and input device issues after account switch
try {
    Write-Log "Resetting mouse and input device settings..."
    
    # Reset mouse settings to defaults
    $MouseRegPath = "HKCU:\Control Panel\Mouse"
    Set-ItemProperty -Path $MouseRegPath -Name "MouseSpeed" -Value "1" -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $MouseRegPath -Name "MouseThreshold1" -Value "6" -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $MouseRegPath -Name "MouseThreshold2" -Value "10" -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $MouseRegPath -Name "MouseSensitivity" -Value "10" -ErrorAction SilentlyContinue
    
    # Restart input services
    Restart-Service -Name "TabletInputService" -Force -ErrorAction SilentlyContinue
    Write-Log "Mouse and input settings reset" "Green"
}
catch {
    Write-Log "Warning: Mouse settings reset failed - $($_.Exception.Message)" "Yellow"
}

# =============================================================================
# SECTION 2: Enhanced UWP Bloatware Removal
# =============================================================================
Write-Log "Removing UWP bloatware applications..." "Cyan"

$bloatwareApps = @(
    "Microsoft.BingNews", "Microsoft.BingWeather", "Microsoft.BingFinance",
    "Microsoft.GetHelp", "Microsoft.Getstarted", "Microsoft.Tips",
    "Microsoft.MicrosoftSolitaireCollection", "Microsoft.MicrosoftMahjong",
    "Microsoft.People", "Microsoft.WindowsFeedbackHub", "Microsoft.WindowsMaps",
    "Microsoft.Xbox.TCUI", "Microsoft.XboxApp", "Microsoft.XboxGameOverlay",
    "Microsoft.XboxIdentityProvider", "Microsoft.XboxSpeechToTextOverlay",
    "Microsoft.ZuneMusic", "Microsoft.ZuneVideo", "Microsoft.WindowsCamera",
    "Clipchamp.Clipchamp", "Microsoft.PowerAutomateDesktop",
    "MicrosoftTeams", "Disney.37853FC22B2CE", "Netflix.NetFlix",
    "SpotifyAB.SpotifyMusic", "Microsoft.MixedReality.Portal"
)

$removedCount = 0
foreach ($app in $bloatwareApps) {
    try {
        $packages = Get-AppxPackage -Name "*$app*" -AllUsers -ErrorAction SilentlyContinue
        if ($packages) {
            $packages | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
            $removedCount++
            Write-Log "Removed: $app" "Green"
        }
    }
    catch {
        Write-Log "Failed to remove $app - $($_.Exception.Message)" "Yellow"
    }
}

# Remove provisioned packages to prevent reinstallation
foreach ($app in $bloatwareApps) {
    try {
        $provisionedPackages = Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -like "*$app*" }
        if ($provisionedPackages) {
            $provisionedPackages | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
        }
    }
    catch {
        Write-Log "Warning: Could not remove provisioned package for $app" "Yellow"
    }
}

Write-Log "Removed $removedCount bloatware applications" "Green"

# =============================================================================
# SECTION 3: Advanced Startup Optimization
# =============================================================================
Write-Log "Optimizing startup programs..." "Cyan"

$startupLocations = @(
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
)

$unwantedStartupItems = @(
    "OneDriveSetup", "KDE Connect", "FxSound", "WavesSvc", "ShareX",
    "Spotify", "Discord", "Steam", "Epic Games Launcher", "Adobe Updater",
    "iTunes Helper", "QuickTime Task", "Java Update Scheduler"
)

foreach ($location in $startupLocations) {
    foreach ($item in $unwantedStartupItems) {
        try {
            $exists = Get-ItemProperty -Path $location -Name $item -ErrorAction SilentlyContinue
            if ($exists) {
                Remove-ItemProperty -Path $location -Name $item -ErrorAction SilentlyContinue
                Write-Log "Removed startup item: $item from $location" "Green"
            }
        }
        catch {
            # Silently continue
        }
    }
}

# Disable unnecessary scheduled tasks
$taskPatterns = @("*Adobe*", "*Google*", "*Microsoft*Office*", "*OneDrive*", "*Skype*")
foreach ($pattern in $taskPatterns) {
    try {
        Get-ScheduledTask -TaskName $pattern -ErrorAction SilentlyContinue | 
        Where-Object { $_.State -eq "Ready" -and $_.TaskName -notlike "*Security*" } |
        Disable-ScheduledTask -ErrorAction SilentlyContinue
    }
    catch {
        # Continue silently
    }
}

# =============================================================================
# SECTION 4: System Services Optimization
# =============================================================================
Write-Log "Optimizing system services..." "Cyan"

$servicesToDisable = @(
    @{Name = "Fax"; DisplayName = "Fax Service" },
    @{Name = "WerSvc"; DisplayName = "Windows Error Reporting" },
    @{Name = "DiagTrack"; DisplayName = "Connected User Experiences and Telemetry" },
    @{Name = "dmwappushservice"; DisplayName = "dmwappushsvc" },
    @{Name = "MapsBroker"; DisplayName = "Downloaded Maps Manager" },
    @{Name = "lfsvc"; DisplayName = "Geolocation Service" },
    @{Name = "XblAuthManager"; DisplayName = "Xbox Live Auth Manager" },
    @{Name = "XblGameSave"; DisplayName = "Xbox Live Game Save" },
    @{Name = "XboxNetApiSvc"; DisplayName = "Xbox Live Networking Service" }
)

foreach ($service in $servicesToDisable) {
    try {
        $svc = Get-Service -Name $service.Name -ErrorAction SilentlyContinue
        if ($svc -and $svc.StartType -ne "Disabled") {
            Stop-Service -Name $service.Name -Force -ErrorAction SilentlyContinue
            Set-Service -Name $service.Name -StartupType Disabled -ErrorAction SilentlyContinue
            Write-Log "Disabled service: $($service.DisplayName)" "Green"
        }
    }
    catch {
        Write-Log "Warning: Could not disable $($service.DisplayName)" "Yellow"
    }
}

# =============================================================================
# SECTION 5: Enhanced Edge and Browser Optimization
# =============================================================================
Write-Log "Optimizing Microsoft Edge..." "Cyan"

try {
    # Stop Edge processes
    Get-Process -Name "*edge*" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Get-Process -Name "*msedge*" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    
    # Disable Edge startup boost
    $EdgePolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
    if (!(Test-Path $EdgePolicyPath)) {
        New-Item -Path $EdgePolicyPath -Force | Out-Null
    }
    Set-ItemProperty -Path $EdgePolicyPath -Name "StartupBoostEnabled" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $EdgePolicyPath -Name "BackgroundModeEnabled" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    
    # Clear Edge data
    $EdgeDataPaths = @(
        "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Cache",
        "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Code Cache",
        "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\GPUCache"
    )
    
    foreach ($path in $EdgeDataPaths) {
        if (Test-Path $path) {
            Remove-Item "$path\*" -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    
    Write-Log "Edge optimization completed" "Green"
}
catch {
    Write-Log "Warning: Edge optimization failed - $($_.Exception.Message)" "Yellow"
}

# =============================================================================
# SECTION 6: System Performance Optimization
# =============================================================================
Write-Log "Applying system performance optimizations..." "Cyan"

# Visual effects optimization
try {
    $VisualEffectsPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects"
    if (!(Test-Path $VisualEffectsPath)) {
        New-Item -Path $VisualEffectsPath -Force | Out-Null
    }
    Set-ItemProperty -Path $VisualEffectsPath -Name "VisualFXSetting" -Value 2 -Type DWord
    
    # Disable animations
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop\WindowMetrics" -Name "MinAnimate" -Value 0 -Type String -ErrorAction SilentlyContinue
    Write-Log "Visual effects optimized for performance" "Green"
}
catch {
    Write-Log "Warning: Visual effects optimization failed" "Yellow"
}

# Memory management optimization
try {
    $MemoryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
    Set-ItemProperty -Path $MemoryPath -Name "ClearPageFileAtShutdown" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $MemoryPath -Name "DisablePagingExecutive" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    Write-Log "Memory management optimized" "Green"
}
catch {
    Write-Log "Warning: Memory optimization failed" "Yellow"
}

# =============================================================================
# SECTION 7: PowerToys and Third-party App Management  
# =============================================================================
Write-Log "Managing PowerToys modules..." "Cyan"

$powerToysModules = @("AlwaysOnTop", "Awake", "ColorPicker", "CropAndLock", "FancyZones", "PowerRename")
$powerToysPath = "HKCU:\SOFTWARE\Microsoft\PowerToys"

if (Test-Path $powerToysPath) {
    foreach ($module in $powerToysModules) {
        try {
            Set-ItemProperty -Path $powerToysPath -Name "Enable$module" -Value 0 -Type DWord -ErrorAction SilentlyContinue
            Write-Log "Disabled PowerToys module: $module" "Green"
        }
        catch {
            Write-Log "Warning: Could not disable PowerToys $module" "Yellow"
        }
    }
}
else {
    Write-Log "PowerToys not installed or not configured" "Yellow"
}

# =============================================================================
# SECTION 8: Deep System Cleanup
# =============================================================================
Write-Log "Performing deep system cleanup..." "Cyan"

# Advanced temporary file cleanup
$tempLocations = @(
    "$env:TEMP",
    "$env:LOCALAPPDATA\Temp",
    "$env:WINDIR\Temp",
    "$env:LOCALAPPDATA\Microsoft\Windows\INetCache",
    "$env:LOCALAPPDATA\Microsoft\Windows\WebCache",
    "$env:APPDATA\Microsoft\Windows\Recent"
)

foreach ($location in $tempLocations) {
    if (Test-Path $location) {
        try {
            Get-ChildItem -Path $location -Force -ErrorAction SilentlyContinue | 
            Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
            Write-Log "Cleaned: $location" "Green"
        }
        catch {
            Write-Log "Warning: Could not fully clean $location" "Yellow"
        }
    }
}

# Windows Update cleanup
try {
    DISM /Online /Cleanup-Image /StartComponentCleanup /ResetBase
    Write-Log "Windows component cleanup completed" "Green"
}
catch {
    Write-Log "Warning: Component cleanup failed" "Yellow"
}

# Empty Recycle Bin
try {
    Clear-RecycleBin -Force -ErrorAction SilentlyContinue
    Write-Log "Recycle bin emptied" "Green"
}
catch {
    Write-Log "Warning: Could not empty recycle bin" "Yellow"
}

# =============================================================================
# SECTION 9: System Restart and Final Steps
# =============================================================================
Write-Log "Restarting critical system processes..." "Cyan"

# Restart Windows Explorer
try {
    Stop-Process -Name "explorer" -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    Start-Process "explorer.exe"
    Write-Log "Windows Explorer restarted" "Green"
}
catch {
    Write-Log "Warning: Could not restart Explorer" "Yellow"
}

# Restart Windows Search
try {
    Restart-Service -Name "WSearch" -Force -ErrorAction SilentlyContinue
    Write-Log "Windows Search service restarted" "Green"
}
catch {
    Write-Log "Warning: Could not restart Windows Search" "Yellow"
}

# Final system refresh
try {
    ie4uinit.exe -ClearIconCache
    ie4uinit.exe -show
    Write-Log "Icon cache cleared" "Green"
}
catch {
    Write-Log "Warning: Icon cache clearing failed" "Yellow"
}

# =============================================================================
# COMPLETION AND SUMMARY
# =============================================================================
Write-Log "Optimization completed successfully!" "Green"
Write-Log "Summary of changes:" "Cyan"
Write-Log "- Microsoft Account transition issues addressed" "White"
Write-Log "- Mouse and input device settings reset" "White"
Write-Log "- $removedCount bloatware applications removed" "White"
Write-Log "- Startup programs optimized" "White"
Write-Log "- System services optimized" "White"
Write-Log "- Browser performance improved" "White"
Write-Log "- System cleanup performed" "White"
Write-Log "Log file saved to: $LogPath" "Yellow"

if (!$SkipReboot) {
    $reboot = Read-Host "Would you like to restart your computer now to complete the optimization? (Y/N)"
    if ($reboot -eq "Y" -or $reboot -eq "y") {
        Write-Log "Restarting computer in 10 seconds..." "Yellow"
        Start-Sleep -Seconds 10
        Restart-Computer -Force
    }
    else {
        Write-Log "Please restart your computer manually to complete the optimization." "Yellow"
    }
}
else {
    Write-Log "Restart your computer to complete all optimizations." "Yellow"
} 