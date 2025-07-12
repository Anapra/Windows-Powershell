<#
.SYNOPSIS
    Windows System Maintainer - All-in-one system maintenance, repair, and optimization tool

.DESCRIPTION
    This consolidated script combines functionality from multiple maintenance scripts into
    a single, modular solution. Run specific modules as needed or all modules at once.

    Modules:
    - Repair: Fix registry issues, scan drivers, manage problematic tasks
    - Refresh: Update environment, restart services, apply fast maintenance
    - Optimize: Control privacy settings, perform disk cleanup, customize UI
    - Core: Run essential system health checks (SFC/DISM)

.PARAMETER Modules
    Specify which modules to run: Repair, Refresh, Optimize, Core, or All
    Default: All

.PARAMETER Fast
    Use parallel processing where possible to speed up execution
    Default: False

.PARAMETER NoReboot
    Skip reboot prompt at the end
    Default: False

.PARAMETER Log
    Path to log file (default: %TEMP%\WindowsSystemMaintainer_[timestamp].log)

.EXAMPLE
    .\WindowsSystemMaintainer.ps1 -Modules Core,Repair
    # Runs only Core and Repair modules

.EXAMPLE
    .\WindowsSystemMaintainer.ps1 -Fast
    # Runs all modules with parallel processing where possible

.NOTES
    Version: 1.0
    Author: System Administrator
    Requires: Administrative privileges
#>

#region Script Parameters and Initialization
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateSet("Repair", "Refresh", "Optimize", "Core", "All")]
    [string[]]$Modules = @("All"),

    [Parameter(Mandatory = $false)]
    [switch]$Fast,

    [Parameter(Mandatory = $false)]
    [switch]$NoReboot,

    [Parameter(Mandatory = $false)]
    [string]$Log = "$env:TEMP\WindowsSystemMaintainer_$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
)

# Ensure the script runs with administrative privileges
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "This script requires administrative privileges. Please run as administrator." -ForegroundColor Red
    Start-Process "pwsh" "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" $args" -Verb RunAs
    exit
}

# Initialize script
$ErrorActionPreference = "Continue"
$StartTime = Get-Date
$CompletedTasks = @()
$FailedTasks = @()
$PendingReboot = $false

# Start logging
Start-Transcript -Path $Log -Append
Write-Host "=== WINDOWS SYSTEM MAINTAINER v1.0 ===" -ForegroundColor Cyan
Write-Host "Started at $(Get-Date)" -ForegroundColor Cyan
Write-Host "Logging to $Log" -ForegroundColor Cyan
Write-Host "Modules to run: $($Modules -join ', ')" -ForegroundColor Cyan
Write-Host "Fast mode: $Fast" -ForegroundColor Cyan
Write-Host "`n"

# Determine if we should run all modules
$RunAllModules = $Modules -contains "All"

# System information detection
$SystemInfo = @{
    IsLaptop        = (Get-CimInstance -ClassName Win32_ComputerSystem).PCSystemType -eq 2
    IsVM            = (Get-CimInstance -ClassName Win32_ComputerSystem).Model -match "Virtual|VMware|KVM"
    IsSSD           = (Get-PhysicalDisk | Where-Object MediaType -eq "SSD" | Measure-Object).Count -gt 0
    OSVersion       = [System.Environment]::OSVersion.Version
    IsWindows10or11 = (Get-CimInstance -ClassName Win32_OperatingSystem).Caption -match "Windows 10|Windows 11"
}

Write-Host "System Information:" -ForegroundColor Yellow
Write-Host "- System Type: $(if ($SystemInfo.IsLaptop) { 'Laptop' } else { 'Desktop' })" -ForegroundColor Yellow
Write-Host "- Hardware: $(if ($SystemInfo.IsVM) { 'Virtual Machine' } else { 'Physical Hardware' })" -ForegroundColor Yellow
Write-Host "- Storage: $(if ($SystemInfo.IsSSD) { 'SSD Present' } else { 'HDD Only' })" -ForegroundColor Yellow
Write-Host "- OS Version: $($SystemInfo.OSVersion)" -ForegroundColor Yellow
Write-Host "`n"
#endregion

#region Helper Functions
function Invoke-Task {
    param(
        [string]$Name,
        [scriptblock]$Action,
        [string]$Module,
        [scriptblock]$PreCheck = { $true },
        [switch]$Critical = $false,
        [switch]$RequireConfirmation = $false
    )
    
    # Check if we should run this module
    if (-not ($RunAllModules -or $Modules -contains $Module)) {
        return
    }
    
    # Confirmation for tasks that require it
    if ($RequireConfirmation) {
        $confirmation = Read-Host -Prompt "Perform task: $Name? [Y/N]"
        if ($confirmation -ne "Y" -and $confirmation -ne "y") {
            Write-Host "Skipping $Name" -ForegroundColor Yellow
            return
        }
    }
    
    # Perform pre-check
    $precondition = & $PreCheck
    if (-not $precondition) {
        Write-Host "[SKIP] $Module - $Name (Preconditions not met)" -ForegroundColor Yellow
        return
    }
    #module
    # Execute the task
    $taskStart = Get-Date
    Write-Host "[START] $Module - $Name" -ForegroundColor Cyan
    
    try {
        & $Action
        $elapsed = [math]::Round(((Get-Date) - $taskStart).TotalSeconds, 2)
        Write-Host "[SUCCESS] $Module - $Name ($elapsed s)" -ForegroundColor Green
        $script:CompletedTasks += "$Module - $Name"
    }
    catch {
        $elapsed = [math]::Round(((Get-Date) - $taskStart).TotalSeconds, 2)
        Write-Host "[FAILED] $Module - $Name ($elapsed s)" -ForegroundColor Red
        Write-Host "Error: $_" -ForegroundColor Red
        $script:FailedTasks += "$Module - $Name"
        
        if ($Critical) {
            Write-Host "Critical task failed - stopping execution" -ForegroundColor Red
            Stop-Transcript
            exit 1
        }
    }
}

function Start-ParallelJob {
    param(
        [string]$Name,
        [scriptblock]$Action,
        [int]$TimeoutSeconds = 300
    )
    
    if ($Fast) {
        Write-Host "[PARALLEL] Starting job: $Name" -ForegroundColor DarkCyan
        $job = Start-Job -ScriptBlock $Action
        return $job
    }
    else {
        Write-Host "[SEQUENTIAL] Running: $Name" -ForegroundColor DarkCyan
        & $Action
        return $null
    }
}

function Wait-ParallelJobs {
    param(
        [System.Management.Automation.Job[]]$Jobs,
        [int]$TimeoutSeconds = 300
    )
    
    if ($null -eq $Jobs -or $Jobs.Count -eq 0) {
        return
    }
    
    Write-Host "Waiting for background jobs to complete..." -ForegroundColor DarkCyan
    $completedJobs = $Jobs | Wait-Job -Timeout $TimeoutSeconds
    
    # Display job results
    foreach ($job in $completedJobs) {
        Write-Host "Job '$($job.Name)' completed with state: $($job.State)" -ForegroundColor DarkCyan
        $job | Receive-Job -AutoRemoveJob -Wait
    }
    
    # Handle any jobs that timed out
    $remainingJobs = $Jobs | Where-Object { $_.State -ne "Completed" }
    if ($null -ne $remainingJobs -and $remainingJobs.Count -gt 0) {
        Write-Host "Some jobs did not complete within the timeout period. Stopping them..." -ForegroundColor Yellow
        $remainingJobs | Stop-Job
        $remainingJobs | Remove-Job -Force
    }
}

function Test-PendingReboot {
    $rebootPending = $false
    
    # Check various registry keys that indicate pending reboot
    $pendingRebootKeys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"
    )
    
    foreach ($key in $pendingRebootKeys) {
        if (Test-Path $key) {
            $rebootPending = $true
            break
        }
    }
    
    # Check for pending file rename operations
    $pendingFileRename = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -ErrorAction SilentlyContinue).PendingFileRenameOperations
    if ($null -ne $pendingFileRename) {
        $rebootPending = $true
    }
    
    return $rebootPending
}

function EnsureRegPath {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path
    )
    
    if (-not (Test-Path $Path)) {
        try {
            New-Item -Path $Path -Force | Out-Null
            return $true
        }
        catch {
            Write-Host "Failed to create registry path: $Path" -ForegroundColor Red
            Write-Host "Error: $_" -ForegroundColor Red
            return $false
        }
    }
    return $true
}
#endregion

#region Define Module Functions
#region Core Module
function Invoke-CoreModule {
    Write-Host "=== RUNNING CORE MODULE ===" -ForegroundColor Magenta
    
    # Create a system restore point
    Invoke-Task -Name "Create System Restore Point" -Module "Core" -RequireConfirmation -Action {
        if ($SystemInfo.IsWindows10or11 -and -not $SystemInfo.IsVM) {
            Enable-ComputerRestore -Drive "$env:SystemDrive" -ErrorAction SilentlyContinue
            Checkpoint-Computer -Description "Windows System Maintainer - $(Get-Date -Format 'yyyy-MM-dd')" -RestorePointType "MODIFY_SETTINGS"
        }
        else {
            Write-Host "System restore point creation skipped (VM or older Windows version)" -ForegroundColor Yellow
        }
    }
    
    # Run SFC scan
    Invoke-Task -Name "System File Checker" -Module "Core" -Action {
        Write-Host "Running SFC /scannow (this may take several minutes)..." -ForegroundColor Yellow
        $sfc = Start-Process -FilePath "sfc.exe" -ArgumentList "/scannow" -Wait -NoNewWindow -PassThru
        if ($sfc.ExitCode -ne 0) {
            throw "SFC scan failed with exit code $($sfc.ExitCode)"
        }
    }
    
    # Run DISM scan
    Invoke-Task -Name "DISM Health Restore" -Module "Core" -Action {
        Write-Host "Running DISM /RestoreHealth (this may take several minutes)..." -ForegroundColor Yellow
        $dism = Start-Process -FilePath "dism.exe" -ArgumentList "/Online /Cleanup-Image /RestoreHealth" -Wait -NoNewWindow -PassThru
        if ($dism.ExitCode -ne 0) {
            throw "DISM restore health failed with exit code $($dism.ExitCode)"
        }
        $script:PendingReboot = $true
    }
}
#endregion

#region Repair Module
function Invoke-RepairModule {
    Write-Host "=== RUNNING REPAIR MODULE ===" -ForegroundColor Magenta
    
    # Fix Registry KnownDLLs
    Invoke-Task -Name "Fix Registry KnownDLLs" -Module "Repair" -Action {
        $knownDLLsPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs"
        $badEntries = @("xtajit64se", "xtajit64", "_wowarmhw", "_wow64cpu")
        
        foreach ($entry in $badEntries) {
            try {
                $exists = Get-ItemProperty -Path $knownDLLsPath -Name $entry -ErrorAction SilentlyContinue
                if ($exists) {
                    # Try to take ownership and set permissions first
                    $acl = Get-Acl -Path $knownDLLsPath
                    $rule = New-Object System.Security.AccessControl.RegistryAccessRule(
                        [System.Security.Principal.WindowsIdentity]::GetCurrent().User,
                        "FullControl",
                        "Allow"
                    )
                    $acl.SetAccessRule($rule)
                    Set-Acl -Path $knownDLLsPath -AclObject $acl
                    
                    # Now try to remove the entry
                    Remove-ItemProperty -Path $knownDLLsPath -Name $entry -Force -ErrorAction Stop
                    Write-Host "  ✓ Deleted: $entry" -ForegroundColor Green
                }
                else {
                    Write-Host "  - Not found: $entry" -ForegroundColor Gray
                }
            }
            catch {
                Write-Host "  ✗ Failed to delete $entry (Access Denied)" -ForegroundColor Red
                Write-Host "    Attempting alternative method..." -ForegroundColor Yellow
                
                # Try alternative method using reg.exe
                try {
                    $regResult = & reg delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs" /v $entry /f
                    if ($LASTEXITCODE -eq 0) {
                        Write-Host "  ✓ Deleted: $entry (using reg.exe)" -ForegroundColor Green
                    }
                    else {
                        throw "Registry deletion failed"
                    }
                }
                catch {
                    Write-Host "    Error: $_" -ForegroundColor Red
                    # Don't throw here, continue with other entries
                }
            }
        }
    }
    
    # Scan Drivers with SigCheck
    Invoke-Task -Name "Scan Drivers (SigCheck)" -Module "Repair" -PreCheck { 
        Test-Path "$env:USERPROFILE\sysinternal\sigcheck64.exe" 
    } -Action {
        $sigCheckPath = "$env:USERPROFILE\sysinternal\sigcheck64.exe"
        $driversPath = "C:\Windows\System32\drivers"
        
        Write-Host "Running SigCheck on *.sys files (this may take a while)..." -ForegroundColor Yellow
        & $sigCheckPath -accepteula -nobanner -u -e "$driversPath\*.sys" | Out-File "$env:TEMP\SigCheck_Results.txt"
        Write-Host "SigCheck results saved to $env:TEMP\SigCheck_Results.txt" -ForegroundColor Green
    }
    
    # Delete Problematic Scheduled Tasks
    Invoke-Task -Name "Fix Problematic Tasks" -Module "Repair" -Action {
        $problematicTasks = @(
            @{Path = "\Microsoft\Windows\UpdateOrchestrator\"; Name = "USO_UxBroker" }
        )
        
        foreach ($task in $problematicTasks) {
            try {
                $taskObj = Get-ScheduledTask -TaskName $task.Name -TaskPath $task.Path -ErrorAction SilentlyContinue
                if ($taskObj) {
                    $taskObj | Disable-ScheduledTask | Out-Null
                    $taskObj | Unregister-ScheduledTask -Confirm:$false | Out-Null
                    Write-Host "  ✓ Task deleted: $($task.Path)$($task.Name)" -ForegroundColor Green
                }
                else {
                    Write-Host "  - Task not found: $($task.Path)$($task.Name)" -ForegroundColor Gray
                }
            }
            catch {
                Write-Host "  ✗ Failed to delete task: $($task.Path)$($task.Name)" -ForegroundColor Red
                Write-Host "    Error: $_" -ForegroundColor Red
            }
        }
    }
}
#endregion

#region Refresh Module
function Invoke-RefreshModule {
    Write-Host "=== RUNNING REFRESH MODULE ===" -ForegroundColor Magenta
    
    $jobs = @()
    
    # Environment refresh
    Invoke-Task -Name "Refresh Environment" -Module "Refresh" -Action {
        # Update Group Policy
        Write-Host "Updating Group Policy..." -ForegroundColor Yellow
        $gpupdate = Start-Process -FilePath "gpupdate.exe" -ArgumentList "/force" -Wait -NoNewWindow -PassThru
        
        # Clear DNS cache
        Write-Host "Clearing DNS cache..." -ForegroundColor Yellow
        Clear-DnsClientCache
        
        # Refresh environment variables - can't use refreshenv command directly in PowerShell
        Write-Host "Refreshing environment variables..." -ForegroundColor Yellow
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
    }
    
    # Winget upgrades (if available)
    Invoke-Task -Name "Update Apps (Winget)" -Module "Refresh" -PreCheck {
        Get-Command winget -ErrorAction SilentlyContinue
    } -Action {
        if ($Fast) {
            $jobs += Start-ParallelJob -Name "WingetUpgrade" -Action {
                winget upgrade --all --include-unknown --accept-source-agreements --accept-package-agreements --silent
            }
        }
        else {
            # Run synchronously to show progress
            Write-Host "Updating package sources..." -ForegroundColor Yellow
            winget source update --all | Out-Null
            
            Write-Host "Upgrading packages (this may take several minutes)..." -ForegroundColor Yellow
            winget upgrade --all --include-unknown --accept-source-agreements --accept-package-agreements
        }
    }
    
    # Disk cleanup
    Invoke-Task -Name "Disk Cleanup" -Module "Refresh" -Action {
        if ($Fast) {
            $jobs += Start-ParallelJob -Name "DiskCleanup" -Action {
                # Run disk cleanup silently with preset settings
                Start-Process cleanmgr.exe -ArgumentList "/sagerun:1" -NoNewWindow -Wait
            }
        }
        else {
            # Run disk cleanup synchronously
            Write-Host "Running disk cleanup..." -ForegroundColor Yellow
            Start-Process cleanmgr.exe -ArgumentList "/sagerun:1" -NoNewWindow -Wait
        }
    }
    
    # Restart essential services
    Invoke-Task -Name "Restart Essential Services" -Module "Refresh" -Action {
        $services = @(
            @{Name = "DeviceAssociationService"; Action = "Restart" },
            @{Name = "bthserv"; Action = "Start" }
        )
        
        foreach ($service in $services) {
            try {
                $svc = Get-Service -Name $service.Name -ErrorAction SilentlyContinue
                if ($svc) {
                    switch ($service.Action) {
                        "Restart" {
                            Restart-Service -Name $service.Name -Force -ErrorAction Stop
                            Write-Host "  ✓ Restarted service: $($service.Name)" -ForegroundColor Green
                        }
                        "Start" {
                            if ($svc.Status -ne "Running") {
                                Start-Service -Name $service.Name -ErrorAction Stop
                                Write-Host "  ✓ Started service: $($service.Name)" -ForegroundColor Green
                            }
                            else {
                                Write-Host "  - Service already running: $($service.Name)" -ForegroundColor Gray
                            }
                        }
                    }
                }
                else {
                    Write-Host "  - Service not found: $($service.Name)" -ForegroundColor Yellow
                }
            }
            catch {
                Write-Host "  ✗ Service operation failed: $($service.Name)" -ForegroundColor Red
                Write-Host "    Error: $_" -ForegroundColor Red
            }
        }
    }
    
    # Power optimization
    Invoke-Task -Name "Power Configuration" -Module "Refresh" -Action {
        # Set to balanced power plan
        powercfg /setactive 381b4222-f694-41f0-9685-ff5bb260df2e | Out-Null
        
        # Enable hibernation only for laptops, disable for desktops
        if ($SystemInfo.IsLaptop) {
            powercfg /h on | Out-Null
            Write-Host "  ✓ Hibernation enabled (laptop detected)" -ForegroundColor Green
        }
        else {
            powercfg /h off | Out-Null
            Write-Host "  ✓ Hibernation disabled (desktop detected)" -ForegroundColor Green
        }
    }
    
    # Wait for background jobs if in fast mode
    if ($Fast -and $jobs.Count -gt 0) {
        Wait-ParallelJobs -Jobs $jobs -TimeoutSeconds 600
    }
}
#endregion

#region Optimize Module
function Invoke-OptimizeModule {
    Write-Host "=== RUNNING OPTIMIZE MODULE ===" -ForegroundColor Magenta
    
    # Microsoft Account Transition Fixes
    Invoke-Task -Name "Microsoft Account Transition Fixes" -Module "Optimize" -Action {
        Write-Host "Fixing Microsoft Account transition issues..." -ForegroundColor Yellow
        
        # Fix user profile synchronization issues
        try {
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
            Write-Host "User profile sync reset completed" -ForegroundColor Green
        }
        catch {
            Write-Host "Warning: Profile sync reset failed - $($_.Exception.Message)" -ForegroundColor Yellow
        }
        
        # Fix mouse and input device issues after account switch
        try {
            $MouseRegPath = "HKCU:\Control Panel\Mouse"
            Set-ItemProperty -Path $MouseRegPath -Name "MouseSpeed" -Value "1" -ErrorAction SilentlyContinue
            Set-ItemProperty -Path $MouseRegPath -Name "MouseThreshold1" -Value "6" -ErrorAction SilentlyContinue
            Set-ItemProperty -Path $MouseRegPath -Name "MouseThreshold2" -Value "10" -ErrorAction SilentlyContinue
            Set-ItemProperty -Path $MouseRegPath -Name "MouseSensitivity" -Value "10" -ErrorAction SilentlyContinue
            
            Restart-Service -Name "TabletInputService" -Force -ErrorAction SilentlyContinue
            Write-Host "Mouse and input settings reset" -ForegroundColor Green
        }
        catch {
            Write-Host "Warning: Mouse settings reset failed - $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
    
    # Enhanced UWP Bloatware Removal
    Invoke-Task -Name "UWP Bloatware Removal" -Module "Optimize" -Action {
        Write-Host "Removing UWP bloatware applications..." -ForegroundColor Yellow
        
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
                    Write-Host "Removed: $app" -ForegroundColor Green
                }
            }
            catch {
                Write-Host "Failed to remove $app - $($_.Exception.Message)" -ForegroundColor Yellow
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
                Write-Host "Warning: Could not remove provisioned package for $app" -ForegroundColor Yellow
            }
        }
        
        Write-Host "Removed $removedCount bloatware applications" -ForegroundColor Green
    }
    
    # Advanced Startup Optimization
    Invoke-Task -Name "Startup Optimization" -Module "Optimize" -Action {
        Write-Host "Optimizing startup programs..." -ForegroundColor Yellow
        
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
                        Write-Host "Removed startup item: $item from $location" -ForegroundColor Green
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
    }
    
    # System Services Optimization
    Invoke-Task -Name "System Services Optimization" -Module "Optimize" -Action {
        Write-Host "Optimizing system services..." -ForegroundColor Yellow
        
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
                    Write-Host "Disabled service: $($service.DisplayName)" -ForegroundColor Green
                }
            }
            catch {
                Write-Host "Warning: Could not disable $($service.DisplayName)" -ForegroundColor Yellow
            }
        }
    }
    
    # Edge and Browser Optimization
    Invoke-Task -Name "Edge and Browser Optimization" -Module "Optimize" -Action {
        Write-Host "Optimizing Microsoft Edge..." -ForegroundColor Yellow
        
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
            
            Write-Host "Edge optimization completed" -ForegroundColor Green
        }
        catch {
            Write-Host "Warning: Edge optimization failed - $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
    
    # PowerToys Management
    Invoke-Task -Name "PowerToys Management" -Module "Optimize" -Action {
        Write-Host "Managing PowerToys modules..." -ForegroundColor Yellow
        
        $powerToysModules = @("AlwaysOnTop", "Awake", "ColorPicker", "CropAndLock", "FancyZones", "PowerRename")
        $powerToysPath = "HKCU:\SOFTWARE\Microsoft\PowerToys"
        
        if (Test-Path $powerToysPath) {
            foreach ($module in $powerToysModules) {
                try {
                    Set-ItemProperty -Path $powerToysPath -Name "Enable$module" -Value 0 -Type DWord -ErrorAction SilentlyContinue
                    Write-Host "Disabled PowerToys module: $module" -ForegroundColor Green
                }
                catch {
                    Write-Host "Warning: Could not disable PowerToys $module" -ForegroundColor Yellow
                }
            }
        }
        else {
            Write-Host "PowerToys not installed or not configured" -ForegroundColor Yellow
        }
    }
    
    # Deep System Cleanup
    Invoke-Task -Name "Deep System Cleanup" -Module "Optimize" -Action {
        Write-Host "Performing deep system cleanup..." -ForegroundColor Yellow
        
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
                    Write-Host "Cleaned: $location" -ForegroundColor Green
                }
                catch {
                    Write-Host "Warning: Could not fully clean $location" -ForegroundColor Yellow
                }
            }
        }
        
        # Windows Update cleanup
        try {
            DISM /Online /Cleanup-Image /StartComponentCleanup /ResetBase
            Write-Host "Windows component cleanup completed" -ForegroundColor Green
        }
        catch {
            Write-Host "Warning: Component cleanup failed" -ForegroundColor Yellow
        }
        
        # Empty Recycle Bin
        try {
            Clear-RecycleBin -Force -ErrorAction SilentlyContinue
            Write-Host "Recycle bin emptied" -ForegroundColor Green
        }
        catch {
            Write-Host "Warning: Could not empty recycle bin" -ForegroundColor Yellow
        }
    }
    
    # Restart critical system processes
    Invoke-Task -Name "Restart Critical Processes" -Module "Optimize" -Action {
        Write-Host "Restarting critical system processes..." -ForegroundColor Yellow
        
        # Restart Windows Explorer
        try {
            Stop-Process -Name "explorer" -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 2
            Start-Process "explorer.exe"
            Write-Host "Windows Explorer restarted" -ForegroundColor Green
        }
        catch {
            Write-Host "Warning: Could not restart Explorer" -ForegroundColor Yellow
        }
        
        # Restart Windows Search
        try {
            Restart-Service -Name "WSearch" -Force -ErrorAction SilentlyContinue
            Write-Host "Windows Search service restarted" -ForegroundColor Green
        }
        catch {
            Write-Host "Warning: Could not restart Windows Search" -ForegroundColor Yellow
        }
        
        # Final system refresh
        try {
            ie4uinit.exe -ClearIconCache
            ie4uinit.exe -show
            Write-Host "Icon cache cleared" -ForegroundColor Green
        }
        catch {
            Write-Host "Warning: Icon cache clearing failed" -ForegroundColor Yellow
        }
    }
    
    # Original optimization tasks
    Invoke-Task -Name "Performance Optimization" -Module "Optimize" -Action {
        Write-Host "Optimizing system performance..." -ForegroundColor Yellow
        
        # Optimize for best performance
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -Value 2 -Type DWord -Force
        
        # Disable visual effects
        $visualEffects = @(
            "AnimateMinMax",
            "ComboBoxAnimation",
            "CursorShadow",
            "DragFullWindows",
            "DropShadow",
            "FontSmoothing",
            "ListBoxSmoothScrolling",
            "ListviewAlphaSelect",
            "ListviewShadow",
            "MenuAnimation",
            "SelectionFade",
            "TaskbarAnimations",
            "TooltipAnimation"
        )
        
        foreach ($effect in $visualEffects) {
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name $effect -Value 0 -Type DWord -Force
        }
        
        # Optimize processor scheduling
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl" -Name "Win32PrioritySeparation" -Value 38 -Type DWord -Force
        
        # Optimize for background services
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl" -Name "IRQ8Priority" -Value 2 -Type DWord -Force
        
        Write-Host "Performance settings optimized" -ForegroundColor Green
    }
    
    # Privacy adjustments
    Invoke-Task -Name "Privacy Optimization" -Module "Optimize" -RequireConfirmation -Action {
        Write-Host "Optimizing privacy settings..." -ForegroundColor Yellow
        
        # Telemetry settings - set to Basic (1) instead of Disabled (0) for better compatibility
        if (EnsureRegPath "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection") {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 1 -Type DWord -Force
        }
        
        # Disable tailored experiences
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" -Name "TailoredExperiencesWithDiagnosticDataEnabled" -Value 0 -Type DWord -Force
        
        # Disable advertising ID
        if (EnsureRegPath "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo") {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Value 1 -Type DWord -Force
        }
        
        # Disable Cortana
        if (EnsureRegPath "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search") {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Value 0 -Type DWord -Force
        }
        
        # Disable location tracking
        if (EnsureRegPath "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location") {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Value "Deny" -Type String -Force
        }
        
        # Disable app diagnostics
        if (EnsureRegPath "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics") {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" -Name "Value" -Value "Deny" -Type String -Force
        }
        
        Write-Host "Privacy settings optimized" -ForegroundColor Green
    }
    
    # Network Optimization
    Invoke-Task -Name "Network Optimization" -Module "Optimize" -Action {
        Write-Host "Optimizing network settings..." -ForegroundColor Yellow
        
        # Optimize TCP/IP settings
        $tcpParams = @{
            "TcpNoDelay"        = 1
            "TcpAckFrequency"   = 1
            "TCPDelAckTicks"    = 0
            "TcpMaxDupAcks"     = 2
            "SackOpts"          = 1
            "Tcp1323Opts"       = 1
            "TcpTimedWaitDelay" = 30
        }
        
        foreach ($param in $tcpParams.GetEnumerator()) {
            Set-NetTCPSetting -SettingName InternetCustom -AutoTuningLevelLocal Normal
            Set-NetTCPSetting -SettingName InternetCustom -ScalingHeuristics Disabled
            Set-NetTCPSetting -SettingName InternetCustom -DynamicPortRangeStartPort 49152
            Set-NetTCPSetting -SettingName InternetCustom -DynamicPortRangeNumberOfPorts 16384
        }
        
        # Optimize DNS settings
        $activeAdapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
        if ($activeAdapters) {
            Set-DnsClientServerAddress -InterfaceIndex $activeAdapters.ifIndex -ServerAddresses ("8.8.8.8", "8.8.4.4")
        }
        
        # Enable DNS over HTTPS (using registry method instead of cmdlet)
        if (EnsureRegPath "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters") {
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name "EnableAutoDoh" -Value 2 -Type DWord -Force
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name "DoHFlags" -Value 0 -Type DWord -Force
        }
        
        Write-Host "Network settings optimized" -ForegroundColor Green
    }
    
    # Disk health check and optimization
    Invoke-Task -Name "Disk Health Check" -Module "Optimize" -Action {
        $disks = Get-PhysicalDisk | Select-Object DeviceId, FriendlyName, MediaType, HealthStatus, OperationalStatus
        $healthReport = "$env:TEMP\DiskHealth_$(Get-Date -Format 'yyyyMMdd').txt"
        
        # Display disk health
        Write-Host "Disk Health Status:" -ForegroundColor Yellow
        $disks | Format-Table -AutoSize
        
        # Save full disk report
        $disks | Format-List | Out-File -FilePath $healthReport -Force
        
        # Run chkdsk if any disk is unhealthy
        if ($disks | Where-Object { $_.HealthStatus -ne "Healthy" }) {
            Write-Host "Unhealthy disk detected! Running CHKDSK..." -ForegroundColor Red
            Start-Process "chkdsk" -ArgumentList "/scan" -NoNewWindow -Wait
            $script:PendingReboot = $true
        }
        
        # SSD optimization (trim) if SSD present
        if ($SystemInfo.IsSSD) {
            Write-Host "SSD detected, optimizing..." -ForegroundColor Yellow
            try {
                # Run defrag with /A parameter to analyze first
                $defragOutput = defrag /A
                if ($defragOutput -match "You don't need to defragment this volume") {
                    Write-Host "Volume is already optimized" -ForegroundColor Green
                }
                else {
                    # Run optimize with retrim
                    Get-Volume | Where-Object { $_.DriveType -eq "Fixed" -and $_.DriveLetter } | ForEach-Object {
                        Write-Host "Optimizing volume $($_.DriveLetter)..." -ForegroundColor Yellow
                        try {
                            Optimize-Volume -DriveLetter $_.DriveLetter -ReTrim -ErrorAction Stop
                            Write-Host "  ✓ Volume $($_.DriveLetter) optimized" -ForegroundColor Green
                        }
                        catch {
                            Write-Host "  ✗ Failed to optimize volume $($_.DriveLetter): $_" -ForegroundColor Red
                        }
                    }
                }
            }
            catch {
                Write-Host "Volume optimization failed: $_" -ForegroundColor Red
            }
            
            # Enable TRIM for SSDs
            try {
                fsutil behavior set disabledeletenotify 0
                Write-Host "TRIM enabled for SSDs" -ForegroundColor Green
            }
            catch {
                Write-Host "Failed to enable TRIM: $_" -ForegroundColor Red
            }
        }
        
        Write-Host "Disk health report saved to $healthReport" -ForegroundColor Green
    }
    
    # Memory Management
    Invoke-Task -Name "Memory Management" -Module "Optimize" -Action {
        Write-Host "Optimizing memory management..." -ForegroundColor Yellow
        
        # Clear system file cache using PowerShell native methods
        try {
            # Clear file system cache
            $code = @'
using System;
using System.Runtime.InteropServices;
public class MemoryManagement {
    [DllImport("psapi.dll")]
    static extern int EmptyWorkingSet(IntPtr hwProc);
    public static void ClearSystemCache() {
        EmptyWorkingSet(System.Diagnostics.Process.GetCurrentProcess().Handle);
    }
}
'@
            Add-Type -TypeDefinition $code
            [MemoryManagement]::ClearSystemCache()
            Write-Host "System cache cleared" -ForegroundColor Green
        }
        catch {
            Write-Host "Failed to clear system cache: $_" -ForegroundColor Red
        }
        
        # Optimize page file
        try {
            $computersys = Get-WmiObject -Class Win32_ComputerSystem
            $memory = [math]::Round($computersys.TotalPhysicalMemory / 1GB)
            
            # Get page file settings using WMI
            $pageFileSetting = Get-WmiObject -Class Win32_PageFileSetting
            if ($pageFileSetting) {
                # Calculate page file size based on RAM
                $initialSize = $memory * 1024
                $maximumSize = $memory * 2048
                
                # Set page file size using WMI
                $pageFileSetting.InitialSize = $initialSize
                $pageFileSetting.MaximumSize = $maximumSize
                $result = $pageFileSetting.Put()
                
                if ($result.ReturnValue -eq 0) {
                    Write-Host "Page file optimized (Initial: ${initialSize}MB, Maximum: ${maximumSize}MB)" -ForegroundColor Green
                }
                else {
                    throw "Failed to set page file size. Return value: $($result.ReturnValue)"
                }
            }
            else {
                # Alternative method using registry
                $pageFilePath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
                if (Test-Path $pageFilePath) {
                    Set-ItemProperty -Path $pageFilePath -Name "PagingFiles" -Value "C:\pagefile.sys $initialSize $maximumSize" -Type String -Force
                    Write-Host "Page file settings updated via registry" -ForegroundColor Green
                }
                else {
                    throw "Could not find page file settings"
                }
            }
        }
        catch {
            Write-Host "Failed to optimize page file: $_" -ForegroundColor Red
            Write-Host "Attempting alternative method..." -ForegroundColor Yellow
            
            # Try using systeminfo to get memory and set page file
            try {
                $systemInfo = systeminfo | Select-String "Total Physical Memory"
                if ($systemInfo -match "(\d+),(\d+) MB") {
                    $totalMemory = [int]($matches[1] + $matches[2])
                    $initialSize = $totalMemory
                    $maximumSize = $totalMemory * 2
                    
                    # Use wmic to set page file
                    $wmicResult = wmic pagefileset where name="C:\\pagefile.sys" set InitialSize=$initialSize, MaximumSize=$maximumSize
                    if ($LASTEXITCODE -eq 0) {
                        Write-Host "Page file optimized using WMIC" -ForegroundColor Green
                    }
                    else {
                        throw "WMIC command failed"
                    }
                }
            }
            catch {
                Write-Host "All page file optimization methods failed" -ForegroundColor Red
            }
        }
        
        Write-Host "Memory management optimized" -ForegroundColor Green
    }
    
    # UI Customization
    Invoke-Task -Name "UI Optimization" -Module "Optimize" -RequireConfirmation -Action {
        Write-Host "Optimizing UI settings..." -ForegroundColor Yellow
        
        # Show file extensions
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Value 0 -Type DWord -Force
        
        # Show hidden files
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Value 1 -Type DWord -Force
        
        # Optimize taskbar
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarSmallIcons" -Value 1 -Type DWord -Force
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarGlomLevel" -Value 2 -Type DWord -Force
        
        # Ask user about dark mode
        $darkMode = Read-Host "Enable Dark Mode? [Y/N]"
        if ($darkMode -eq "Y" -or $darkMode -eq "y") {
            Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Value 0 -Type DWord -Force
            Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "SystemUsesLightTheme" -Value 0 -Type DWord -Force
        }
        
        # Optimize visual effects
        $visualEffects = @(
            @{Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects"; Name = "VisualFXSetting"; Value = 2 }
            @{Path = "HKCU:\Software\Microsoft\Windows\DWM"; Name = "EnableAeroPeek"; Value = 0 }
            @{Path = "HKCU:\Software\Microsoft\Windows\DWM"; Name = "AlwaysHibernateThumbnails"; Value = 0 }
        )
        
        foreach ($effect in $visualEffects) {
            Set-ItemProperty -Path $effect.Path -Name $effect.Name -Value $effect.Value -Type DWord -Force
        }
        
        # Restart explorer to apply changes
        Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue
        Start-Process explorer
        
        Write-Host "UI settings optimized" -ForegroundColor Green
    }
}
#endregion
#endregion

#region Main Execution
try {
    # Run modules based on parameters
    if ($RunAllModules -or $Modules -contains "Core") {
        Invoke-CoreModule
    }
    
    if ($RunAllModules -or $Modules -contains "Repair") {
        Invoke-RepairModule
    }
    
    if ($RunAllModules -or $Modules -contains "Refresh") {
        Invoke-RefreshModule
    }
    
    if ($RunAllModules -or $Modules -contains "Optimize") {
        Invoke-OptimizeModule
    }
    
    # Check for pending reboot
    if (-not $PendingReboot) {
        $PendingReboot = Test-PendingReboot
    }
    
    # Display summary
    $TotalTime = [math]::Round(((Get-Date) - $StartTime).TotalMinutes, 2)
    
    Write-Host "`n=== MAINTENANCE SUMMARY ===" -ForegroundColor Cyan
    Write-Host "Execution time: $TotalTime minutes" -ForegroundColor Cyan
    Write-Host "Completed tasks: $($CompletedTasks.Count)" -ForegroundColor Green
    Write-Host "Failed tasks: $($FailedTasks.Count)" -ForegroundColor $(if ($FailedTasks.Count -gt 0) { "Red" } else { "Green" })
    
    if ($FailedTasks.Count -gt 0) {
        Write-Host "`nFailed tasks:" -ForegroundColor Red
        $FailedTasks | ForEach-Object { Write-Host "- $_" -ForegroundColor Red }
    }
    
    # Recommend reboot if needed
    if ($PendingReboot) {
        Write-Host "`nA system reboot is recommended to complete maintenance" -ForegroundColor Yellow
        
        if (-not $NoReboot) {
            $rebootConfirm = Read-Host "Would you like to reboot now? [Y/N]"
            if ($rebootConfirm -eq "Y" -or $rebootConfirm -eq "y") {
                Write-Host "Rebooting in 10 seconds..." -ForegroundColor Magenta
                Start-Sleep -Seconds 10
                Restart-Computer -Force
            }
        }
    }
}
catch {
    Write-Host "An unexpected error occurred:" -ForegroundColor Red
    Write-Host $_ -ForegroundColor Red
}
finally {
    # Ensure transcript is stopped
    Stop-Transcript
    Write-Host "`nLog file saved to: $Log" -ForegroundColor Cyan
}
#endregion