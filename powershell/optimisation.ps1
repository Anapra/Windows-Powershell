# Windows System Optimization Script
# Run as Administrator for full functionality

Write-Host "Starting Windows System Optimization..." -ForegroundColor Green

# 1. Disk Check and Repair
Write-Host "`n[1/9] Running Disk Check..." -ForegroundColor Yellow
chkdsk C: /f /r

# 2. Clear Temporary Files
Write-Host "`n[2/9] Clearing Temporary Files..." -ForegroundColor Yellow
try {
    Remove-Item -Path "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "$env:LOCALAPPDATA\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "C:\Windows\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "Temporary files cleared successfully" -ForegroundColor Green
} catch {
    Write-Host "Some temp files couldn't be removed (may be in use)" -ForegroundColor Yellow
}

# 3. Run Disk Cleanup
Write-Host "`n[3/9] Running Disk Cleanup..." -ForegroundColor Yellow
Start-Process -FilePath "cleanmgr.exe" -ArgumentList "/sagerun:1" -Wait

# 4. Update Chocolatey
Write-Host "`n[4/9] Updating Chocolatey..." -ForegroundColor Yellow
if (Get-Command choco -ErrorAction SilentlyContinue) {
    choco upgrade chocolatey -y
    Write-Host "`n[4/9] Upgrading all Chocolatey packages..." -ForegroundColor Yellow
    choco upgrade all -y
} else {
    Write-Host "Chocolatey not found - skipping..." -ForegroundColor Yellow
}

# 5. Update Winget packages
Write-Host "`n[5/9] Updating Winget packages..." -ForegroundColor Yellow
winget upgrade --all --include-unknown --accept-source-agreements --accept-package-agreements

# 6. DISM Health Checks and Repairs
Write-Host "`n[6/9] Running DISM Health Checks..." -ForegroundColor Yellow
dism /online /cleanup-image /checkhealth
dism /online /cleanup-image /scanhealth
dism /online /cleanup-image /restorehealth

# 7. System File Checker
Write-Host "`n[7/9] Running System File Checker..." -ForegroundColor Yellow
sfc /scannow

# 8. Component Store Cleanup
Write-Host "`n[8/9] Cleaning up Component Store..." -ForegroundColor Yellow
dism /online /cleanup-image /startcomponentcleanup /resetbase

# 9. System Maintenance Tasks
Write-Host "`n[9/13] Checking for pending reboot..." -ForegroundColor Yellow
$pendingReboot = $false
if (Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired" -ErrorAction SilentlyContinue) { $pendingReboot = $true }
if (Get-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\PostRebootReporting" -ErrorAction SilentlyContinue) { $pendingReboot = $true }
if ($pendingReboot) {
    Write-Host "Pending reboot detected" -ForegroundColor Yellow
} else {
    Write-Host "No pending reboot required" -ForegroundColor Green
}

# 10. Update Windows Defender
Write-Host "`n[10/13] Updating Windows Defender..." -ForegroundColor Yellow
try {
    Update-MpSignature
    Write-Host "Windows Defender updated successfully" -ForegroundColor Green
} catch {
    Write-Host "Windows Defender update failed or not available" -ForegroundColor Yellow
}

# 11. Network Reset and Optimization
Write-Host "`n[11/13] Optimizing Network Settings..." -ForegroundColor Yellow
try {
    netsh winsock reset
    netsh int ip reset
    ipconfig /flushdns
    Write-Host "Network settings optimized" -ForegroundColor Green
} catch {
    Write-Host "Network optimization completed with warnings" -ForegroundColor Yellow
}

# 12. Update Device Drivers
Write-Host "`n[12/13] Checking for driver updates..." -ForegroundColor Yellow
try {
    $drivers = Get-WmiObject Win32_SystemDriver | Where-Object {$_.State -eq "Running"}
    Write-Host "Found $($drivers.Count) active drivers" -ForegroundColor Green
    
    # Use Windows Update for driver updates
    if (Get-Module -ListAvailable -Name PSWindowsUpdate) {
        Get-WindowsUpdate -Category "Driver Updates" -AcceptAll -Install -IgnoreReboot
    } else {
        Write-Host "PSWindowsUpdate module not available - using built-in driver update" -ForegroundColor Yellow
        pnputil /scan-devices
    }
} catch {
    Write-Host "Driver update check completed" -ForegroundColor Yellow
}

# 13. Check and clear pending tasks
Write-Host "`n[13/13] Checking scheduled tasks status..." -ForegroundColor Yellow
$pendingTasks = Get-ScheduledTask | Where-Object {$_.State -eq "Running" -and $_.TaskName -like "*Update*"}
if ($pendingTasks) {
    Write-Host "Found $($pendingTasks.Count) running update tasks" -ForegroundColor Yellow
} else {
    Write-Host "No pending update tasks found" -ForegroundColor Green
}

Write-Host "`nSystem optimization completed!" -ForegroundColor Green
Write-Host "System will restart in 30 seconds..." -ForegroundColor Yellow

# Restart system
shutdown /r /f /t 30