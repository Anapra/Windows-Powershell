<#
.SYNOPSIS
    Enhanced Registry Tweaks for Windows 11 Pro (Workstation) v2.1
.DESCRIPTION
    Applies registry tweaks with:
    - Pre-application validation
    - Backup/restore functionality
    - System compatibility checks
    - Transactional rollback capability
    - Default user hive handling
.EXAMPLE
    .\RegTweaks.ps1
    Applies all registry tweaks with backups
.EXAMPLE
    .\RegTweaks.ps1 -DryRun
    Shows which registry tweaks would be applied without making changes
.EXAMPLE
    .\RegTweaks.ps1 -RestoreBackup "C:\Path\To\Backup.reg"
    Restores registry from a backup file
.PARAMETER DryRun
    When specified, performs a simulation without making changes
.PARAMETER RestoreBackup
    Path to a backup file to restore instead of applying tweaks
.NOTES
    Version: 2.1
    Author: Your Name
    Date: $(Get-Date -Format "yyyy-MM-dd")
#>

[CmdletBinding(DefaultParameterSetName = "Apply")]
param(
    [Parameter(ParameterSetName = "Apply")]
    [switch]$DryRun = $false,
    
    [Parameter(ParameterSetName = "Restore", Mandatory = $true)]
    [string]$RestoreBackup
)

#region Initialization
$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

# Backup directory
$backupDir = "$env:ProgramData\RegTweaks\Backups"
if (-not (Test-Path $backupDir)) { New-Item -ItemType Directory -Path $backupDir -Force | Out-Null }

# Logging
$logDir = "$env:USERPROFILE\.config\powershell\log"
if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }

# Use separate files for transcript and custom logging
$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$transcriptFile = "$logDir\Transcript_RegTweaks_$timestamp.txt"
$logFile = "$logDir\RegTweaks_$timestamp.log"

# Start transcript in a separate file
Start-Transcript -Path $transcriptFile -Append

# Enhanced logging with file locking protection
function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter()]
        [ValidateSet('Info', 'Warning', 'Error', 'Success')]
        [string]$Level = 'Info'
    )
    
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logEntry = "[$timestamp] [$Level] $Message"
    
    switch ($Level) {
        'Info' { Write-Host $logEntry -ForegroundColor Cyan }
        'Warning' { Write-Host $logEntry -ForegroundColor Yellow }
        'Error' { Write-Host $logEntry -ForegroundColor Red }
        'Success' { Write-Host $logEntry -ForegroundColor Green }
    }
    
    # Use a try-catch block to handle potential file access issues
    try {
        # Use a mutex to prevent concurrent access
        $mutex = New-Object System.Threading.Mutex($false, "RegTweaksLogMutex")
        $mutex.WaitOne() | Out-Null
        
        try {
            Add-Content -Path $logFile -Value $logEntry -ErrorAction Stop
        }
        finally {
            $mutex.ReleaseMutex()
            $mutex.Dispose()
        }
    }
    catch {
        # If we can't write to the log file, just continue with console output
        Write-Host "Warning: Could not write to log file: $_" -ForegroundColor Yellow
    }
}

# Check if running as administrator
function Test-Administrator {
    $currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Administrator)) {
    Write-Log -Message "This script requires administrator privileges. Please run PowerShell as Administrator." -Level Error
    Stop-Transcript
    exit 1
}
#endregion

#region Registry Operations
class RegistryTweak {
    [string]$Path
    [string]$Name
    [string]$Type
    [string]$Value
    [string]$Description
    [Version]$MinOSVersion
    [bool]$RequiresReboot = $false
}

# Load registry tweaks from JSON or fallback to default
$registryTweaks = @()
$registryTweaksPath = Join-Path $PSScriptRoot "RegTweaks.json"

if (Test-Path $registryTweaksPath) {
    try {
        $tweaksJson = Get-Content -Path $registryTweaksPath -Raw
        $tweaksData = $tweaksJson | ConvertFrom-Json
        
        # Convert JSON objects to RegistryTweak objects
        $registryTweaks = $tweaksData | ForEach-Object {
            $tweak = [RegistryTweak]::new()
            $tweak.Path = $_.Path
            $tweak.Name = $_.Name
            $tweak.Type = $_.Type
            $tweak.Value = $_.Value
            $tweak.Description = $_.Description
            if ($_.MinOSVersion) { $tweak.MinOSVersion = [Version]$_.MinOSVersion }
            if ($null -ne $_.RequiresReboot) { $tweak.RequiresReboot = [bool]$_.RequiresReboot }
            $tweak
        }
        
        Write-Log -Message "Loaded registry tweaks from $registryTweaksPath" -Level Success
    }
    catch {
        Write-Log -Message "Error loading registry tweaks from JSON: $_" -Level Error
        # Fall back to default tweaks
    }
}

# Fallback to default tweaks if JSON loading failed
if ($registryTweaks.Count -eq 0) {
    Write-Log -Message "Using default registry tweaks" -Level Info
    
    $registryTweaks = @(
        [RegistryTweak]@{
            Path        = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
            Name        = "ShowSyncProviderNotifications"
            Type        = "DWORD"
            Value       = "0"
            Description = "Disable sync provider notifications"
        }
        [RegistryTweak]@{
            Path        = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
            Name        = "HideFileExt"
            Type        = "DWORD"
            Value       = "0"
            Description = "Show file extensions"
        }
        [RegistryTweak]@{
            Path        = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
            Name        = "Hidden"
            Type        = "DWORD"
            Value       = "1"
            Description = "Show hidden files"
        }
    )
}

function Validate-RegistryValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Type,
        
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Value
    )
    
    switch ($Type) {
        "DWORD" {
            [int]$intValue = 0
            return [int]::TryParse($Value, [ref]$intValue)
        }
        "QWORD" {
            [long]$longValue = 0
            return [long]::TryParse($Value, [ref]$longValue)
        }
        "String" { return $true }
        "ExpandString" { return $true }
        "MultiString" { return $true }
        "Binary" {
            try {
                [byte[]]$bytes = $Value.Split(',') | ForEach-Object { [byte]$_ }
                return $true
            }
            catch {
                return $false
            }
        }
        default { return $false }
    }
}

function Backup-RegistryKey {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path
    )
    
    $backupFile = "$backupDir\$(($Path -replace '[\\:]','_'))_$(Get-Date -Format 'yyyyMMddHHmmss').reg"
    
    try {
        reg export $Path $backupFile /y | Out-Null
        Write-Log -Message "Backed up registry key $Path to $backupFile" -Level Info
        return $backupFile
    }
    catch {
        Write-Log -Message "Failed to backup registry key ${Path}: $_" -Level Error
        return $null
    }
}

function Restore-RegistryBackup {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$BackupFile
    )
    
    if (Test-Path $BackupFile) {
        try {
            reg import $BackupFile | Out-Null
            Write-Log -Message "Successfully restored registry from $BackupFile" -Level Success
            return $true
        }
        catch {
            Write-Log -Message "Failed to restore registry from ${BackupFile}: $_" -Level Error
            return $false
        }
    }
    else {
        Write-Log -Message "Backup file not found: $BackupFile" -Level Error
        return $false
    }
}

function Verify-RegistryChange {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [RegistryTweak]$Tweak
    )
    
    try {
        $actualValue = Get-ItemProperty -Path $Tweak.Path -Name $Tweak.Name -ErrorAction Stop
        $propertyName = $Tweak.Name
        
        if ($actualValue.$propertyName -eq $Tweak.Value) {
            return $true
        }
        
        Write-Log -Message "Registry value verification failed: Expected '$($Tweak.Value)' but got '$($actualValue.$propertyName)'" -Level Warning
        return $false
    }
    catch {
        Write-Log -Message "Could not verify registry change: $_" -Level Warning
        return $false
    }
}

function Apply-RegistryTweak {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [RegistryTweak]$Tweak,
        
        [Parameter()]
        [switch]$DryRun = $false
    )
    
    try {
        # Check OS version compatibility
        if ($Tweak.MinOSVersion -and [Environment]::OSVersion.Version -lt $Tweak.MinOSVersion) {
            Write-Log -Message "$($Tweak.Description) requires Windows $($Tweak.MinOSVersion) or newer" -Level Warning
            return $false
        }

        # Validate registry value
        if (-not (Validate-RegistryValue -Type $Tweak.Type -Value $Tweak.Value)) {
            Write-Log -Message "Invalid registry value for $($Tweak.Description): Type=$($Tweak.Type), Value=$($Tweak.Value)" -Level Error
            return $false
        }
        
        # For dry run, just report
        if ($DryRun) {
            Write-Log -Message "Would apply: $($Tweak.Description) [$($Tweak.Path)\$($Tweak.Name) = $($Tweak.Value)]" -Level Info
            return $Tweak.RequiresReboot
        }
        
        # Backup original value
        $backupFile = Backup-RegistryKey -Path $Tweak.Path
        
        # Apply tweak
        if (-not (Test-Path $Tweak.Path)) {
            New-Item -Path $Tweak.Path -Force | Out-Null
            Write-Log -Message "Created registry key: $($Tweak.Path)" -Level Info
        }
        
        Set-ItemProperty -Path $Tweak.Path -Name $Tweak.Name -Value $Tweak.Value -Type $Tweak.Type -Force
        
        # Verify the change was applied correctly
        if (Verify-RegistryChange -Tweak $Tweak) {
            Write-Log -Message "Applied: $($Tweak.Description)" -Level Success
            if ($backupFile) {
                Write-Log -Message "Backup saved to: $backupFile" -Level Info
            }
            return $Tweak.RequiresReboot
        }
        else {
            Write-Log -Message "Failed to verify registry change for $($Tweak.Description)" -Level Warning
            return $false
        }
    }
    catch [System.UnauthorizedAccessException] {
        Write-Log -Message "Access denied when applying $($Tweak.Description): $_" -Level Error
        return $false
    }
    catch [System.IO.IOException] {
        Write-Log -Message "I/O error when applying $($Tweak.Description): $_" -Level Error
        return $false
    }
    catch {
        Write-Log -Message "Failed to apply $($Tweak.Description): $_" -Level Error
        return $false
    }
}
#endregion

#region Main Execution
if ($PSCmdlet.ParameterSetName -eq "Restore") {
    # Restore mode
    Write-Log -Message "Restoring registry from backup: $RestoreBackup" -Level Info
    $result = Restore-RegistryBackup -BackupFile $RestoreBackup
    if ($result) {
        Write-Log -Message "Registry restore completed successfully" -Level Success
    }
    else {
        Write-Log -Message "Registry restore failed" -Level Error
        exit 1
    }
}
else {
    # Apply mode
    if ($DryRun) {
        Write-Log -Message "=== DRY RUN MODE ===" -Level Info
    }
    else {
        Write-Log -Message "=== APPLYING REGISTRY TWEAKS ===" -Level Info
    }
    
    # Process tweaks
    $needsReboot = $false
    $successCount = 0
    $failureCount = 0
    
    foreach ($tweak in $registryTweaks) {
        $result = Apply-RegistryTweak -Tweak $tweak -DryRun:$DryRun
        if ($result) { 
            $needsReboot = $true 
            $successCount++
        }
        elseif ($null -eq $result) {
            # Skipped
        }
        else {
            $failureCount++
        }
    }
    
    Write-Log -Message "Registry tweaks: $successCount succeeded, $failureCount failed" -Level Info
    
    # Default user hive handling with transaction
    if (-not $DryRun) {
        try {
            Write-Log -Message "Configuring default user registry..." -Level Info
            
            # Load default user hive
            reg load "HKU\DefaultUser" "C:\Users\Default\NTUSER.DAT"
            
            $defaultUserTweaks = @(
                [RegistryTweak]@{
                    Path        = "HKU:\DefaultUser\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
                    Name        = "SystemPaneSuggestionsEnabled"
                    Type        = "DWORD"
                    Value       = "0"
                    Description = "Disable suggestions for default user"
                }
            )
            
            foreach ($tweak in $defaultUserTweaks) {
                $result = Apply-RegistryTweak -Tweak $tweak
                if ($result) { $needsReboot = $true }
            }
            
            # Unload default user hive
            reg unload "HKU\DefaultUser"
            
            Write-Log -Message "Default user registry configuration completed" -Level Success
        }
        catch {
            Write-Log -Message "Failed to configure default user registry: $_" -Level Error
            # Try to unload the hive if it was loaded
            try {
                reg unload "HKU\DefaultUser" 2>$null
            }
            catch {
                Write-Log -Message "Failed to unload default user hive: $_" -Level Warning
            }
        }
    }
    
    # Export RegistryTweaks.json template if it doesn't exist
    if (-not (Test-Path $registryTweaksPath)) {
        $tweaksTemplate = $registryTweaks | ForEach-Object {
            [PSCustomObject]@{
                Path           = $_.Path
                Name           = $_.Name
                Type           = $_.Type
                Value          = $_.Value
                Description    = $_.Description
                MinOSVersion   = $_.MinOSVersion.ToString()
                RequiresReboot = $_.RequiresReboot
            }
        }
        
        $tweaksTemplate | ConvertTo-Json -Depth 3 | Out-File -FilePath $registryTweaksPath
        Write-Log -Message "Created template registry tweaks at $registryTweaksPath" -Level Info
    }
    
    # Handle reboot requirement
    if ($needsReboot -and -not $DryRun) {
        Write-Log -Message "Some changes require a reboot to take effect." -Level Warning
        $choice = Read-Host "Reboot now? (Y/N)"
        if ($choice -eq 'Y' -or $choice -eq 'y') {
            Write-Log -Message "Initiating system reboot..." -Level Info
            Restart-Computer -Force
        }
    }
}

Write-Log -Message "Operation completed. Log saved to $logFile" -Level Info
Stop-Transcript
#endregion