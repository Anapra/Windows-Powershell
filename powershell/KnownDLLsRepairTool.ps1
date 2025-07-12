# Enhanced Registry KnownDLLs Repair Tool
# Requires Administrator privileges and proper permissions handling

param(
    [switch]$Force,
    [switch]$BackupFirst = $true,
    [switch]$Verbose
)

# Check if running as Administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "ERROR: This script must be run as Administrator!" -ForegroundColor Red
    Write-Host "Right-click PowerShell and select 'Run as Administrator'" -ForegroundColor Yellow
    exit 1
}

# Enhanced logging function
function Write-StatusLog {
    param(
        [string]$Message,
        [string]$Status = "INFO", # INFO, SUCCESS, WARNING, ERROR
        [switch]$Verbose
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $color = switch ($Status) {
        "SUCCESS" { "Green" }
        "WARNING" { "Yellow" }
        "ERROR" { "Red" }
        default { "White" }
    }
    
    $prefix = switch ($Status) {
        "SUCCESS" { "✓" }
        "WARNING" { "⚠" }
        "ERROR" { "✗" }
        default { "ℹ" }
    }
    
    Write-Host "[$timestamp] $prefix $Message" -ForegroundColor $color
    
    if ($Verbose -or $Status -eq "ERROR") {
        Add-Content -Path "$env:TEMP\KnownDLLs_Repair_$(Get-Date -Format 'yyyyMMdd').log" -Value "[$timestamp] [$Status] $Message"
    }
}

Write-StatusLog "Starting Enhanced Registry KnownDLLs Repair..." "INFO"

# Registry paths
$knownDLLsPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs"
$knownDLLs32Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs32"

# Suspicious entries that shouldn't be in KnownDLLs
$suspiciousEntries = @(
    "xtajit64se",
    "xtajit64", 
    "_wowarmhw",
    "_wow64cpu",
    "wow64cpu",
    "wow64win",
    "xtajit",
    "wowreg32",
    "wow64base",
    "wow64con"
)

# Valid KnownDLLs entries (Windows 10/11 standard)
$validKnownDLLs = @(
    "ADVAPI32", "COMDLG32", "GDI32", "KERNEL32", "LZ32", "MSVCRT", 
    "OLEAUT32", "OLE32", "RPCRT4", "SHELL32", "USER32", "VERSION",
    "WINMM", "WINSPOOL", "WS2_32", "WS2HELP", "NTDLL", "PSAPI",
    "IMAGEHLP", "WLDAP32", "SETUPAPI", "MPR", "MPRAPI", "WININET",
    "URLMON", "SECUR32", "NETAPI32", "USERENV", "CRYPT32", "CRYPTSP",
    "clbcatq", "combase", "coml2", "DifxApi", "gdiplus", "IMM32",
    "MSCTF", "NORMALIZ", "NSI", "sechost", "SHCORE", "SHLWAPI",
    "wow64", "wow64base", "wow64con", "wow64win", "_xtajit"
)

# Function to enable registry key permissions
function Enable-RegistryKeyPermissions {
    param(
        [string]$RegistryPath
    )
    
    try {
        Write-StatusLog "Attempting to enable permissions for: $RegistryPath" "INFO"
        
        # Method 1: Using .NET Registry classes for better control
        $registryHive = [Microsoft.Win32.Registry]::LocalMachine
        $subKey = $RegistryPath.Replace("HKLM:\", "").Replace("\", "\")
        
        # Open with write access
        $regKey = $registryHive.OpenSubKey($subKey, $true)
        if ($regKey -eq $null) {
            Write-StatusLog "Could not open registry key: $RegistryPath" "ERROR"
            return $false
        }
        
        Write-StatusLog "Successfully opened registry key with write access" "SUCCESS"
        return $regKey
        
    }
    catch {
        Write-StatusLog "Failed to enable permissions: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

# Function to take ownership of registry key using external tools
function Take-RegistryOwnership {
    param(
        [string]$RegistryPath
    )
    
    try {
        Write-StatusLog "Attempting to take ownership of registry key..." "INFO"
        
        # Convert PowerShell path to reg.exe format
        $regPath = $RegistryPath.Replace("HKLM:\", "HKEY_LOCAL_MACHINE\")
        
        # Take ownership using regini (built into Windows)
        $reginiContent = @"
$regPath [1 17]
"@
        $reginiFile = "$env:TEMP\takown.ini"
        $reginiContent | Out-File -FilePath $reginiFile -Encoding ASCII
        
        $result = Start-Process -FilePath "regini.exe" -ArgumentList $reginiFile -Wait -PassThru -WindowStyle Hidden
        
        Remove-Item $reginiFile -Force -ErrorAction SilentlyContinue
        
        if ($result.ExitCode -eq 0) {
            Write-StatusLog "Successfully took ownership of registry key" "SUCCESS"
            return $true
        }
        else {
            Write-StatusLog "Failed to take ownership (Exit code: $($result.ExitCode))" "ERROR"
            return $false
        }
        
    }
    catch {
        Write-StatusLog "Ownership attempt failed: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

# Function to backup registry key
function Backup-RegistryKey {
    param(
        [string]$RegistryPath,
        [string]$BackupPath
    )
    
    try {
        Write-StatusLog "Creating backup of registry key..." "INFO"
        
        $regPath = $RegistryPath.Replace("HKLM:\", "HKEY_LOCAL_MACHINE\")
        $backupFile = "$BackupPath\KnownDLLs_Backup_$(Get-Date -Format 'yyyyMMdd_HHmmss').reg"
        
        $result = Start-Process -FilePath "reg.exe" -ArgumentList "export", "`"$regPath`"", "`"$backupFile`"", "/y" -Wait -PassThru -WindowStyle Hidden
        
        if ($result.ExitCode -eq 0 -and (Test-Path $backupFile)) {
            Write-StatusLog "Backup created: $backupFile" "SUCCESS"
            return $backupFile
        }
        else {
            Write-StatusLog "Backup creation failed" "ERROR"
            return $null
        }
        
    }
    catch {
        Write-StatusLog "Backup failed: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

# Function to remove suspicious registry entries
function Remove-SuspiciousKnownDLL {
    param(
        [string]$EntryName,
        [string]$RegistryPath
    )
    
    try {
        Write-StatusLog "Attempting to remove suspicious entry: $EntryName" "INFO"
        
        # Method 1: Direct PowerShell removal with elevated privileges
        try {
            $acl = Get-Acl -Path $RegistryPath
            $rule = New-Object System.Security.AccessControl.RegistryAccessRule(
                [System.Security.Principal.WindowsIdentity]::GetCurrent().Name,
                "FullControl",
                "Allow"
            )
            $acl.SetAccessRule($rule)
            Set-Acl -Path $RegistryPath -AclObject $acl
            
            Remove-ItemProperty -Path $RegistryPath -Name $EntryName -Force -ErrorAction Stop
            Write-StatusLog "Successfully removed $EntryName using PowerShell" "SUCCESS"
            return $true
        }
        catch {
            Write-StatusLog "PowerShell removal failed, trying alternative methods..." "WARNING"
        }
        
        # Method 2: Using reg.exe with elevated privileges
        try {
            $regPath = $RegistryPath.Replace("HKLM:\", "HKEY_LOCAL_MACHINE\")
            $result = Start-Process -FilePath "reg.exe" -ArgumentList "delete", "`"$regPath`"", "/v", $EntryName, "/f" -Wait -PassThru -WindowStyle Hidden -Verb RunAs
            
            if ($result.ExitCode -eq 0) {
                Write-StatusLog "Successfully removed $EntryName using reg.exe" "SUCCESS"
                return $true
            }
        }
        catch {
            Write-StatusLog "reg.exe removal failed" "WARNING"
        }
        
        # Method 3: Using .NET Registry classes with full permissions
        try {
            if (Take-RegistryOwnership -RegistryPath $RegistryPath) {
                Start-Sleep -Seconds 2
                
                # Get the registry key
                $registryHive = [Microsoft.Win32.Registry]::LocalMachine
                $subKey = $RegistryPath.Replace("HKLM:\", "").Replace("\", "\")
                $regKey = $registryHive.OpenSubKey($subKey, $true)
                
                if ($regKey -ne $null) {
                    $regKey.DeleteValue($EntryName, $true)
                    $regKey.Close()
                    Write-StatusLog "Successfully removed $EntryName using .NET Registry" "SUCCESS"
                    return $true
                }
            }
        }
        catch {
            Write-StatusLog "Ownership-based removal failed" "WARNING"
        }
        
        # Method 4: Using regini with full permissions
        try {
            $regPath = $RegistryPath.Replace("HKLM:\", "HKEY_LOCAL_MACHINE\")
            $reginiContent = @"
$regPath [1 17]
$regPath\$EntryName [1 17]
"@
            $reginiFile = "$env:TEMP\takown.ini"
            $reginiContent | Out-File -FilePath $reginiFile -Encoding ASCII
            
            $result = Start-Process -FilePath "regini.exe" -ArgumentList $reginiFile -Wait -PassThru -WindowStyle Hidden -Verb RunAs
            
            Remove-Item $reginiFile -Force -ErrorAction SilentlyContinue
            
            if ($result.ExitCode -eq 0) {
                Remove-ItemProperty -Path $RegistryPath -Name $EntryName -Force -ErrorAction Stop
                Write-StatusLog "Successfully removed $EntryName using regini" "SUCCESS"
                return $true
            }
        }
        catch {
            Write-StatusLog "regini removal failed" "WARNING"
        }
        
        Write-StatusLog "All removal methods failed for $EntryName" "ERROR"
        return $false
        
    }
    catch {
        Write-StatusLog "Unexpected error removing $EntryName : $($_.Exception.Message)" "ERROR"
        return $false
    }
}

# Function to validate KnownDLLs integrity
function Test-KnownDLLsIntegrity {
    param(
        [string]$RegistryPath
    )
    
    try {
        Write-StatusLog "Validating KnownDLLs integrity..." "INFO"
        
        if (!(Test-Path $RegistryPath)) {
            Write-StatusLog "KnownDLLs registry path does not exist!" "ERROR"
            return $false
        }
        
        $currentEntries = Get-ItemProperty -Path $RegistryPath -ErrorAction SilentlyContinue
        if (!$currentEntries) {
            Write-StatusLog "Could not read KnownDLLs registry entries" "ERROR"
            return $false
        }
        
        $suspiciousFound = @()
        $validCount = 0
        
        foreach ($property in $currentEntries.PSObject.Properties) {
            if ($property.Name -in @("PSPath", "PSParentPath", "PSChildName", "PSDrive", "PSProvider")) {
                continue
            }
            
            if ($property.Name -in $suspiciousEntries) {
                $suspiciousFound += $property.Name
                Write-StatusLog "Found suspicious entry: $($property.Name) = $($property.Value)" "WARNING"
            }
            elseif ($property.Name -in $validKnownDLLs -or $property.Name -eq "DllDirectory") {
                $validCount++
                if ($Verbose) {
                    Write-StatusLog "Valid entry: $($property.Name) = $($property.Value)" "INFO"
                }
            }
            else {
                Write-StatusLog "Unknown entry (manual review needed): $($property.Name) = $($property.Value)" "WARNING"
            }
        }
        
        Write-StatusLog "Integrity check complete: $validCount valid entries, $($suspiciousFound.Count) suspicious entries" "INFO"
        return @{
            IsSuspicious      = $suspiciousFound.Count -gt 0
            SuspiciousEntries = $suspiciousFound
            ValidCount        = $validCount
        }
        
    }
    catch {
        Write-StatusLog "Integrity check failed: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

# Main execution
Write-StatusLog "Starting KnownDLLs repair process..." "INFO"

# Create backup if requested
if ($BackupFirst) {
    $backupDir = "$env:USERPROFILE\Desktop\Registry_Backups"
    if (!(Test-Path $backupDir)) {
        New-Item -Path $backupDir -ItemType Directory -Force | Out-Null
    }
    
    $backupFile = Backup-RegistryKey -RegistryPath $knownDLLsPath -BackupPath $backupDir
    if ($backupFile) {
        Write-StatusLog "Backup completed successfully" "SUCCESS"
    }
    else {
        Write-StatusLog "Backup failed - continuing anyway..." "WARNING"
    }
}

# Check current state
$integrityResult = Test-KnownDLLsIntegrity -RegistryPath $knownDLLsPath

if ($integrityResult -is [hashtable] -and $integrityResult.IsSuspicious) {
    Write-StatusLog "Found $($integrityResult.SuspiciousEntries.Count) suspicious entries to remove" "WARNING"
    
    $successCount = 0
    $failCount = 0
    
    foreach ($suspiciousEntry in $integrityResult.SuspiciousEntries) {
        Write-StatusLog "Processing suspicious entry: $suspiciousEntry" "INFO"
        
        if (Remove-SuspiciousKnownDLL -EntryName $suspiciousEntry -RegistryPath $knownDLLsPath) {
            $successCount++
        }
        else {
            $failCount++
        }
        
        Start-Sleep -Milliseconds 500
    }
    
    Write-StatusLog "Removal complete: $successCount successful, $failCount failed" "INFO"
    
    # Final integrity check
    Write-StatusLog "Performing final integrity check..." "INFO"
    $finalCheck = Test-KnownDLLsIntegrity -RegistryPath $knownDLLsPath
    
    if ($finalCheck -is [hashtable] -and !$finalCheck.IsSuspicious) {
        Write-StatusLog "KnownDLLs registry successfully cleaned!" "SUCCESS"
    }
    else {
        Write-StatusLog "Some suspicious entries may remain - manual intervention required" "WARNING"
    }
    
}
else {
    Write-StatusLog "No suspicious entries found in KnownDLLs registry" "SUCCESS"
}

# Additional system checks
Write-StatusLog "Running additional system integrity checks..." "INFO"

# Check for system file corruption
try {
    Write-StatusLog "Running System File Checker..." "INFO"
    $sfcResult = Start-Process -FilePath "sfc.exe" -ArgumentList "/scannow" -Wait -PassThru -WindowStyle Hidden
    if ($sfcResult.ExitCode -eq 0) {
        Write-StatusLog "System File Checker completed successfully" "SUCCESS"
    }
    else {
        Write-StatusLog "System File Checker reported issues (Exit code: $($sfcResult.ExitCode))" "WARNING"
    }
}
catch {
    Write-StatusLog "Could not run System File Checker: $($_.Exception.Message)" "ERROR"
}

# Restart recommendation
Write-StatusLog "Registry repair process completed!" "SUCCESS"
Write-StatusLog "It is recommended to restart your computer to ensure all changes take effect." "INFO"

$restart = Read-Host "Would you like to restart now? (Y/N)"
if ($restart -eq "Y" -or $restart -eq "y") {
    Write-StatusLog "Restarting computer in 10 seconds..." "INFO"
    Start-Sleep -Seconds 10
    Restart-Computer -Force
}
else {
    Write-StatusLog "Please restart your computer manually when convenient." "INFO"
}

Write-StatusLog "Log file saved to: $env:TEMP\KnownDLLs_Repair_$(Get-Date -Format 'yyyyMMdd').log" "INFO"