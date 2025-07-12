# Dell Inspiron 5430 - Enhanced PowerShell Profile
# Path: $HOME\.config\powershell\profile.ps1

# ===== ENVIRONMENT SETUP =====
$ConfigRoot = "$HOME\.config"
$env:Path += ";$ConfigRoot\scripts"

# ===== MODULES =====
# Terminal visual enhancements - conditional installation
if (-not (Get-Module -ListAvailable -Name Terminal-Icons)) {
    Write-Host "Installing Terminal-Icons module..." -ForegroundColor Cyan
    Install-Module Terminal-Icons -Scope CurrentUser -Force
}
Import-Module Terminal-Icons

# ===== PROMPT CUSTOMIZATION =====
# Check if Oh-My-Posh is installed, install if needed
if (-not (Get-Command oh-my-posh -ErrorAction SilentlyContinue)) {
    Write-Host "Installing Oh-My-Posh..." -ForegroundColor Cyan
    winget install JanDeDobbeleer.OhMyPosh -s winget
}
oh-my-posh init pwsh --config "$env:POSH_THEMES_PATH\cobalt2.omp.json" | Invoke-Expression

# ===== COMMAND LINE EXPERIENCE =====
# PSReadLine configuration for better history and autocomplete
Import-Module PSReadLine
Set-PSReadLineOption -PredictionSource HistoryAndPlugin
Set-PSReadLineOption -PredictionViewStyle ListView
Set-PSReadLineKeyHandler -Key UpArrow -Function HistorySearchBackward
Set-PSReadLineKeyHandler -Key DownArrow -Function HistorySearchForward
Set-PSReadLineKeyHandler -Chord "Ctrl+f" -Function ForwardWord

# ===== USEFUL ALIASES =====
Set-Alias -Name open -Value explorer.exe
Set-Alias -Name touch -Value New-Item
Set-Alias -Name g -Value git

# ===== UTILITY FUNCTIONS =====
# Quick navigation
function .. { Set-Location .. }
function ... { Set-Location ..\.. }
function ~ { Set-Location $HOME }
function cfg { Set-Location $ConfigRoot }

# Enhanced package management function
function Install-App {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Name,
        
        [Parameter(Mandatory=$true)]
        [string]$WingetId,
        
        [string]$ChocoName
    )
    
    Write-Host "Installing $Name..." -ForegroundColor Cyan
    try {
        winget install --id $WingetId --accept-source-agreements --accept-package-agreements
        Write-Host "$Name installed successfully!" -ForegroundColor Green
    } 
    catch {
        Write-Host "Winget installation failed, trying Chocolatey..." -ForegroundColor Yellow
        if (-not $ChocoName) { $ChocoName = $Name.ToLower() }
        
        try {
            # Ensure Chocolatey is installed
            if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
                Write-Host "Installing Chocolatey..." -ForegroundColor Cyan
                Set-ExecutionPolicy Bypass -Scope Process -Force
                [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
                Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
            }
            
            choco install $ChocoName -y
            Write-Host "$Name installed via Chocolatey!" -ForegroundColor Green
        }
        catch {
            Write-Host "Failed to install $Name" -ForegroundColor Red
        }
    }
}

# System diagnostics helper
function Get-SystemInfo {
    $computerInfo = Get-ComputerInfo
    $diskInfo = Get-PSDrive -PSProvider FileSystem
    
    Write-Host "===== DELL INSPIRON 5430 SYSTEM INFO =====" -ForegroundColor Cyan
    Write-Host "OS: $($computerInfo.WindowsProductName) $($computerInfo.WindowsVersion)" -ForegroundColor White
    Write-Host "CPU: $($computerInfo.CsProcessors.Name)" -ForegroundColor White
    Write-Host "RAM: $([math]::Round($computerInfo.CsTotalPhysicalMemory/1GB, 2)) GB" -ForegroundColor White
    
    Write-Host "`nDisk Information:" -ForegroundColor Cyan
    foreach ($disk in $diskInfo) {
        $freePercent = [math]::Round(($disk.Free / $disk.Used) * 100, 2)
        $freeGB = [math]::Round($disk.Free/1GB, 2)
        $usedGB = [math]::Round($disk.Used/1GB, 2)
        
        Write-Host "$($disk.Name): $freeGB GB free of $($freeGB + $usedGB) GB ($freePercent% free)" -ForegroundColor White
    }
}

# Fast directory jumping with fuzzy matching
if (-not (Get-Command z -ErrorAction SilentlyContinue)) {
    Write-Host "Installing zoxide for directory jumping..." -ForegroundColor Cyan
    winget install ajeetdsouza.zoxide
    Invoke-Expression (& { (zoxide init powershell | Out-String) })
}

# ===== WELCOME MESSAGE =====
function Show-Welcome {
    Clear-Host
    Write-Host "Welcome to your Dell Inspiron 5430!" -ForegroundColor Cyan
    Write-Host "PowerShell $($PSVersionTable.PSVersion)" -ForegroundColor White
    Write-Host "Type 'Get-SystemInfo' for system details" -ForegroundColor White
    Write-Host "Type 'Install-App' for package installation" -ForegroundColor White
}

# Show welcome message on startup (comment out if you don't want this)
Show-Welcome