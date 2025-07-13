<#
.SYNOPSIS
    Main PowerShell profile for Windows. Modular, secure, and cloud-ready. Loads aliases, functions, settings, and customizes the shell environment.
#>
# Optimized PowerShell 7.5.2 Profile
# Performance-first configuration with cloud-ready tools

# --- Define ConfigDir globally ---
$global:ConfigDir = "$HOME\.config\powershell"

# --- Security: Execution Policy ---
# SECURITY WARNING:
# Setting execution policy to RemoteSigned allows local scripts to run, but blocks unsigned remote scripts.
# Only set this if you understand the implications. See: https://go.microsoft.com/fwlink/?LinkID=135170
if ((Get-ExecutionPolicy -Scope CurrentUser) -ne 'RemoteSigned') {
    try {
        Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force
    }
    catch {
        Write-Host "Could not set execution policy. Please run as administrator if needed." -ForegroundColor Yellow
    }
}

# --- Dot-source modular files ---
if (Test-Path "$global:ConfigDir\aliases.ps1") { . "$global:ConfigDir\aliases.ps1" }
if (Test-Path "$global:ConfigDir\functions.ps1") { . "$global:ConfigDir\functions.ps1" }
if (Test-Path "$global:ConfigDir\settings.ps1") { . "$global:ConfigDir\settings.ps1" }

# --- Profile timing start ---
$profileStart = Get-Date
#------------------------------------------------------------------------------
# Performance Settings
#------------------------------------------------------------------------------
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'

# Disable unnecessary features for speed
$env:POWERSHELL_TELEMETRY_OPTOUT = '1'
$env:DOTNET_CLI_TELEMETRY_OPTOUT = '1'

#------------------------------------------------------------------------------
# Module Management (Optimized)
#------------------------------------------------------------------------------
function Install-ModuleIfMissing {
    param([string]$ModuleName, [switch]$SkipPublisherCheck)
    
    if (-not (Get-Module -ListAvailable -Name $ModuleName)) {
        Write-Host "Installing $ModuleName..." -ForegroundColor Yellow
        $params = @{
            Name       = $ModuleName
            Scope      = 'CurrentUser'
            Force      = $true
            Repository = 'PSGallery'
        }
        if ($SkipPublisherCheck) { $params['SkipPublisherCheck'] = $true }
        Install-Module @params
    }
    Import-Module $ModuleName -Global -Force
}

#------------------------------------------------------------------------------
# Core Modules (Lazy Loading)
#------------------------------------------------------------------------------
$coreModules = @(
    @{Name = 'PSReadLine'; Critical = $true },
    @{Name = 'Terminal-Icons'; Critical = $false },
    @{Name = 'posh-git'; Critical = $false; Condition = { Get-Command git -ErrorAction SilentlyContinue } }
)

foreach ($module in $coreModules) {
    if ($module.Critical -or (-not $module.Condition) -or (& $module.Condition)) {
        Install-ModuleIfMissing -ModuleName $module.Name -SkipPublisherCheck
    }
}

# --- Cascadia Code Font Check/Install Helper ---
function Ensure-CascadiaCodeFont {
    $fontName = "Cascadia Code"
    $fontRegPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts"
    $fontInstalled = Get-ItemProperty -Path $fontRegPath -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "${fontName} (TrueType)" -ErrorAction SilentlyContinue
    if (-not $fontInstalled) {
        Write-Host "Cascadia Code font not found. Downloading and installing..." -ForegroundColor Yellow
        $url = "https://github.com/microsoft/cascadia-code/releases/latest/download/CascadiaCode-ttf.zip"
        $zipPath = "$env:TEMP\CascadiaCode-ttf.zip"
        $fontDir = "$env:TEMP\CascadiaCodeFont"
        Invoke-WebRequest -Uri $url -OutFile $zipPath
        Expand-Archive -Path $zipPath -DestinationPath $fontDir -Force
        $ttfs = Get-ChildItem -Path $fontDir -Filter *.ttf
        foreach ($ttf in $ttfs) {
            Copy-Item $ttf.FullName -Destination "$env:WINDIR\Fonts" -Force
        }
        Write-Host "Cascadia Code font installed. Please set it in your terminal settings." -ForegroundColor Green
        Remove-Item $zipPath -Force
        Remove-Item $fontDir -Recurse -Force
    }
}
# Call this function if you want to ensure font is present
# Ensure-CascadiaCodeFont

# --- Auto-Reload Profile on Change ---
$global:__ProfileLastWrite = (Get-Item $PROFILE).LastWriteTime
function Test-ProfileReload {
    $currentWrite = (Get-Item $PROFILE).LastWriteTime
    if ($currentWrite -ne $global:__ProfileLastWrite) {
        Write-Host "Profile changed. Reloading..." -ForegroundColor Yellow
        . $PROFILE
        $global:__ProfileLastWrite = $currentWrite
    }
}
# Add to your prompt function:
if (Test-Path function:prompt) {
    $oldPrompt = (Get-Content function:prompt)
    function prompt {
        Test-ProfileReload
        & $oldPrompt
    }
}
else {
    function prompt {
        Test-ProfileReload
        "PS $($executionContext.SessionState.Path.CurrentLocation)> "
    }
}

# --- Fixed Admin Function (No Dialog, Reliable) ---
function admin {
    $pwshPath = (Get-Command pwsh -ErrorAction SilentlyContinue).Source
    $ps5Path = (Get-Command powershell.exe -ErrorAction SilentlyContinue).Source
    $currentDir = $PWD.Path
    $profileCmd = ". '$PROFILE'"
    if ($pwshPath) {
        Start-Process -FilePath $pwshPath -Verb RunAs -ArgumentList "-NoProfile -NoExit -Command Set-Location '$currentDir'; $profileCmd"
    }
    elseif ($ps5Path) {
        Start-Process -FilePath $ps5Path -Verb RunAs -ArgumentList "-NoProfile -NoExit -Command Set-Location '$currentDir'; $profileCmd"
    }
    else {
        Write-Host "No suitable PowerShell executable found for admin session." -ForegroundColor Red
    }
}

#------------------------------------------------------------------------------
# PSReadLine Configuration (Enhanced)
#------------------------------------------------------------------------------
if (Get-Module PSReadLine) {
    Set-PSReadLineOption -PredictionSource HistoryAndPlugin
    Set-PSReadLineOption -PredictionViewStyle ListView
    Set-PSReadLineOption -EditMode Windows
    Set-PSReadLineOption -HistorySaveStyle SaveIncrementally
    Set-PSReadLineOption -MaximumHistoryCount 4000
    Set-PSReadLineOption -ShowToolTips
    
    # Key bindings
    Set-PSReadLineKeyHandler -Key Tab -Function MenuComplete
    Set-PSReadLineKeyHandler -Key UpArrow -Function HistorySearchBackward
    Set-PSReadLineKeyHandler -Key DownArrow -Function HistorySearchForward
    Set-PSReadLineKeyHandler -Key "Ctrl+Spacebar" -Function AcceptSuggestion
    Set-PSReadLineKeyHandler -Key "Ctrl+f" -Function ForwardWord
    Set-PSReadLineKeyHandler -Key "Ctrl+r" -Function ReverseSearchHistory
}

#------------------------------------------------------------------------------
# Oh My Posh (Conditional Loading)
#------------------------------------------------------------------------------
$themePath = "$env:CONFIG_ROOT\powershell\themes\cobalt2.omp.json"
if ((Get-Command oh-my-posh -ErrorAction SilentlyContinue) -and (Test-Path $themePath)) {
    oh-my-posh init pwsh --config $themePath | Invoke-Expression
}
else {
    # Fallback minimal prompt
    function prompt {
        $location = $ExecutionContext.SessionState.Path.CurrentLocation
        $gitBranch = if (Get-Command git -ErrorAction SilentlyContinue) {
            $branch = git branch --show-current 2>$null
            if ($branch) { " ($branch)" }
        }
        "$($location)$gitBranch> "
    }
}

#------------------------------------------------------------------------------
# Zoxide Integration (Smart Directory Navigation)
#------------------------------------------------------------------------------
if (Get-Command zoxide -ErrorAction SilentlyContinue) {
    Invoke-Expression (& { (zoxide init powershell | Out-String) })
}

#------------------------------------------------------------------------------
# GCP/Cloud Aliases and Functions
#------------------------------------------------------------------------------
# Google Cloud SDK shortcuts
if (Get-Command gcloud -ErrorAction SilentlyContinue) {
    function gcl { gcloud auth list }
    function gcp { gcloud config set project $args[0] }
    function gcs { gcloud config set compute/zone $args[0] }
    function gce { gcloud compute instances list }
    function gck { gcloud container clusters get-credentials $args[0] --zone $args[1] }
}

# Kubernetes shortcuts
if (Get-Command kubectl -ErrorAction SilentlyContinue) {
    function k { kubectl $args }
    function kgp { kubectl get pods }
    function kgs { kubectl get services }
    function kgn { kubectl get nodes }
    function kdesc { kubectl describe $args }
    function klogs { kubectl logs $args }
}

# Docker shortcuts
if (Get-Command docker -ErrorAction SilentlyContinue) {
    function d { docker $args }
    function dps { docker ps }
    function dimg { docker images }
    function drun { docker run -it $args }
    function dstop { docker stop $(docker ps -q) }
    function dclean { docker system prune -af }
}

#------------------------------------------------------------------------------
# Enhanced Git Functions
#------------------------------------------------------------------------------
if (Get-Command git -ErrorAction SilentlyContinue) {
    function g { git $args }
    function gs { git status --short }
    function ga { git add $args }
    function gc { git commit -m $args }
    function gp { git push }
    function gpl { git pull }
    function gco { git checkout $args }
    function gb { git branch $args }
    function gl { git log --oneline --graph --decorate -10 }
    function gd { git diff $args }
    function gclone { git clone $args }
    function gremote { git remote -v }
}

#------------------------------------------------------------------------------
# System Utilities (Performance Optimized)
#------------------------------------------------------------------------------
function reload { 
    Clear-Host
    . $PROFILE 
    Write-Host "Profile reloaded successfully!" -ForegroundColor Green
}

function update-all {
    Write-Host "Updating system packages..." -ForegroundColor Yellow
    if (Get-Command winget -ErrorAction SilentlyContinue) { 
        winget upgrade --all --accept-source-agreements 
    }
    if (Get-Command choco -ErrorAction SilentlyContinue) { 
        choco upgrade all -y 
    }
    Update-Module -Force
    Write-Host "System updated!" -ForegroundColor Green
}

function which { 
    param([string]$command)
    (Get-Command $command -ErrorAction SilentlyContinue).Source
}

function touch { 
    param([string]$file)
    New-Item -ItemType File -Path $file -Force | Out-Null
}

function ll { Get-ChildItem -Force $args }
function la { Get-ChildItem -Force -Hidden $args }

# Directory navigation shortcuts
function cdh { Set-Location $HOME }
function cdd { Set-Location (Join-Path $HOME 'Downloads') }
function cdp { Set-Location (Join-Path $HOME 'projects') }
function cdc { Set-Location (Join-Path $HOME 'Documents') }

function mkcd { 
    param([string]$path)
    New-Item -ItemType Directory -Path $path -Force | Out-Null
    Set-Location $path
}

#------------------------------------------------------------------------------
# Advanced Functions
#------------------------------------------------------------------------------
function Find-File { 
    param([string]$name, [string]$path = ".")
    Get-ChildItem -Path $path -Recurse -Filter "*$name*" -ErrorAction SilentlyContinue
}

function Get-SystemInfo {
    @{
        OS         = (Get-CimInstance Win32_OperatingSystem).Caption
        PowerShell = $PSVersionTable.PSVersion.ToString()
        CPU        = (Get-CimInstance Win32_Processor).Name
        Memory     = "{0:N2} GB" -f ((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB)
        Disk       = Get-CimInstance Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 } | 
        Select-Object DeviceID, @{Name = "Size(GB)"; Expression = { "{0:N2}" -f ($_.Size / 1GB) } }, 
        @{Name = "Free(GB)"; Expression = { "{0:N2}" -f ($_.FreeSpace / 1GB) } }
    }
}

function Show-Help {
    Write-Host "PowerShell Profile Commands:" -ForegroundColor Cyan
    Write-Host "=============================`n" -ForegroundColor Cyan
    
    $commands = @(
        @{Category = "Cloud/DevOps"; Commands = @("gcl", "gcp", "gcs", "k", "kgp", "d", "dps") },
        @{Category = "Git"; Commands = @("g", "gs", "ga", "gc", "gp", "gpl", "gco", "gb", "gl") },
        @{Category = "Navigation"; Commands = @("cdh", "cdd", "cdp", "z", "mkcd") },
        @{Category = "System"; Commands = @("reload", "admin", "update-all", "which", "ll", "la") }
    )
    
    foreach ($cat in $commands) {
        Write-Host $cat.Category -ForegroundColor Yellow
        Write-Host ("-" * $cat.Category.Length) -ForegroundColor Yellow
        $cat.Commands | ForEach-Object { Write-Host "  $_" -ForegroundColor White }
        Write-Host ""
    }
}

# Aliases for common commands
Set-Alias -Name help -Value Show-Help
Set-Alias -Name info -Value Get-SystemInfo
Set-Alias -Name find -Value Find-File

#------------------------------------------------------------------------------
# Enhanced GCP Functions ---
function gcp-switch {
    param([string]$project)
    gcloud config set project $project
    gcloud config set compute/zone us-central1-a  # Adjust as needed
}
function gcp-login { gcloud auth application-default login }

#------------------------------------------------------------------------------
# Startup Message (Conditional)
#------------------------------------------------------------------------------
if (-not $env:PROFILE_QUIET) {
    $width = try { $Host.UI.RawUI.WindowSize.Width } catch { 80 }
    $line = "─" * [Math]::Min($width - 1, 60)
    
    Write-Host $line -ForegroundColor DarkGray
    Write-Host "PowerShell $($PSVersionTable.PSVersion) | $(Get-Date -Format 'yyyy-MM-dd HH:mm')" -ForegroundColor Blue
    Write-Host "Type 'help' for command reference | 'info' for system info" -ForegroundColor Green
    Write-Host $line -ForegroundColor DarkGray
}

# --- Profile timing end ---
$profileEnd = Get-Date
Write-Host "Profile load time: $((($profileEnd - $profileStart).TotalMilliseconds)) ms" -ForegroundColor DarkGray

# --- Enhanced Dynamic Prompt ---
function global:prompt {
    Test-ProfileReload
    $admin = if (([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { "#" } else { ">" }
    $branch = ""
    if (Get-Command git -ErrorAction SilentlyContinue) {
        try {
            $branch = git rev-parse --abbrev-ref HEAD 2>$null
            if ($branch -and $branch -ne 'HEAD') { $branch = " ($branch)" } else { $branch = "" }
        }
        catch { $branch = "" }
    }
    $time = (Get-Date -Format "HH:mm:ss")
    "[$time] $($executionContext.SessionState.Path.CurrentLocation)$branch $admin "
}
