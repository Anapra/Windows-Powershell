# Settings and environment awareness
# Security: Execution Policy Reminder
if ((Get-ExecutionPolicy -Scope CurrentUser) -ne 'RemoteSigned') {
    Write-Host "Consider setting execution policy: Set-ExecutionPolicy RemoteSigned -Scope CurrentUser" -ForegroundColor Yellow
}

# Environment Awareness
if ($env:WSL_DISTRO_NAME) {
    Write-Host "Running inside WSL: $($env:WSL_DISTRO_NAME)" -ForegroundColor Cyan
}
if ($env:COMPUTERNAME) {
    Write-Host "Host: $($env:COMPUTERNAME)" -ForegroundColor Cyan
}

# Auto-Updater
function Update-Profile {
    Write-Host "Updating profile and modules..." -ForegroundColor Yellow
    if (Test-Path "$HOME/.config/.git") {
        git -C "$HOME/.config" pull
        Write-Host "Profile updated from git." -ForegroundColor Green
    }
    Update-Module -Force
    if (Get-Command winget -ErrorAction SilentlyContinue) { winget upgrade --all --accept-source-agreements }
    if (Get-Command choco -ErrorAction SilentlyContinue) { choco upgrade all -y }
    Write-Host "All updates complete!" -ForegroundColor Green
} 