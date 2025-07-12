# Utility functions for PowerShell profile
function .. { Set-Location .. }
function ... { Set-Location ..\.. }
function ~ { Set-Location $HOME }
function cfg { Set-Location "$HOME\.config" }
function Backup-Profile {
    $backupPath = "$PROFILE.bak_$(Get-Date -Format yyyyMMddHHmmss)"
    Copy-Item $PROFILE $backupPath
    Write-Host "Profile backed up to $backupPath" -ForegroundColor Green
}
function Restore-Profile {
    $latest = Get-ChildItem "$PROFILE.bak_*" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($latest) {
        Copy-Item $latest.FullName $PROFILE -Force
        Write-Host "Profile restored from $($latest.Name)" -ForegroundColor Green
    }
    else {
        Write-Host "No backup found." -ForegroundColor Yellow
    }
}
# Enhanced GCP functions
function gcp-switch {
    param([string]$project)
    gcloud config set project $project
    gcloud config set compute/zone us-central1-a  # Adjust as needed
}
function gcp-login { gcloud auth application-default login } 