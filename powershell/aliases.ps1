<#
.SYNOPSIS
    Centralized alias definitions for PowerShell profile. For navigation, git, and system shortcuts.
#>
# Aliases for quick navigation and commands
Set-Alias ll Get-ChildItem
Set-Alias la "Get-ChildItem -Force"
Set-Alias gs "git status"
# Set-Alias gc "git commit"   # 'gc' is reserved in PowerShell (Get-Content), cannot overwrite
# Set-Alias gp "git push"     # 'gp' is reserved in PowerShell (Get-Process), cannot overwrite
Set-Alias gpl "git pull"
Set-Alias open explorer.exe
Set-Alias touch New-Item
Set-Alias reload reload
Set-Alias update update-all
# Add any other aliases here as needed 