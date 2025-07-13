<#
.SYNOPSIS
    Quick setup script for initializing PowerShell config directory and cloning repo on new machines.
#>
# Quick setup for new machines
$configDir = "$HOME\.config\powershell"
New-Item -ItemType Directory -Path $configDir -Force
# Git clone logic here (user should fill in their repo URL)
# Example:
# git clone https://github.com/Anapra/windows-powershell $configDir 