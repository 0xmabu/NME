<#
.SYNOPSIS
Start-up module for the NME Framework

.DESCRIPTION
This is the Start-up module for NME. It loads all child modules and initializes the runtime environment.
#>

Write-Host "Starting NME"

If (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
{
    Write-Host "NME requires an elevated runtime - start powershell as an administrator" -ForegroundColor Red

    Break
}

Write-Host "Loading environment modules"
Get-ChildItem "$PSScriptRoot\Environment" | ? { $_.PSIsContainer } | % { Import-Module $_.FullName -DisableNameChecking -Force}

Write-Host "Loading external modules"
Get-ChildItem "$PSScriptRoot\External" | ? { $_.PSIsContainer } | % { Import-Module $_.FullName -DisableNameChecking -Force}

Write-Host "Loading importer modules"
Get-ChildItem "$PSScriptRoot\Importers" | ? { $_.PSIsContainer } | % { Import-Module $_.FullName -DisableNameChecking -Force}

Write-Host "Loading enumeration modules"
Get-ChildItem "$PSScriptRoot\MapEnum" | ? { $_.PSIsContainer } | % { Import-Module $_.FullName -DisableNameChecking -Force}

Write-Host "Initializing runtime environment"
Invoke-Expression $PSScriptRoot\Runtime.ps1