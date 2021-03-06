﻿<#
.SYNOPSIS
Environment configuration module for NME.

.DESCRIPTION
This module configures the NME runtime environment. It loads global variables and functions, and creates the needed folders.
#>

Write-Host 'Setting global variables'

$Global:NMEVars = [ordered]@{
    CurrentUser = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    CurrentCred = $null
    HomeDir     = $null
    LocalIP     = $null
    BackupJob   = $null
}

Write-Host "Enter the path to a working directory where logs and data will be stored (<Enter> defaults to $HOME\NME)" -ForegroundColor DarkYellow
do { $prompt = Read-Host "Path" } until (([uri]$prompt).IsAbsoluteUri -or ($prompt -eq "`0"))

if($prompt -eq "`0")
{
    $NMEVars.HomeDir = "$HOME\NME"
}
else
{
    $NMEVars.HomeDir = $prompt
}

$prompt = $null

Write-Host 'Creating folder structure'

If(!(Test-Path $NMEVars.HomeDir))
{
    Write-Host "Creating working directory"
    New-Item $NMEVars -type directory |Out-Null
}

If(!(Test-Path "$($NMEVars.HomeDir)\bin"))
{
    Write-Host "Creating bin subfolder"
    New-Item "$($NMEVars.HomeDir)\bin" -type directory |Out-Null
}

If(!(Test-Path "$($NMEVars.HomeDir)\backup"))
{
    Write-Host "Creating backup subfolder"
    New-Item "$($NMEVars.HomeDir)\backup" -type directory |Out-Null
}

If(!(Test-Path "$($NMEVars.HomeDir)\data"))
{
    Write-Host "Creating data subfolder"
    New-Item "$($NMEVars.HomeDir)\data" -type directory |Out-Null
}

If(!(Test-Path "$($NMEVars.HomeDir)\config"))
{
    Write-Host "Creating config subfolder"
    New-Item "$($NMEVars.HomeDir)\config" -type directory |Out-Null
}

If(!(Test-Path "$($NMEVars.HomeDir)\activity.log"))
{
    Write-Host "Creating activity log"
    New-Item "$($NMEVars.HomeDir)\activity.log" -type file |Out-Null
}

Write-Host "Fetching local IP address"

$IPArray = (Get-WmiObject win32_NetworkAdapterConfiguration |? {$_.IPAddress -ne $null}).IPAddress

if($IPArray -eq $null)
{
    Write-Host "No IP address assigned to any local interface" -ForegroundColor Yellow
}
elseif($IPArray.Count -eq 1)
{
    $NMEVars.LocalIP = $IPArray
}
else
{
    Write-Host "Select one of the following IP address to be used by scripts for inbound connections (<Enter> defaults to $($IPArray[0]))" -ForegroundColor DarkYellow 

    for($i=1; $i -le $IPArray.length; $i++)
    {
        Write-Host -ForegroundColor DarkYellow "[$i] " $IPArray[$i-1]
    }

    do{ $prompt = Read-Host "Number" } until( (1..($IPArray.length) -contains $prompt) -or ($prompt -eq "`0") )

    if($prompt -eq "`0")
    {
        $NMEVars.LocalIP = $IPArray[0]
    }
    else
    {
        $NMEVars.LocalIP = $IPArray[$prompt-1]
    }
}

$prompt = $null

$Global:NMEModules = @{}

foreach($module in (Get-Module))
{
    if($module.Path -like "*\NME\*")
    {
        $NMEModules.Add($module.Name, $module.ModuleBase)
    }
}

Write-Host "Defining global object arrays"

$Global:Networks      = [ordered]@{}
$Global:Computers     = [ordered]@{}
$Global:Services      = [ordered]@{
    HTTP      = @{Servers = @{}; Instances = @{}}
    MSSQL     = @{Servers = @{}; Databases = @{}}
    SMB       = @{Servers = @{}; Shares = @{}}
}
$Global:Applications  = [ordered]@{}
$Global:DNSDomains    = [ordered]@{}
$Global:Credentials   = [System.Collections.ArrayList]@()

$Global:NMEObjects = @{
    Networks     = $Networks
    Computers    = $Computers
    Services     = $Services
    Applications = $Applications
    DNSDomains   = $DNSDomains
    Credentials  = $Credentials
}

[void](Get-DNSDomainObject -DomainName orphan.nme)

Write-Host 'Configuring aliases'
Set-Alias NME-NET-TestState Test-NETState -Scope Global
Set-Alias query Test-NETState -Scope Global
Set-Alias NME-SMB-EnumUsers Get-SMBUsers -Scope Global
Set-Alias NME-SMB-EnumShares Get-SMBShares -Scope Global
Set-Alias NME-SMB-EnumAccountPolicy Get-SMBAccountPolicy -Scope Global
Set-Alias NME-SMB-EnumLoggedon Get-SMBLoggedon -Scope Global
Set-Alias NME-SMB-EnumGroups Get-SMBGroups -Scope Global
Set-Alias NME-SMB-TestAccountLockout Test-SMBAccountLockout -Scope Global
Set-Alias NME-SMB-TestCredentials Test-SMBCredentials -Scope Global
Set-Alias NME-SMB-TestShares Test-SMBShares -Scope Global
Set-Alias NME-MSSQL-EnumServices Get-MSSQLServers -Scope Global
Set-Alias NME-MSSQL-TestCredentials Test-MSSQLCredentials -Scope Global
Set-Alias NME-MSSQL-TestWindowsLogin Test-MSSQLWindowsLogin -Scope Global
Set-Alias NME-WHOIS-QueryWHOIS Invoke-WHOISQuery -Scope Global
Set-Alias whois Invoke-WHOISQuery -Scope Global
Set-Alias NME-DNS-QueryDNS Invoke-DNSQuery -Scope Global
Set-Alias resolve Invoke-DNSQuery -Scope Global
Set-Alias NME-HTTP-BingHostnames Invoke-BingHostnames -Scope Global
Set-Alias bing Invoke-BingHostnames -Scope Global
Set-Alias NME-HTTP-GoogleHostnames Invoke-GoogleHostnames -Scope Global
Set-Alias google Invoke-GoogleHostname -Scope Global
Set-Alias NME-HTTP-EnumServices Get-HTTPServers -Scope Global
Set-Alias NME-HTTP-EnumServiceInstances Get-HTTPServerInstances -Scope Global
#Set-Alias NME-WMI-DumpCredentials Invoke-WMIDumpCredentials -Scope Global
#Set-Alias NME-WMI-GetNetstat Invoke-WMINetstat -Scope Global

Set-Alias NME-InvokeNmap Invoke-Nmap -Scope Global
Set-Alias nmap Invoke-Nmap -Scope Global

Set-Alias NME-ImportNmapXML Import-NmapXML -Scope Global
Set-Alias NME-ImportNessusXML Import-NessusXML -Scope Global
Set-Alias NME-BackupObjects Backup-Objects -Scope Global
Set-Alias backup Backup-Objects -Scope Global
Set-Alias NME-RestoreObjects Restore-Objects -Scope Global
Set-Alias restore Restore-Objects -Scope Global
Set-Alias NME-ImpersonateUser Invoke-UserImpersonation -Scope Global
Set-Alias impersonate Invoke-UserImpersonation -Scope Global
#Set-Alias NME-ViewData Show-Objects -Scope Global
Set-Alias NME-GetNetwork Get-NetworkObject -Scope Global
Set-Alias NME-GetComputer Get-ComputerObject -Scope Global
Set-Alias NME-GetMSSQLServer Get-MSSQLObject -Scope Global
Set-Alias NME-GetSMBShare Get-SMBShareObject -Scope Global
Set-Alias NME-GetDNSDomain Get-DNSDomainObject -Scope Global
Set-Alias NME-GetCredential Get-CredentialObject -Scope Global
Set-Alias NME-GetHTTPServer Get-HTTPServerObject -Scope Global
Set-Alias NME-GetHTTPServerInstance Get-HTTPServerInstanceObject -Scope Global

Write-Host 'Changing path to working directory'
Set-Location $NMEVars.HomeDir

Write-Host 'Module initialization completed'