<#
 
.SYNOPSIS
Nmap wrapper module.
 
.DESCRIPTION
This tool can be used to run Nmap from Powershell. It simply wraps around the existing binaries and adds pipeline and results parsing support that is specific to the framework. As such, this module requires that the Nmap package has been installed on the local computer.

The usage syntax of this tool is identical with using standard nmap, with the following exceptions:
- All parameters and values passed to nmap MUST be passed as a single string, enclosed with commas. See the examples section for details.
- When the targets are passed as objects over the pipeline (see Target in parameter section), the tool overrides any provided log parameters and values, and instead saves log files (using -oA) in the $NMEVars.HomeDir\data\InvokeNmap folder.

.PARAMETER Target
This parameter is used to provide support for Computer and Network objects passed as targets over the pipeline. If the pipeline is not used, targets should be defined according to standard Nmap syntax (See examples section).

.PARAMETER cmdparams
This parameter is internally by the tool and should not be used.

.EXAMPLE
NME-InvokeNmap "-sS -sV -sC -O 192.168.56.0/24 -oX 'C:\users\foo bar\scan.xml'"

.EXAMPLE
<computer objects>| NME-InvokeNmap "-sS -p80,443 --script http-methods"

.EXAMPLE
<network objects>|?{$_.CIDR -like "192.168*"} |NME-InvokeNmap "-sn --traceroute --dns-servers 192.168.1.1,192.168.1.2"

.NOTES

Module dependencies
-------------------
- Environment: HelperFunctions

Other dependencies
------------------
- Nmap installation

.LINK
https://nmap.org

#>

function Invoke-Nmap
{
    [CmdletBinding(PositionalBinding=$false)]
    Param
    (
        [parameter(ValueFromPipelineByPropertyName)]
        [Alias('IPAddress','CIDR')]
        [string]$target,

        [parameter(ValueFromRemainingArguments)]
        [string]$cmdparams
    )

    BEGIN
    {
        try
        {
            nmap.exe |Out-Null
        }
        catch
        {
            $message = 'Nmap not found'
            LogEvent -Command 'nmap' -Severity Err -Event $message -ToConsole

            return
        }

        if(!(Test-Path "$($NMEVars.HomeDir)\data\InvokeNmap")) #Verifies existance of script subfolder for storing scan logs
        {
            Write-Verbose 'No script folder exists (creating)'
            [void](New-Item "$($NMEVars.HomeDir)\data\InvokeNmap" -ItemType Directory)
        }

        $ScriptDir = "$($NMEVars.HomeDir)\data\InvokeNmap"
    }

    PROCESS
    {
        $command = "nmap.exe $($PSBoundParameters['cmdparams'])"

        if($target) #Forces -oA logging to script dir, if targets are provided over pipeline
        {
            $date = Get-Date
            $timestamp = "$($date.Year)$($date.Month)$($date.Day)_$($date.Hour)$($date.Minute)$($date.Second)"
            $command = $command + " $target -oA $ScriptDir\$($target -replace '/','_')-$timestamp"
        }

        $message = "Running '$command'"
        Write-Host ''
        LogEvent -Command 'nmap' -Severity Info -Event $message -ToConsole -ToFile

        if($command -match ",") #Escaping any commas in expression
        {
            $command = $command -replace ",","','"
        }

        Invoke-Expression $command

        $message = 'Command completed'
        Write-Host ''
        LogEvent -Command 'nmap' -Severity Info -Event $message -ToConsole -ToFile
    }

    END
    {}
}