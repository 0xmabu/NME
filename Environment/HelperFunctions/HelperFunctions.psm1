<#
.SYNOPSIS
Function used to manage console and log output

.DESCRIPTION
This function can be called to generate color-coded/categorized event messages to the console and a detailed activity log on disk. It is intended as a helper function that can be called by tools in order to log events in a consistent manner.

Four color-coded event categories has been defined for use - "Info", "Err", "Succ" and "Warn". Also, if the "file" switch parameter is used, an activity.log file is created and stored in the default working directory.

.PARAMETER source
A string that should specify the host affected by the event

.PARAMETER command
A string that should specify the tool that generated the event

.PARAMETER severity
A switch parameter supporting the arguments "Info", "Err", "Succ" and "Warn", defining the event category

.PARAMETER message
The event message

.PARAMETER native
This switch causes the function to translate a native Windows error code (which should be a number passed with the message parameter) into a corresponding Windows error message.

.PARAMETER file
This switch causes the function to log the event to the activity.log file in the working directory of the module

.PARAMETER console
This switch causes the function to write output to the console

.NOTES

Windows native error codes:
- https://msdn.microsoft.com/en-us/library/windows/desktop/ms681382%28v=vs.85%29.aspx
#>
Function LogEvent
{
    Param
    (
        [Parameter()]
        [string]$Source,

        [Parameter()]
        [string]$Command,

        [Parameter()]
        [ValidateSet('Info','Warn','Err','Succ')]
        [string]$Severity,

        [Parameter()]
        [switch]$Native,

        [Parameter()]
        [string]$Event,

        [Parameter()]
        [switch]$ToFile,

        [Parameter()]
        [switch]$ToConsole
    )

    if (!$Source)
    {
        $Source = 'localhost'
    }

    if ($Native)
    {
        if($Event -eq 0)
        {
            $Severity = 'Info'
        }
        else
        {
            $Severity = 'Err'
        }

        $Event = (New-Object System.ComponentModel.Win32Exception([int]$Event)).Message
    }

    if($ToFile)
    {
        (Get-Date -Format G) + (echo `t) + $Source + (echo `t) + $Command + (echo `t) + $Severity + (echo `t) + $Event |Out-File -Append "$($NMEVars.HomeDir)\activity.log"
    }

    if($ToConsole)
    {
        switch($severity)
        {
            Info {$color = 'white'; $icon = '[*]'; break}
            Err  {$color = 'red'; $icon = '[!]'; break}
            Succ {$color = 'green'; $icon = '[+]'; break}
            Warn {$color = 'yellow'; $icon = '[@]'; break}
        }

        Write-Host "$icon [$source] $event" -ForegroundColor $color
    }
}

<#
.SYNOPSIS
Function used to create a command execution thread

.DESCRIPTION
This function can be called to stage a command execution thread. The thread can then be initialized from the calling function to run commands in the background (in the cotext of the primary powershell process).

The function returns a "powershell object" that can be used to close/dispose the thread.

.PARAMETER ImportModules
Name of module(s) that will be imported into the thread runspace.

.PARAMETER ImportVarialves
Name of varialble(s) that will be imported into the thread runspace.

.PARAMETER Command
The command to be executed by the thread
#>
Function CreateThread
{
    Param
    (
        [Parameter()]
        [array]$ImportModules,

        [Parameter()]
        [array]$ImportVariables,

        [Parameter(Mandatory)]
        [string]$Command
    )

    if($ImportModules)
    {
        foreach($mod in $ImportModules)
        {
            $modules += @($NMEModules."$mod")
        }
        
        $iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
        $iss.ImportPSModule($modules)

        $runspace = [runspacefactory]::CreateRunspace($Host,$iss)
    }
    else
    {
        $runspace = [runspacefactory]::CreateRunspace($Host)
    }

    $runspace.Open()

    if($ImportVariables)
    {
        foreach($var in $ImportVariables)
        {
            $runspace.SessionStateProxy.SetVariable($var,(Invoke-Expression ("$" + "$var")))
        }
    }

    $powershell = [powershell]::Create()
    $powershell.Runspace = $runspace

    $thread = $powershell.AddScript($Command)

    return $thread
}

<#
.SYNOPSIS
Function used to monitor the status of threads

.DESCRIPTION
This function can be called to monitor the running time of code that executes in a separate thread. The function can be passed a timeout value that, when hit, gives the user the option to break current execution and continue the processing flow of the main (calling) function.

.PARAMETER handle
The handle to the thread to be monitored

.PARAMETER timeout
The time, in seconds, to wait until prompting the user to either continue to wait or end processing
#>
Function WatchThread
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory)]
        [object]$handle,

        [Parameter(Mandatory)]
        [int]$timeout
    )
    
    $break = $false
    $status = $null
    $initTime = Get-Date

    Write-Verbose 'Monitoring thread'

    while(1 -eq 1)
    {
        $span = New-TimeSpan -Seconds $timeout
        $time = [diagnostics.stopwatch]::StartNew()

        while ($time.Elapsed -lt $span)
        {
            if($handle.IsCompleted)
            {
                return $true
            }
            else
            {
                Start-Sleep -Seconds 1
            }
        }
        
        $runtime = "{0:N0}" -f $(( (Get-Date)-($inittime)).totalminutes)

        Write-Host -ForegroundColor DarkYellow "[@] Operation has run for $runtime minutes - continue to wait?"
        do { $prompt = Read-Host 'Y|N' } until ($prompt -eq 'n' -or $prompt -eq 'y')
        
        if($prompt -eq 'n')
        {
            return $false
        }
    }
}

<#
.SYNOPSIS
Function used to conduct IP calculations

.DESCRIPTION
This function can be used to conduct various calculations/translations on IPv4 and IPv6 addresses.

.PARAMETER CIDRToRange
Switch that causes the function to translate the CIDR notation to an IP range

.PARAMETER RangeToCIDR
Switch that causes the function to translate an IP range to CIDR notation 

.PARAMETER IsMember
Switch that causes the function to check if the specified IP address is member of the specified IP network (provided in CIDR notation)

.PARAMETER IsValidCIDR
Switch that causes the function to check if the specified CIDR notation is valid

.PARAMETER IsValidIP
Switch that causes the function to check if the specified IP address is valid. If valid, the function returns the IP address type - "IPv4" or "IPv6".

.PARAMETER CIDR
An IP network in the CIDR notation, i.e. "<IPAddress>/<mask>"

.PARAMETER IPRange
An IP range, formated as two IP addresses separated by a hyphen, i.e. "<Start IP> - <End IP>"

.PARAMETER IPAddress
An IPv4 or IPv6 address
#>
Function IPHelper
{
    Param
    (
        [Parameter(Mandatory,ParameterSetName = 'CIDRToRange')]
        [switch]$CIDRToRange,

        [Parameter(Mandatory,ParameterSetName = 'RangeToCIDR')]
        [switch]$RangeToCIDR,
        
        [Parameter(Mandatory,ParameterSetName = 'IsMember')]
        [switch]$IsMember,

        [Parameter(Mandatory,ParameterSetName = 'ListMembers')]
        [switch]$ListMembers,

        [Parameter(Mandatory,ParameterSetName = 'ValidateCIDR')]
        [switch]$ValidateCIDR,

        [Parameter(Mandatory,ParameterSetName = 'ValidateIP')]
        [switch]$ValidateIP,

        [Parameter(Mandatory,ParameterSetName = 'CIDRToRange')]
        [Parameter(Mandatory,ParameterSetName = 'IsMember')]
        [Parameter(Mandatory,ParameterSetName = 'ListMembers')]
        [Parameter(Mandatory,ParameterSetName = 'ValidateCIDR')]
        [string]$CIDR,

        [Parameter(Mandatory,ParameterSetName = 'RangeToCIDR')]
        [String]$IPRange,

        [Parameter(Mandatory,ParameterSetName = 'IsMember')]
        [Parameter(Mandatory,ParameterSetName = 'ValidateIP')]
        [String]$IPAddress
    )

    #Helper functions to convert IP addresses to/from binary format
    function IPToBinary($ip)
    {
        $ip = ($ip -as [ipaddress]).GetAddressBytes()

        foreach($byte in $ip)
        {
            [string]$string += ([convert]::ToString($byte,2).PadLeft(8,'0'))
        }

        return $string
    }

    function BinaryToIP($bin)
    {
        $bitcount = $bin.ToCharArray().count

        switch ($bitcount)
        {
            32 {$type = 'ipv4'; break}
            128 {$type = 'ipv6'; break}
            Default {return}
        }

        $bitarray = @()

        if($type -eq 'ipv6')
        {
            for ($i = 0; $i -lt $bitcount; $i = $i+16)
            { 
                $bitarray += $bin.Substring($i,16)
            }

            foreach($i in $bitarray)
            {
                $dec = [System.Convert]::ToInt32($i,2)
                $hex = [Convert]::ToString($dec, 16).PadLeft(4,"0")

                $ip += "$hex`:"
            }

            $ip = $ip.TrimEnd(':')

            return $ip
        }
        else
        {
            for ($i = 0; $i -lt $bitcount; $i = $i+8)
            { 
                $bitarray += $bin.Substring($i,8)
            }

            foreach($i in $bitarray)
            {
                $dec = [System.Convert]::ToInt32($i,2)
                $ip += "$dec."
            }

            $ip = $ip.TrimEnd('.')

            return $ip
        }
    }

    #Main functions
    if($CIDRToRange)
    {
        $netip = ($CIDR -split '/')[0]
        $netmask = ($CIDR -split '/')[1]

        if(($netip -as [ipaddress]).AddressFamily -eq 'InterNetwork')
        {
            $hostmask = 32-$netmask
        }
        else
        {
            $hostmask = 128-$netmask
        }

        $netbin = IPtoBinary $netip

        $bcastbin = $netbin -replace ".{$hostmask}$",('1'*$hostmask)

        $bcastip = BinaryToIP $bcastbin

        $netbin = $netbin -replace ".{$hostmask}$",('0'*$hostmask)

        $netip = BinaryToIP $netbin

        $range = "$netip - $bcastip"
    
        return $range
    }

    if($RangeToCIDR)
    {
        $netip = (($IPRange -split '-')[0]).TrimEnd()
        $bcastip = (($IPRange -split '-')[1]).TrimStart()

        $netbin = IPtoBinary $netip
        $bcastbin = IPtoBinary $bcastip

        if($netbin -gt $bcastbin) #Simple check to verify that netip actually contains bcastip
        {
            return "ERROR"
        }

        $bitcount = $netbin.ToCharArray().count

        for ($i = 0; $i -lt $bitcount; $i++)
        { 
            if($netbin[$i] -eq $bcastbin[$i])
            {
                $netmask++
            }
            else
            {
                break
            }
        }

        if(($netip -as [ipaddress]).AddressFamily -eq 'InterNetwork')
        {
            $hostmask = 32-$netmask
        }
        else
        {
            $hostmask = 128-$netmask
        }

        $netbin = $netbin -replace ".{$hostmask}$",("0"*$hostmask)

        $netip = BinaryToIP $netbin

        return "$netip/$netmask"
    }

    if($IsMember)
    {
        $netip = ($CIDR -split '/')[0]
        $netmask = ($CIDR -split '/')[1]

        $netbin = IPtoBinary $netip
        $hostbin = IPtoBinary $IPAddress

        $netnet = $netbin.substring(0,$netmask)
        $hostnet = $hostbin.substring(0,$netmask)

        if($hostnet -eq $netnet)
        {
            return $true
        }
        else
        {
            return $false
        }
    }

    if($ListMembers)
    {
        function recursive($bits)
        {
            if($bits -le 0)
            {
                Return $($bitsarray -join '')
            }
            else
            {
                $bitsarray[$bits -1] = 0
                recursive($bits -1)

                $bitsarray[$bits -1] = 1
                recursive($bits -1)
            }
        }
        
        $netip = ($CIDR -split '/')[0]
        $netmask = ($CIDR -split '/')[1]

        if(($netip -as [ipaddress]).AddressFamily -eq 'InterNetwork')
        {
            $hostbitnum = 32-$netmask
        }
        else
        {
            $hostbitnum = 128-$netmask
        }

        $netbin = IPtoBinary $netip
        $netbits = $netbin.Substring(0,$netmask)
        $bitsarray = New-Object int[] $hostbitnum

        $hosts = recursive($hostbitnum)
        
        $computers = @()

        foreach($i in $hosts)
        {
            $ipbits = $netbits + $i

            $computers += (BinaryToIP $ipbits)
        }

        return $computers
    }

    if($ValidateCIDR)
    {
        $netip = ($CIDR -split '/')[0]
        $netmask = ($CIDR -split '/')[1] -as [int]

        if($netip -as [ipaddress])
        {
            if(($netip -as [ipaddress]).AddressFamily -eq 'InterNetwork')
            {
                if($netmask -lt 0 -or $netmask -gt 32)
                {
                    return $false
                }
            }
            else
            {
                if($netmask -lt 0 -or $netmask -gt 128)
                {
                    return $false
                }
            }
        }
        else
        {
            return $false
        }
        
        $netbin = IPtoBinary $netip

        $hostbin = $netbin.substring($netmask)

        if($hostbin -notmatch '1')
        {
            return $true
        }
        else
        {
            return $false
        }
    }

    if($ValidateIP)
    {
        switch ($IPAddress)
        {
            {($_ -as [ipaddress]).AddressFamily -eq 'InterNetwork'} {return 'IPv4'}
            {($_ -as [ipaddress]).AddressFamily -eq 'InterNetworkV6'} {return 'IPv6'}
            Default {return $false}
        }
    }
}