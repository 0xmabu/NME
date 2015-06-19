<#
 
.SYNOPSIS
Tests the account lockout settings on a Windows computer.
 
.DESCRIPTION
This tool determines the lockout threshold for accounts on a remote Windows computer. Is does this by guessing an invalid password against a selected account (Guest by default) and couting the number of guesses conducted before the account is locked. The NetUseAdd function, exposed in Netapi32, is used for establishing a connection to the target when guessing passwords. The tool automatically generates a random password, using the [guid]::NewGuid() function.

.PARAMETER Target
The target computer, specified as a single hostname or IP address. The tool also supports multiple targets as computer objects through the pipeline.

.PARAMETER User
The user account targeted for lockout testing. The default value is "Guest".

.PARAMETER Domain
A Windows domain that is passed with the user. The default value is NULL.

.PARAMETER MaxAttempts
The number of login attempts until processing is stopped. The default value is 101.

.EXAMPLE
NME-SMB-TestLockOut 192.168.56.22

.EXAMPLE
<computer objects>| NME-SMB-TestLockout -MaxAttempts 25 |Format-Table -AutoSize

.NOTES

Data update policy
------------------
Replaces "AccLockThreshold" property data for existing object.

Module dependencies
-------------------
- Environment: HelperFunctions, CreateObjects

Other
-----
- Still using native import of C# code to access NetUseAdd - Getting error 87 from the NetUseAdd function when using PSReflect and pure powershell code...

.LINK
NetUseAdd (NetApi32):
- https://msdn.microsoft.com/en-us/library/windows/desktop/aa370645%28v=vs.85%29.aspx

#>

Function Test-SMBAccountLockout
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]
        [Alias('IPAddress')]
        [string]$Target,

        [Parameter()]
        [string]$User = 'Guest',

        [Parameter()]
        [string]$Domain = $null,

        [Parameter()]
        [int]$MaxAttempts = 101
    )

    BEGIN
    {
        #Default functions/variables
        $CmdName = 'Test-SMBAccountLockout'
        $CmdAlias = 'NME-SMB-TestAccountLockout'
        $Results = @()
    }

    PROCESS
    {
        if( !($Target -as [ipaddress])) #Resolves the IP address of a hostname-based target
        {
            try
            {
                Write-Verbose "Attempting to resolve $target to an IP address"
                $Target = ([System.Net.Dns]::GetHostAddresses($Target)).IPAddressToString
                
                Write-Verbose "IP address obtained ($Target)"
            }
            catch
            {
                $message = "Unable to resolve target `'$Target`'"

                if($SuppressMessages)
                {
                    LogEvent -Command $CmdName -Severity Err -Event $message -ToFile
                }
                else
                {
                    LogEvent -Command $CmdName -Severity Err -Event $message -ToFile -ToConsole
                }

                return
            }
        }

        $CompObj = Get-ComputerObject -IP $Target -OnlyFromArray

        if(! $CompObj)
        {
            $message = "Unable to find Computer object for '$($target)'"
            LogEvent -Command $CmdName -Severity Err -Event $message -ToFile -ToConsole

            return
        }

        $unc = "\\$Target\ipc$"
        $pass = [guid]::NewGuid().Guid
        $AccLockout = $null

        $message = "Testing account lockout threshold (using $User)"
        LogEvent -source $Target -command $CmdName -severity Info -event $message -ToFile -ToConsole #Maybe verbose only (only highlight successes and failures (like locked or other error))
        
        $LockCount = 0

        Write-Host ""

        for ($i = 1; $i -le $MaxAttempts; $i++)
        { 
            $paramErrorIndex = $null

            $useInfo = New-Object ([NativeTestLockout+USE_INFO_2]) -Property @{
                ui2_local      = $null
                ui2_remote     = $unc
                ui2_password   = $pass
                ui2_asg_type   = 3
                ui2_usecount   = 1
                ui2_username   = $User
                ui2_domainname = $Domain
            } #Create USE_INFO_2 object used by NetUseAdd to issue the request

            $message = [NativeTestLockout]::NetUseAdd($null, 2, [ref]$useInfo, [ref]$paramErrorIndex)
            
            switch ($message)
            {
                53      {LogEvent -source $Target -command $CmdName -event $message -native -ToFile -ToConsole; return}
                1326    {$lockCount++; Write-Host "." -NoNewline; break}
                1909    {if($i -eq 1){$message = 'Cannot use this account for lockout testing as it is already locked'; LogEvent -source $Target -command $CmdName -severity Err -event $message -ToFile -ToConsole; return} else {$i = $MaxAttempts; break}}
                Default {Write-Warning "Unmanaged error code: $message"}
            }
        }

        Write-Host ""

        if($LockCount -eq $MaxAttempts)
        {
            $Lockout = 0
        }

        if(! $Domain)
        {
            $Domain = '.'
        }

        $LockoutObj = New-Object psobject -Property @{
            IPAddress        = $Target
            AccLockThreshold = $LockCount
            LockAccount      = $Domain + "\" + $User
        } |Select-Object IPAddress,AccLockThreshold,LockAccount

        if($CompObj.Policy.AccLockThreshold)
        {
            $CompObj.Policy.AccLockThreshold = $LockoutObj.AccLockThreshold
        }
        else
        {
            $CompObj.Policy = $LockoutObj |Select-Object AccLockThreshold
        }

        $Results += $LockoutObj
    }

    END
    {
        Write-Output $Results
    }
}

$Native = @'
using System;
using System.Runtime.InteropServices;
using System.Text;
    
public class NativeTestLockout
{
    [DllImport("NetApi32.dll", CharSet = CharSet.Unicode)]
    public static extern int NetUseAdd(
        string UncServerName,
        int Level,
        ref USE_INFO_2 Buf,
        out int ParmError
        );

    [DllImport("NetApi32.dll", CharSet = CharSet.Unicode)]
    public static extern int NetUseDel(
        string UncServerName,
        string UseName,
        int ForceCond
        );

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct USE_INFO_2
    {
        public string ui2_local;
        public string ui2_remote;
        public string ui2_password;
        public int ui2_status;
        public int ui2_asg_type;
        public int ui2_refcount;
        public int ui2_usecount;
        public string ui2_username;
        public string ui2_domainname;
    }
}
'@

Add-Type -TypeDefinition $Native