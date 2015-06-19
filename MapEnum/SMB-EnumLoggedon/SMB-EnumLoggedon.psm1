<#
 
.SYNOPSIS
Enumerates users currently logged on to a Windows computer.
 
.DESCRIPTION
This tool enumerates user accounts that are currently logged on to a remote Windows computer, either interactively or through the batch and service logon types.

The tool support two types of queries (Interfaces) when trying to enumerate logged-on users: The NetWkstaUser (NetApi32) query and the WINREG (Registry) query, both over the MSRPC protocol. When using the WINREG query, a list of account SIDs are returned which then are translated into account names using the LookupAccountSid function (exposed in Advapi32).

The queries issued by this tool usually require at least user privileges on the target computer. This can vary, though, depending on the version and configuration of the SMB server.

The tool outputs a computer object with logged-on user information.

.PARAMETER Target
The target computer, specified as a single hostname or IP address. The tool and also supports multiple targets as computer objects through the pipeline.

.PARAMETER Interface
The interface(s) to be queried, including "NetApi" and/or "Registry". The default value is to query both.

.PARAMETER MultiThread
Enables multi-threading, where each target is processed by its own thread.

.PARAMETER ThreadLimit
The maximum number of threads that will be assigned when multi-threading. The default value is 20.

.PARAMETER ShowProgress
Enables a progress bar.

.PARAMETER SuppressMessages
Prevents event messages from being printed to the screen.

.PARAMETER DontFeedObject
Prevents results from being saved to the Computer object. By default, results are saved to the "Loggedon" property of the object. This is done according to the data update policy defined for this tool (see notes).

.EXAMPLE
<computer objects>|NME-SMB-EnumLoggedon

.EXAMPLE
NME-SMB-EnumLoggedon -Target 192.168.56.22 -Feed Console |Format-table -Autosize

.EXAMPLE
<computer objects>|?{$_.IPAddress -like "192.168.5*"}|NME-SMB-EnumLoggedon -MultiThread -ShowProgress

.NOTES

Data update policy
------------------
Replaces all data on existing object.

Module dependencies
-------------------
- External: PSReflect
- Environment: HelperFunctions, CreateObjects

Other
-----
- Still using native import of C# code to access Advapi/LookupAccountSid, using PSReflect to import the corresponding function crashes Powershell
 
.LINK
NetWkstaUser (NetApi):
- http://msdn.microsoft.com/en-us/library/windows/desktop/aa370669%28v=vs.85%29.aspx

WINREG (Registry)
- http://msdn.microsoft.com/en-us/library/microsoft.win32.registrykey.aspx
- http://msdn.microsoft.com/en-us/library/windows/desktop/aa379166%28v=vs.85%29.aspx

PowerSploit Framework
- https://github.com/mattifestation/PowerSploit

#>

Function Get-SMBLoggedon
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]
        [Alias('IPAddress')]
        [string]$Target,

        [Parameter()]
        [ValidateSet('NetApi','Registry')]
        [string[]]$Interface = ('NetApi','Registry'),

        [Parameter()]
        [switch]$MultiThread,

        [Parameter()]
        [int]$ThreadLimit = 20,

        [Parameter()]
        [switch]$ShowProgress,

        [Parameter()]
        [switch]$SuppressMessages,

        [Parameter()]
        [switch]$DontFeedObject
    )
     
    BEGIN
    {
        #Default functions/variables
        $CmdName = 'Get-SMBLoggedon'
        $CmdAlias = 'NME-SMB-EnumLoggedon'
        $Results = @()

        #Initial processing
        if($PSBoundParameters['Verbose'])
        {
            $VerboseEnabled = $true
        }

        if($ShowProgress -and $MyInvocation.CommandOrigin -eq 'Runspace') #'CommandOrigin -eq Runspace' will prevent execution of block when in a threaded context
        {
            $PipeInput = $MyInvocation.Line

            if($PipeInput -match $CmdName)
            {
                $PipeExp = $PipeInput.Substring(0, $PipeInput.IndexOf($CmdName)).trimend(' |')
            }
            else
            {
                $PipeExp = $PipeInput.Substring(0, $PipeInput.IndexOf($CmdAlias)).trimend(' |')
            }

            if($PipeExp) #Determines number of targets coming through pipe
            {
                $TargetsTotal = (Invoke-Expression $PipeExp| Measure-Object).Count
            }
            else #If no pipe expression, number of targets will be 1
            {
                $TargetsTotal = 1
            }

            #Synchronized array so that data can data can be shared propertly in multithread mode
            $Counter = [hashtable]::Synchronized(@{
                Total = $TargetsTotal
                Done = 0
            })
        }

        #Multi-threading
        if($MultiThread)
        {
            #Command-specific input to multithreading
            $ScriptBlock = $MyInvocation.MyCommand.Definition
            $ImportModules = @('HelperFunctions','PSReflect','CreateObjects')
            $ImportVariables = @('NMEObjects','NMEVars','Counter')

            foreach ($key in $MyInvocation.BoundParameters.Keys) #Creates a string of parameters that is passed to the powershell::create() command
            {
                if(($key -ne 'MultiThread') -and ($key -ne 'ThreadLimit') -and ($key -ne 'Target'))
                {
                    if(($($MyInvocation.BoundParameters.Item($key)) -eq $true) -or ($($MyInvocation.BoundParameters.Item($key)) -eq $false))
                    {
                        $ParamString += ".AddParameter(`"$key`")"
                    }
                    else
                    {
                        if($MyInvocation.BoundParameters.Item($key) -is [system.array]) #String-array params
                        {
                            $ArrToString = ($MyInvocation.BoundParameters.Item($key) -join '","').insert(0,'"') + '"'
                            $ParamString += ".AddParameter(`"$key`",@($ArrToString))"
                        }
                        else #Single-string params
                        {
                            $ParamString += ".AddParameter(`"$key`",`"$($MyInvocation.BoundParameters.Item($key))`")"
                        }
                    } 
                }
            }

            # Configuring initial session state
            $iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()

            if($ImportModules) #Importing modules into the iss
            {
                foreach($mod in $ImportModules)
                {
                    $modules += @($NMEModules."$mod")
                }

                $iss.ImportPSModule($modules)
            }

            if($ImportVariables) #Importing variables into the iss
            {
                foreach($var in $ImportVariables)
                {
                    $varEntry = New-Object System.Management.Automation.Runspaces.SessionStateVariableEntry -ArgumentList "$var",(Invoke-Expression ('$' + "$var")),$null
                    $iss.Variables.Add($varEntry)
                }
            }

            # Setting up runspace pool
            $runspacepool = [runspacefactory]::CreateRunspacePool(1, $ThreadLimit, $iss, $host)
            $runspacepool.Open()

            #Building powershell command
            $Command = [scriptblock]::Create("[powershell]::Create().AddScript(`$ScriptBlock).AddParameter(`"Target`",`$Target)" + $ParamString)

            #Creating array for storing threads, handles and job results
            $JobsArray = New-Object System.Collections.ArrayList

            $message = 'Starting multi-thread processing'
            LogEvent -Command $CmdName -Severity Info -Event $message -ToFile -ToConsole

            Function GetResults #Defining function for monitoring jobs and fetching results            {			    param                (                    [switch]$WaitForCompletion                )                			    do                {				    $HasData = $false                    foreach($job in $jobsArray)                    {					    if ($job.Handle.isCompleted)                        {                            $job.Result = $job.Thread.EndInvoke($job.Handle)						    $job.Thread.dispose()						    $job.Handle = $null						    $job.Thread = $null					    }                        elseif ($job.Handle -ne $null)                        {						    $HasData = $true					    }				    }				    if ($HasData -and $WaitForCompletion)                    {                        Start-Sleep -Milliseconds 100                    }			    } while ($HasData -and $WaitForCompletion)		    }
        }
    }
    
    PROCESS
    {
        if($MultiThread) #Invoking new thread for each target in pipe and storing threads/handles/results in jobsArray
        {
            $thread = Invoke-Command $Command
            $thread.RunspacePool = $runspacepool
            $rcvObj = "" | Select-Object Handle, Thread, Result
            $rcvObj.Thread = $thread
            $rcvObj.Handle = $thread.BeginInvoke()
            [void]$jobsArray.Add($rcvObj)

            GetResults
        }
        else
        {
            if(! ($Target -as [ipaddress])) #Resolves the IP address of a hostname-based target
            {
                try
                {
                    Write-Verbose "Attempting to resolve $target to an IP address"
                    $Target = ([System.Net.Dns]::GetHostAddresses($Target)).IPAddressToString
                
                    Write-Verbose "IP address successfully obtained ($Target)"
                }
                catch
                {
                    $message = "Unable to resolve target `'$Target`'"
                    LogEvent -Command $CmdName -Severity Err -Event $message -ToFile -ToConsole

                    return
                }
            }

            $ObjArray = @()

            if($Interface.Contains('NetApi'))
            {
                #NetWkstaUserEnum variables
                $servername = $Target
                $level = 1
                $bufptr = [intPtr]::Zero
                $prefmaxlen = -1
                $entriesread = 0
                $totalentries = 0
                $resume_handle = 0

                $message = 'Enumerating logged-on users (Netapi)'

                if($SuppressMessages)
                {
                    LogEvent -Source $Target -Command $CmdName -Severity Info -Event $message -ToFile
                }
                else
                {
                    LogEvent -Source $Target -Command $CmdName -Severity Info -Event $message -ToFile -ToConsole
                }

                Write-Verbose 'NetWkstaUserEnum request'

                if($NMEVars.CurrentUser -eq "ANONYMOUS LOGON")
                {
                    [void]$Advapi32::ImpersonateAnonymousToken($Kernel32::GetCurrentThread())
           
                    $message = $Netapi32::NetWkstaUserEnum($servername,$level,[ref]$bufptr,$prefmaxlen,[ref]$entriesread,[ref]$totalentries,[ref]$resume_handle)

                    [void]$Advapi32::RevertToSelf()
                }
                else
                {
                    $message = $Netapi32::NetWkstaUserEnum($servername,$level,[ref]$bufptr,$prefmaxlen,[ref]$entriesread,[ref]$totalentries,[ref]$resume_handle)

                }

                if($SuppressMessages)
                {
                    LogEvent -Source $Target -Command $CmdName -Event $message -ToFile -Native
                }
                else
                {
                    LogEvent -Source $Target -Command $CmdName -Event $message -ToFile -ToConsole -Native
                }

                if($message -eq 0) #Parses data returned based on WKSTA_USER_INFO_1 structure
                {
                    $structSize = [WKSTA_USER_INFO_1]::GetSize()
                    $currentPtr = $bufptr

                    for ($i = 0; $i -lt $entriesread; $i++) #Process each entry in the results buffer
                    {
                        $obj = [System.Runtime.InteropServices.Marshal]::PtrToStructure($currentPtr, [System.Type]([WKSTA_USER_INFO_1])) #Casting current buffer to selected structure

                        $loggedonObj = New-Object psobject -Property @{
                            Username     = $obj.wkui1_username
                            LogonDomain  = $obj.wkui1_logon_domain
                            OtherDomains = $obj.wkui1_oth_domains
                            LogonServer  = $obj.wkui1_logon_server
                        }

                        $ObjArray += $loggedonObj

                        $currentPtr = [System.IntPtr]::Add($currentPtr.ToInt32(), $structSize) #Incrementing pointer for next iteration
                    }
                }

                [void]$Netapi32::NetApiBufferFree($bufptr) #Clears NetApi buffer from previous request
            }
        
            if($Interface.Contains('Registry'))
            {
                $message = 'Enumerating logged on users (Registry)'
            
                if($SuppressMessages)
                {
                    LogEvent -Source $Target -Command $CmdName -Severity Info -Event $message -ToFile
                }
                else
                {
                    LogEvent -Source $Target -Command $CmdName -Severity Info -Event $message -ToFile -ToConsole
                }

                try
                {
                    $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey("USERS",$Target)

                    $sids = $reg.GetSubKeyNames()|?{($_ -notlike "*DEFAULT") -and ($_ -notlike "*Classes")} #Enumerating keys on remote computer that can be translated to logged-on users

                    foreach($s in $sids) #Doing sid-to-user lookups
                    {
                        $sidObj = [System.Security.Principal.SecurityIdentifier]$s
                    
                        $bSid = New-Object Byte[] $sidObj.binaryLength
                        $sidObj.GetBinaryForm($bSid, 0)

                        $UserName = New-Object System.Text.StringBuilder
                        $DomainName = New-Object System.Text.StringBuilder
                        $cchUser = [uint32]$UserName.Capacity
                        $cchDomain = [uint32]$DomainName.Capacity
                        $sidType = [SID_NAME_USE]::SidTypeUnKnown
                        #$sidType = [SID_NAME_USE]::SidTypeUnknown
                    
                        Write-Verbose 'LookupAccountSid request'

                        if($NMEVars.CurrentUser -eq "ANONYMOUS LOGON")
                        {
                            [void]$Advapi32::ImpersonateAnonymousToken($Kernel32::GetCurrentThread())

                            #$message = $Advapi32::LookupAccountSid($Target,$bSid,$UserName,[ref]$cchUser,$DomainName,[ref]$cchDomain,[ref]$sidType)
                            $message = [NativeGetLoggedOn]::LookupAccountSid($Target,$bSid,$UserName,[ref]$cchUser,$DomainName,[ref]$cchDomain,[ref]$sidType)
           
                            [void]$Advapi32::RevertToSelf()
                        }
                        else
                        {
                            #$message = $Advapi32::LookupAccountSid($Target,$bSid,$UserName,[ref]$cchUser,$DomainName,[ref]$cchDomain,[ref]$sidType)
                            $message = [NativeGetLoggedOn]::LookupAccountSid($Target,$bSid,$UserName,[ref]$cchUser,$DomainName,[ref]$cchDomain,[ref]$sidType)
                        }

                        #if ($Advapi32::LookupAccountSid($Target,$bSid,$UserName2,[ref]$cchUser2,$DomainName2,[ref]$cchDomain2,[ref]$sidType))
                        if ($message -ne 0)
                        {
                            $loggedonObj = New-Object psobject -Property @{
                                Username     = $UserName.ToString()
                                LogonDomain  = $DomainName.ToString()
                                OtherDomains = $null
                                LogonServer  = $null
                            }

                            $ExistingObj = $ObjArray|
                                ?{$_.UserName -eq $UserName}|
                                ?{$_.LogonDomain -eq $DomainName}
        
                            if($ExistingObj)
                            {
                                Write-Verbose "LoggedonObj $DomainName\$UserName already exists (skipping)"
                            }
                            else
                            {
                                $objArray += $loggedonObj
                            }

                            <#foreach($i in $objArray) #Checks if object already exists
                            {
                                if( !(Compare-Object $i $loggedonObj -Property UserName,LogonDomain))
                                {
                                    $ObjExist = $true
                                    break
                                }
                            }

                            if($ObjExist)
                            {
                                Write-Verbose "LoggedonObj $DomainName\$UserName already exists (skipping)"
                            }
                            else
                            {
                                $objArray += $loggedonObj
                            }#>
                        }
                        else
                        {
                            $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                            $message = New-Object System.ComponentModel.Win32Exception([int]$err)
                            Write-Verbose $message
                        }
                    }
                
                    $message = 'The operation completed successfully'

                    if($SuppressMessages)
                    {
                        LogEvent -Source $Target -Command $CmdName -Severity Info -Event $message -ToFile
                    }
                    else
                    {
                        LogEvent -Source $Target -Command $CmdName -Severity Info -Event $message -ToFile -ToConsole
                    }
                }
                catch
                {
                    if ($_.FullyQualifiedErrorId -like "*UnauthorizedAccess*") #Rule to harmonize access-denied-related errors
                    {
                        $message = 'Access is denied'
                    }
                    else
                    {
                        $message = $_.Exception.Message
                    }

                    if($SuppressMessages)
                    {
                        LogEvent -Source $Target -Command $CmdName -Severity Err -Event $message -ToFile
                    }
                    else
                    {
                        LogEvent -Source $Target -Command $CmdName -Severity Err -Event $message -ToFile -ToConsole
                    }
                }
            }

            if($ObjArray)
            {
                if(! $DontFeedObject) #Writing array to computer object
                {
                    $CompObj = Get-ComputerObject -IP $Target
                    $CompObj.LoggedOn = $ObjArray
                }

                $Results += $ObjArray |Select-Object * |Add-Member IPAddress $Target -PassThru #Bulding results object for later console output
            }

            if($ShowProgress)
            {
                $Counter.Done++
                Write-Progress -Activity 'Enumerating logged-on users' -Status "$($Counter.Done) of $($Counter.Total) targets completed" -PercentComplete (($($Counter.Done)/$($Counter.Total))*100)
            }
        }
    }

    END
    {
        if($MultiThread)
        {
            GetResults -WaitForCompletion

            $message = 'Multi-thread processing completed'
            LogEvent -Command $CmdName -Severity Info -Event $message -ToFile -ToConsole

            Write-Host ""
            Write-Output $JobsArray.Result
        }
        else
        {
            Write-Output $Results |Select-object IPAddress,UserName,LogonDomain,LogonServer,OtherDomains
        }
    }
}

#######################
# Custom type imports #
#######################

$Native = @'
using System;
using System.Runtime.InteropServices;
using System.Text;

public enum SID_NAME_USE 
{
    SidTypeUser = 1,
    SidTypeGroup,
    SidTypeDomain,
    SidTypeAlias,
    SidTypeWellKnownGroup,
    SidTypeDeletedAccount,
    SidTypeInvalid,
    SidTypeUnknown,
    SidTypeComputer
}
    
public class NativeGetLoggedOn
{
    public const int NO_ERROR = 0;
    public const int ERROR_INSUFFICIENT_BUFFER = 122;

    [DllImport("advapi32.dll", CharSet=CharSet.Auto, SetLastError = true)]
    public static extern bool LookupAccountSid (
        string lpSystemName,
        [MarshalAs(UnmanagedType.LPArray)] byte[] Sid,
        StringBuilder lpName,
        ref uint cchName,
        StringBuilder ReferencedDomainName,
        ref uint cchReferencedDomainName,
        out SID_NAME_USE peUse
        );
}
'@

Add-Type -TypeDefinition $Native