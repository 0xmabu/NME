<#
 
.SYNOPSIS
Enumerates the account policy on a Windows computer.
 
.DESCRIPTION
This tool enumerates account policy information for objects in the account database (SAM or Active Directory) on a remote Windows computer. It does this using the NetUserModalsGet function exposed in NetApi32.

The queries issued by this tool usually require at least user privileges on the target computer. This can vary, though, depending on the version and configuration of the SMB server.

This tool outputs a Computer object with account policy information.

.PARAMETER Target
The target computer, specified as a single hostname or IP address. The tool also supports multiple targets as computer objects through the pipeline.

.PARAMETER MultiThread
Enables multi-threading, where each target is processed by its own thread.

.PARAMETER ThreadLimit
The maximum number of threads that will be assigned when multi-threading. The default value is 20.

.PARAMETER ShowProgress
Enables a progress bar.

.PARAMETER SuppressMessages
Prevents event messages from being printed to the screen.

.EXAMPLE
<computer objects>|NME-SMB-EnumAccountPolicy

.EXAMPLE
NME-SMB-EnumAccountPolicy -Target 192.168.56.22 |Format-table -Autosize

.EXAMPLE
<computer objects>|?{$_.IPAddress -like "192.168.5*"}|NME-SMB-EnumAccountPolicy -MultiThread -ShowProgress

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
- No password complexity data included as of yet (http://msdn.microsoft.com/en-us/library/windows/desktop/aa375371%28v=vs.85%29.aspx)
- LogonSrvRole and LogonSrvPrimary properties not properly translated

.LINK
NetUserModalsGet (NetApi):
- http://msdn.microsoft.com/en-us/library/windows/desktop/aa370656%28v=vs.85%29.aspx

PowerSploit Framework
- https://github.com/mattifestation/PowerSploit

#>

Function Get-SMBAccountPolicy
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]
        [Alias('IPAddress')]
        [string]$Target,

        [Parameter()]
        [switch]$MultiThread,

        [Parameter()]
        [int]$ThreadLimit = 20,

        [Parameter()]
        [switch]$ShowProgress,

        [Parameter()]
        [switch]$SuppressMessages
    )

    BEGIN
    {
        #Default functions/variables
        $CmdName = 'Get-SMBPAccountolicy'
        $CmdAlias = 'NME-SMB-EnumAccountPolicy'
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

            $policyObj  = New-Object psobject -Property @{
                PwdMinLength       = $null
                PwdMaxAge          = $null
                PwdMinAge          = $null
                PwdHistory         = $null
                AccLockDuration    = $null
                AccLockThreshold   = $null
                AccLockWindow      = $null
                ForceLogoff        = $null
                SamDomain          = $null
                SamDomainId        = $null
                LogonSrvRole       = $null
                LogonSrvPrimary    = $null
            }|Select-Object PwdMinLength,PwdMaxAge,PwdMinAge,PwdHistory,AccLockDuration,AccLockThreshold,AccLockWindow,ForceLogoff,SamDomain,SamDomainId,LogonSrvRole,LogonSrvPrimary

            $servername = $target

            $bufptr = [intPtr]::Zero

            $message = 'Enumerating account policy'
            
            if($SuppressMessages)
            {
                LogEvent -Source $Target -Command $CmdName -Event $message -Severity Info -ToFile
            }
            else
            {
                LogEvent -Source $Target -Command $CmdName -Event $message -Severity Info -ToFile -ToConsole
            }
                    
            Write-Verbose 'Level 0 request'

            if($NMEVars.CurrentUser -eq 'ANONYMOUS LOGON')
            {
                [void]$Advapi32::ImpersonateAnonymousToken($Kernel32::GetCurrentThread())
           
                $message = $Netapi32::NetUserModalsGet($servername, 0, [ref]$bufptr)
                       
                [void]$Advapi32::RevertToSelf()
            }
            else
            {
                $message = $Netapi32::NetUserModalsGet($servername, 0, [ref]$bufptr)
            }

            if($SuppressMessages)
            {
                LogEvent -Source $Target -Command $CmdName -Event $message -ToFile -Native
            }
            else
            {
                LogEvent -Source $Target -Command $CmdName -Event $message -ToFile -ToConsole -Native
            }

            if($message -eq 0) #Parses data returned based on USER_MODALS_INFO_0 structure
            {
                $currentPtr = $bufptr

                $obj = [System.Runtime.InteropServices.Marshal]::PtrToStructure($currentPtr, [System.Type]([USER_MODALS_INFO_0])) #Casting current buffer to selected structure

                $policyObj.PwdMinLength = $obj.usrmod0_min_passwd_len
                $policyObj.PwdMaxAge    = [decimal]::Floor($obj.usrmod0_max_passwd_age / 86400)
                $policyObj.PwdMinAge    = ($obj.usrmod0_min_passwd_age / 86400)
                $policyObj.PwdHistory   = $obj.usrmod0_password_hist_len
            
                if($obj.usrmod0_force_logoff -eq 4294967295)
                {
                    $policyObj.ForceLogoff = 'No forced logoff'
                }
                else
                {
                    $policyObj.ForceLogoff = $obj.usrmod0_force_logoff
                }
            }
        
            [void]$Netapi32::NetApiBufferFree($bufptr) #Clears NetApi buffer from previous request

            $bufptr = [intPtr]::Zero

            Write-Verbose 'Level 1 request'

            if($NMEVars.CurrentUser -eq 'ANONYMOUS LOGON')
            {
                [void]$Advapi32::ImpersonateAnonymousToken($Kernel32::GetCurrentThread())
           
                $message = $Netapi32::NetUserModalsGet($servername, 1, [ref]$bufptr)
                       
                [void]$Advapi32::RevertToSelf()
            }
            else
            {
                $message = $Netapi32::NetUserModalsGet($servername, 1, [ref]$bufptr)
            }

            if($message -eq 0)  #Parses data returned based on USER_MODALS_INFO_1 structure
            {
                $currentPtr = $bufptr

                $obj = [System.Runtime.InteropServices.Marshal]::PtrToStructure($currentPtr, [System.Type]([USER_MODALS_INFO_1])) #Casting current buffer to structure

                $policyObj.LogonSrvRole    = $obj.usrmod1_role
                $policyObj.LogonSrvPrimary = $obj.usrmod1_primary
            }

            [void]$Netapi32::NetApiBufferFree($bufptr) #Clears NetApi buffer from previous request

            $bufptr = [intPtr]::Zero

            Write-Verbose 'Level 2 request'

            if($NMEVars.CurrentUser -eq 'ANONYMOUS LOGON')
            {
                [void]$Advapi32::ImpersonateAnonymousToken($Kernel32::GetCurrentThread())
           
                $message = $Netapi32::NetUserModalsGet($servername, 2, [ref]$bufptr)
                       
                [void]$Advapi32::RevertToSelf()
            }
            else
            {
                $message = $Netapi32::NetUserModalsGet($servername, 2, [ref]$bufptr)
            }
        
            if($message -eq 0) #Parses data returned based on USER_MODALS_INFO_2 structure
            {
                $structSize = [USER_MODALS_INFO_2]::GetSize()
                $currentPtr = $bufptr

                $polObj = [System.Runtime.InteropServices.Marshal]::PtrToStructure($currentPtr, [System.Type]([USER_MODALS_INFO_2])) #Casting current buffer to structure
                $currentPtr = [System.IntPtr]::Add($currentPtr.ToInt32(), $structSize) #Incrementing pointer to next iteration

                $sidObj = [System.Runtime.InteropServices.Marshal]::PtrToStructure($currentPtr, [System.Type]([SID])) #Casting current buffer to structure

                $str_sid = "S-" + $sidObj.Revision.ToString() + "-" + ($sidObj.IdentifierAuthority.Value.Length -1).ToString() + "-"

                for($i = 0; $i -lt $sidObj.SubAuthorityCount; $i++)
                {
                    $str_sid += $sidObj.SubAuthority[$i].ToString() + "-"
                }

                $str_sid = $str_sid.TrimEnd('-')

                $policyObj.SamDomain   = $polObj.usrmod2_domain_name
                $policyObj.SamDomainId = $str_sid
            }

            [void]$Netapi32::NetApiBufferFree($bufptr) #Clears NetApi buffer from previous request

            $bufptr = [intPtr]::Zero

            Write-Verbose 'Level 3 request'

            if($NMEVars.CurrentUser -eq 'ANONYMOUS LOGON')
            {
                [void]$Advapi32::ImpersonateAnonymousToken($Kernel32::GetCurrentThread())
           
                $message = $Netapi32::NetUserModalsGet($servername, 3, [ref]$bufptr)
                       
                [void]$Advapi32::RevertToSelf()
            }
            else
            {
                $message = $Netapi32::NetUserModalsGet($servername, 3, [ref]$bufptr)
            }

            if($message -eq 0) #Parses data returned based on USER_MODALS_INFO_3 structure
            {
                $currentPtr = $bufptr

                $obj = [System.Runtime.InteropServices.Marshal]::PtrToStructure($currentPtr, [System.Type]([USER_MODALS_INFO_3]))
            
                $policyObj.AccLockDuration = ($obj.usrmod3_lockout_duration / 60)
                $policyObj.AccLockWindow = ($obj.usrmod3_lockout_observation_window / 60)
                $policyObj.AccLockThreshold = $obj.usrmod3_lockout_threshold
            }    

            [void]$Netapi32::NetApiBufferFree($bufptr) #Clears NetApi buffer from previous request

            if($policyObj.SamDomain) #If value exists, then policyObj contains results that should be processed
            {
                $CompObj = Get-ComputerObject -IP $Target
                $CompObj.Policy = $policyObj

                $Results += $policyObj |Select-Object * |Add-Member IPAddress $Target -PassThru #Bulding results object for later console output
            }

            if($ShowProgress)
            {
                $Counter.Done++
                Write-Progress -Activity 'Enumerating account policy' -Status "$($Counter.Done) of $($Counter.Total) targets completed" -PercentComplete (($($Counter.Done)/$($Counter.Total))*100)
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
            Write-Output $Results |Select-object IPAddress,PwdMinLength,PwdMaxAge,PwdMinAge,PwdHistory,AccLockDuration,AccLockThreshold,AccLockWindow,ForceLogoff,SamDomain,LogonSrvRole,LogonSrvPrimary
        }
    }
}