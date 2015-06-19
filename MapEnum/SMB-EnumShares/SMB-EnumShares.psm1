<#
 
.SYNOPSIS
Enumerates shared folders on a Windows computer.
 
.DESCRIPTION
This tool enumerates file shares hosted on a remote Windows computer. It makes use of the NetShareEnum function exposed in NetApi32.

The query issued by this tool usually require at least user privileges on the target computer. This can vary, though, depending on the version and configuration of the SMB server.

This tool outputs a SMBShare object.

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
<computer objects>|NME-SMB-EnumShares

.EXAMPLE
NME-SMB-EnumShares -Target 192.168.56.22 |Format-table -Autosize

.EXAMPLE
<computer objects>|?{$_.IPAddress -like "192.168.5*"}|NME-SMB-EnumShares -MultiThread -ShowProgress

.NOTES

Data update policy
------------------
Replaces "Type" and "Remark" property data for existing object.

Module dependencies
-------------------
- Environment: HelperFunctions, CreateObjects
- External: PSReflect

.LINK
NetShareEnum (NetApi):
- http://msdn.microsoft.com/en-us/library/windows/desktop/bb525387%28v=vs.85%29.aspx

PowerSploit Framework
- https://github.com/mattifestation/PowerSploit

#>

Function Get-SMBShares
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
        $CmdName = 'Get-SMBShares'
        $CmdAlias = 'NME-SMB-EnumShares'
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
            $ImportModules = @('HelperFunctions','CreateObjects','PSReflect')
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
                    Write-Verbose "Attempting to resolve $Target to an IP address"
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

            #NetShareEnum arguments
            $servername = $target
            $level = 1
            $bufptr = [intPtr]::Zero
            $prefmaxlen = -1
            $entriesread = 0
            $totalentries = 0
            $resume_handle = 0
        
            $message = 'Enumerating shares'
            
            if($SuppressMessages)
            {
                LogEvent -Source $Target -Command $CmdName -Severity Info -Event $message -ToFile
            }
            else
            {
                LogEvent -Source $Target -Command $CmdName -Severity Info -Event $message -ToFile -ToConsole
            }

            Write-Verbose 'NetShareEnum request'

            if($NMEVars.CurrentUser -eq 'ANONYMOUS LOGON')
            {
                [void]$Advapi32::ImpersonateAnonymousToken($Kernel32::GetCurrentThread())

                $message = $Netapi32::NetShareEnum($servername,$level,[ref]$bufptr,$prefmaxlen,[ref]$entriesread,[ref]$totalentries,[ref]$resume_handle)

                [void]$Advapi32::RevertToSelf()
            }
            else
            {
                $message = $Netapi32::NetShareEnum($servername,$level,[ref]$bufptr,$prefmaxlen,[ref]$entriesread,[ref]$totalentries,[ref]$resume_handle)
            }

            if($SuppressMessages)
            {
                LogEvent -Source $Target -Command $CmdName -Event $message -ToFile -Native
            }
            else
            {
                LogEvent -Source $Target -Command $CmdName -Event $message -ToFile -ToConsole -Native
            }

            if($message -eq 0)
            {
                $structSize = [SHARE_INFO_1]::GetSize()
                $currentPtr = $bufptr
                        
                for ($i = 0; $i -lt $entriesread; $i++) #Process each entry in the results buffer
                {
                    $obj = [System.Runtime.InteropServices.Marshal]::PtrToStructure($currentPtr, [System.Type]([SHARE_INFO_1])) #Casting current buffer to selected structure

                    $ShareObj = Get-SMBShareObject -HostIP $Target -ShareName $obj.shi1_netname #Creates a share object

                    $ShareObj.Remark = $obj.shi1_remark
                    $ShareObj.Type   = $null
                
                    #The following switch is guesswork - it is unclear how the type value should be parsed...
                    #Ref: http://stackoverflow.com/questions/8235095/winapi-how-do-i-interpret-a-bitmask-of-0-lmshare-h-stype-disktree
                    #Ref: http://msdn.microsoft.com/en-us/library/cc247110.aspx
                    switch ($obj.shi1_type)
                    {
                        {($_ -band [SHARE_TYPE]::STYPE_SPECIAL.value__) -ne 0} {$shareObj.Type += "SPECIAL"}
                        {($_ -band [SHARE_TYPE]::STYPE_TEMPORARY.value__) -ne 0} {$shareObj.Type += "TEMPORARY"}
                        {$_ -eq [SHARE_TYPE]::STYPE_DISKTREE.value__} {$shareObj.Type += "DISKTREE"; break}
                        {$_ -eq [SHARE_TYPE]::STYPE_PRINTQ.value__} {$shareObj.Type += "PRINTQ"; break}
                        {$_ -eq [SHARE_TYPE]::STYPE_DEVICE.value__} {$shareObj.Type += "DEVICE"; break}
                        {$_ -eq [SHARE_TYPE]::STYPE_IPC.value__} {$shareObj.Type += "IPC"; break}   
                    }

                    $Results += $shareObj

                    $currentPtr = [System.IntPtr]::Add($currentPtr.ToInt32(), $structSize) #Incrementing pointer for next iteration
                }

                Get-ComputerObject -IP $Target |Out-Null #Verifies or creates a host computer object if services are found
            }

            [void]$Netapi32::NetApiBufferFree($bufptr) #Clears NetApi buffer from previous request

            if($ShowProgress)
            {
                $Counter.Done++
                Write-Progress -Activity 'Enumerating SMB shares' -Status "$($Counter.Done) of $($Counter.Total) targets completed" -PercentComplete (($($Counter.Done)/$($Counter.Total))*100)
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
            Write-Output $Results
        }
    }
}