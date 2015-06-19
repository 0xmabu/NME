<#

.SYNOPSIS
Enumerate groups on a Windows computer.

.DESCRIPTION
This tool enumerates local and global group accounts on a remote Windows computer, including their member users. It makes use of the NetLocalGroupEnum, NetLocalGroupGetMembers, NetGroupEnum and NetGroupGetUsers functions exposed in Netapi32.

The queries issued by this tool usually require at least user privileges on the target computer. This can vary, though, depending on the version and configuration of the SMB server.

This tool outputs a Computer object with group account information.

.PARAMETER Target
The target computer, specified as a single hostname or IP address. The tool also supports multiple targets as computer objects through the pipeline.

.PARAMETER Type
The group type(s) to be enumerated, including "Local" and/or "Global". The default value is to enumerate both.

.PARAMETER ExcludeMembers
Prevents the enumeration of group members.

.PARAMETER MultiThread
Enables multi-threading, where each target is processed by its own thread.

.PARAMETER ThreadLimit
The maximum number of threads that will be assigned when multi-threading. The default value is 20.

.PARAMETER ShowProgress
Enables a progress bar.

.PARAMETER SuppressMessages
Prevents event messages from being printed to the screen.

.PARAMETER DontFeedObject
Prevents results from being saved to the Computer object. By default, results are saved to the "Groups" property of the object. This is done according to the data update policy defined for this tool (see notes).

.EXAMPLE
<computer objects>|NME-SMB-EnumGroups

.EXAMPLE
NME-SMB-EnumGroups -Target 192.168.56.22 |Format-table -Autosize

.EXAMPLE
<computer objects>|?{$_.IPAddress -like "192.168.5*"}|NME-SMB-EnumGroups -MultiThread -ShowProgress

.NOTES

Data update policy
------------------
Replaces all data for existing object.

Module dependencies
-------------------
- Environment: HelperFunctions, CreateObjects
- External: PSReflect

.LINK
NetLocalGroupEnum function
- http://msdn.microsoft.com/en-us/library/windows/desktop/aa370440%28v=vs.85%29.aspx

NetLocalGroupGetMembers function
- http://msdn.microsoft.com/en-us/library/windows/desktop/aa370601%28v=vs.85%29.aspx

NetGroupEnum function
- http://msdn.microsoft.com/en-us/library/windows/desktop/aa370428%28v=vs.85%29.aspx

NetGroupGetUsers function
- http://msdn.microsoft.com/en-us/library/windows/desktop/aa370430%28v=vs.85%29.aspx

PowerSploit Framework
- https://github.com/mattifestation/PowerSploit

#>

Function Get-SMBGroups
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]
        [Alias('IPAddress')]
        [string]$Target,

        [Parameter()]
        [ValidateSet('Local','Global')]
        [string[]]$Type = ('Local','Global'),

        [Parameter()]
        [switch]$ExcludeMembers,

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
        $CmdName = 'Get-SMBGroups'
        $CmdAlias = 'NME-SMB-EnumGroups'
        $Results = @()

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
        else #Main processing
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

            $ObjArray = @()
            $servername = $target

            if($Type.Contains('Local'))
            {
                #NetLocalGroupEnum variables
                $lg_level         = 1
                $lg_bufptr        = [intPtr]::Zero
                $lg_prefmaxlen    = -1
                $lg_entriesread   = 0
                $lg_totalentries  = 0
                $lg_resume_handle = 0

                $message = 'Enumerating local groups'
                
                if($SuppressMessages)
                {
                    LogEvent -Source $Target -Command $CmdName -Severity Info -Event $message -ToFile
                }
                else
                {
                    LogEvent -Source $Target -Command $CmdName -Severity Info -Event $message -ToFile -ToConsole
                }

                Write-Verbose 'NetLocalGroupEnum request'
            
                if($NMEVars.CurrentUser -eq 'ANONYMOUS LOGON')
                {
                    [void]$Advapi32::ImpersonateAnonymousToken($Kernel32::GetCurrentThread())

                    $message = $Netapi32::NetLocalGroupEnum($servername,$lg_level,[ref]$lg_bufptr,$lg_prefmaxlen,[ref]$lg_entriesread,[ref]$lg_totalentries,[ref]$lg_resume_handle)
           
                    [void]$Advapi32::RevertToSelf()
                }
                else
                {
                    $message = $Netapi32::NetLocalGroupEnum($servername,$lg_level,[ref]$lg_bufptr,$lg_prefmaxlen,[ref]$lg_entriesread,[ref]$lg_totalentries,[ref]$lg_resume_handle)
                }

                if($SuppressMessages)
                {
                    LogEvent -Source $Target -Command $CmdName -Event $message -ToFile -Native
                }
                else
                {
                    LogEvent -Source $Target -Command $CmdName -Event $message -ToFile -ToConsole -Native
                }

                if($message -eq 0) #Parses data returned based on LOCALGROUP_INFO_1 structure
                {
                    $lg_structSize = [LOCALGROUP_INFO_1]::GetSize()
                    $lg_currentPtr = $lg_bufptr

                    for ($i = 0; $i -lt $lg_entriesread; $i++) #Process each entry in the results buffer
                    {
                        $lg_obj = [System.Runtime.InteropServices.Marshal]::PtrToStructure($lg_currentPtr, [System.Type]([LOCALGROUP_INFO_1])) #Casting current buffer to selected structure

                        $groupObj  = New-Object psobject -Property @{
                            Name    = $lg_obj.lgrpi1_name
                            Comment = $lg_obj.lgrpi1_comment
                            Type    = "Local"
                            Members = @()
                        } |Select-Object Name,Comment,Type,Members #Creates results object

                        $ObjArray += $groupObj

                        $lg_currentPtr = [System.IntPtr]::Add($lg_currentPtr.ToInt32(), $lg_structSize) #Incrementing pointer for next iteration

                        if(! ($ExcludeMembers))
                        {
                            #NetLocalGroupGetMembers variables
                            $lgm_group = $groupObj.Name
                            $lgm_level = 3
                            $lgm_bufptr = [intPtr]::Zero
                            $lgm_prefmaxlen = -1
                            $lgm_entriesread = 0
                            $lgm_totalentries = 0
                            $lgm_resume_handle = 0

                            Write-Verbose 'NetLocalGroupGetMembers request'

                            if($NMEVars.CurrentUser -eq 'ANONYMOUS LOGON')
                            {
                                [void]$Advapi32::ImpersonateAnonymousToken($Kernel32::GetCurrentThread())
                            
                                $message = $Netapi32::NetLocalGroupGetMembers($servername,$lgm_group,$lgm_level,[ref]$lgm_bufptr,$lgm_prefmaxlen,[ref]$lgm_entriesread,[ref]$lgm_totalentries,[ref]$lgm_resume_handle)
                            
                                [void]$Advapi32::RevertToSelf()
                            }
                            else
                            {
                                $message = $Netapi32::NetLocalGroupGetMembers($servername,$lgm_group,$lgm_level,[ref]$lgm_bufptr,$lgm_prefmaxlen,[ref]$lgm_entriesread,[ref]$lgm_totalentries,[ref]$lgm_resume_handle)
                            }
                        
                            if($message -eq 0) #Parses data returned based on LOCALGROUP_MEMBERS_INFO_3 structure
                            {
                                $lgm_structSize = [LOCALGROUP_MEMBERS_INFO_3]::GetSize()
                                $lgm_currentPtr = $lgm_bufptr
            
                                for ($j = 0; $j -lt $lgm_entriesread; $j++) #Process each entry in the results buffer
                                {
                                    $lgm_obj = [System.Runtime.InteropServices.Marshal]::PtrToStructure($lgm_currentPtr, [System.Type]([LOCALGROUP_MEMBERS_INFO_3])) #Casting current buffer to selected structure

                                    $groupObj.Members += $lgm_obj

                                    $lgm_currentPtr = [System.IntPtr]::Add($lgm_currentPtr.ToInt32(), $lgm_structSize) #Incrementing pointer for next iteration
                                }
                            }

                            [void]$Netapi32::NetApiBufferFree($lgm_bufptr) #Clears NetApi buffer from previous request
                        }
                    }
                }

                [void]$Netapi32::NetApiBufferFree($lg_bufptr) #Clears NetApi buffer from previous request
            }

            if($Type.Contains('Global'))
            {
                #NetGroupEnum variables
                $gg_level = 2
                $gg_bufptr = [intPtr]::Zero
                $gg_prefmaxlen = -1
                $gg_entriesread = 0
                $gg_totalentries = 0
                $gg_resume_handle = 0

                $message = 'Enumerating global groups'

                if($SuppressMessages)
                {
                    LogEvent -Source $Target -Command $CmdName -Severity Info -Event $message -ToFile
                }
                else
                {
                    LogEvent -Source $Target -Command $CmdName -Severity Info -Event $message -ToFile -ToConsole
                }

                Write-Verbose 'NetGroupEnum request'
            
                if($NMEVars.CurrentUser -eq 'ANONYMOUS LOGON')
                {
                    [void]$Advapi32::ImpersonateAnonymousToken($Kernel32::GetCurrentThread())

                    $message = $Netapi32::NetGroupEnum($servername,$gg_level,[ref]$gg_bufptr,$gg_prefmaxlen,[ref]$gg_entriesread,[ref]$gg_totalentries,[ref]$gg_resume_handle)

                    [void]$Advapi32::RevertToSelf()
                }
                else
                {
                    $message = $Netapi32::NetGroupEnum($servername,$gg_level,[ref]$gg_bufptr,$gg_prefmaxlen,[ref]$gg_entriesread,[ref]$gg_totalentries,[ref]$gg_resume_handle)
                }

                if($SuppressMessages)
                {
                    LogEvent -Source $Target -Command $CmdName -Event $message -ToFile -Native
                }
                else
                {
                    LogEvent -Source $Target -Command $CmdName -Event $message -ToFile -ToConsole -Native
                }

                if($message -eq 0) #Parses data returned based on GROUP_INFO_2 structure
                {
                    $gg_structSize = [GROUP_INFO_2]::GetSize()
                    $gg_currentPtr = $gg_bufptr

                    for ($i = 0; $i -lt $gg_entriesread; $i++) #Process each entry in the results buffer
                    {
                        $gg_obj = [System.Runtime.InteropServices.Marshal]::PtrToStructure($gg_currentPtr, [System.Type]([GROUP_INFO_2])) #Casting current buffer to selected structure

                        $groupObj  = New-Object psobject -Property @{
                            Name       = $gg_obj.grpi2_name
                            Comment    = $gg_obj.grpi2_comment
                            Attributes = $gg_obj.grpi2_attributes
                            Rid        = $gg_obj.grpi2_group_id
                            Type       = "Global"
                            Members    = @()
                        } |Select-Object Name,Comment,Type,Members,Rid #Creates results object

                        $objArray += $groupObj

                        $gg_currentPtr = [System.IntPtr]::Add($gg_currentPtr.ToInt32(), $gg_structSize) #Incrementing pointer for next iteration

                        if(! ($ExcludeMembers))
                        {
                            #NetGroupGetUsers variables
                            $ggm_group = $groupObj.Name
                            $ggm_level = 0
                            $ggm_bufptr = [intPtr]::Zero
                            $ggm_prefmaxlen = -1
                            $ggm_entriesread = 0
                            $ggm_totalentries = 0
                            $ggm_resume_handle = 0

                            Write-Verbose 'NetGroupGetUsers request'

                            if($NMEVars.CurrentUser -eq 'ANONYMOUS LOGON')
                            {
                                [void]$Advapi32::ImpersonateAnonymousToken($Kernel32::GetCurrentThread())
                            
                                $message = $Netapi32::NetGroupGetUsers($servername,$ggm_group,$ggm_level,[ref]$ggm_bufptr,$ggm_prefmaxlen,[ref]$ggm_entriesread,[ref]$ggm_totalentries,[ref]$ggm_resume_handle)

                                [void]$Advapi32::RevertToSelf()
                            }
                            else
                            {
                                $message = $Netapi32::NetGroupGetUsers($servername,$ggm_group,$ggm_level,[ref]$ggm_bufptr,$ggm_prefmaxlen,[ref]$ggm_entriesread,[ref]$ggm_totalentries,[ref]$ggm_resume_handle)
                            }

                            if($message -eq 0) #Parses data returned based on GROUP_USERS_INFO_0 structure
                            {
                                $ggm_structSize = [GROUP_USERS_INFO_0]::GetSize()
                                $ggm_currentPtr = $ggm_bufptr

                                for ($j = 0; $j -lt $ggm_entriesread; $j++) #Process each entry in the results buffer
                                {
                                    $ggm_obj = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ggm_currentPtr, [System.Type]([GROUP_USERS_INFO_0])) #Casting current buffer to selected structure

                                    $groupObj.Members += $ggm_obj

                                    $ggm_currentPtr = [System.IntPtr]::Add($ggm_currentPtr.ToInt32(), $ggm_structSize) #Incrementing pointer for next iteration
                                }
                            }

                            [void]$Netapi32::NetApiBufferFree($ggm_bufptr)
                        }
                    }
                }

                [void]$Netapi32::NetApiBufferFree($gg_bufptr)
            }

            if($ObjArray)
            {
                if(! $DontFeedObject) #Writing array to computer object
                {
                    $CompObj = Get-ComputerObject -IP $Target
                    $CompObj.Groups = $ObjArray
                }

                $Results += $ObjArray |Select-Object * |Add-Member IPAddress $Target -PassThru #Bulding results object for console output
            }

            if($ShowProgress)
            {
                $Counter.Done++
                Write-Progress -Activity 'Enumerating groups' -Status "$($Counter.Done) of $($Counter.Total) targets completed" -PercentComplete (($($Counter.Done)/$($Counter.Total))*100)
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
            Write-Output $Results |Select-object IPAddress,Name,Comment,Type,Members
        }
    }
}