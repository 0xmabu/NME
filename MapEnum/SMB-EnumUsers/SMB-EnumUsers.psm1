<#
 
.SYNOPSIS
Enumerates user accounts on a Windows computer.
 
.DESCRIPTION
This tool enumerates user accounts on a remote Windows computer. It makes use of the NetUserEnum function exposed in NetApi32.

The query issued by this tool usually require at least user privileges on the target computer. This can vary, though, depending on the version and configuration of the SMB server.

The tool outputs a computer object with user account information.

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
<computer objects>|NME-SMB-EnumUsers

.EXAMPLE
NME-SMB-EnumUsers -Target 192.168.56.22 |Format-Table -AutoSize

.EXAMPLE
<computer objects>|?{$_.IPAddress -like "192.168.5*"}|NME-SMB-EnumUsers -MultiThread -ShowProgress

.NOTES

Module dependencies
-------------------
- Environment: HelperFunctions, CreateObjects
- External: PSReflect

Data update policy
------------------
- Replaces all data for existing object unless results are null

Issues
------
- User logon hours not calculated properly
  
.LINK
NetUserEnum (NetApi):
- http://msdn.microsoft.com/en-us/library/windows/desktop/aa370652%28v=vs.85%29.aspx

PowerSploit Framework
- https://github.com/mattifestation/PowerSploit

#>

Function Get-SMBUsers
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
        $CmdName = 'Get-SMBUsers'
        $CmdAlias = 'NME-SMB-EnumUsers'
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

            $objArray = @()

            #NetUserEnum arguments
            $servername = $target
            $level = 3
            $filter = 0
            $bufptr = [intPtr]::Zero
            $prefmaxlen = -1
            $entriesread = 0
            $totalentries = 0
            $resume_handle = 0
        
            $message = 'Enumerating user accounts'
            
            if($SuppressMessages)
            {
                LogEvent -Source $Target -Command $CmdName -Severity Info -Event $message -ToFile
            }
            else
            {
                LogEvent -Source $Target -Command $CmdName -Severity Info -Event $message -ToFile -ToConsole
            }

            Write-Verbose 'NetUserEnum request'
        
            if($NMEVars.CurrentUser -eq 'ANONYMOUS LOGON')
            {
                [void]$Advapi32::ImpersonateAnonymousToken($Kernel32::GetCurrentThread())
           
                $message = $Netapi32::NetUserEnum($servername,$level,$filter,[ref]$bufptr,$prefmaxlen,[ref]$entriesread,[ref]$totalentries,[ref]$resume_handle)
           
                [void]$Advapi32::RevertToSelf()
            }
            else
            {
                $message = $Netapi32::NetUserEnum($servername,$level,$filter,[ref]$bufptr,$prefmaxlen,[ref]$entriesread,[ref]$totalentries,[ref]$resume_handle)
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
                $structSize = [USER_INFO_3]::GetSize()
                $currentPtr = $bufptr

                for ($i = 0; $i -lt $entriesread; $i++) #Process each entry in the results buffer
                {
                    $obj = [System.Runtime.InteropServices.Marshal]::PtrToStructure($currentPtr, [System.Type]([USER_INFO_3])) #Casting current buffer to selected structure

                    $userObj = New-Object psobject -Property @{
                    Name            = $obj.usri3_name
                    Password        = $obj.usri3_password
                    PasswordAge     = $null
                    Priv            = $obj.usri3_priv
                    HomeDir         = $obj.usri3_home_dir
                    Comment         = $obj.usri3_comment
                    Flags           = $null
                    ScriptPath      = $obj.usri3_script_path
                    AuthFlags       = $null
                    FullName        = $obj.usri3_full_name
                    UsrComment      = $obj.usri3_usr_comment
                    Params          = $obj.usri3_params
                    Workstations    = $obj.usri3_workstations
                    LastLogoff      = $null
                    LastLogon       = $null
                    AcctExpires     = $null
                    MaxStorage      = $null
                    #UnitsPerWeek    = $obj.usri3_units_per_week
                    #LogonHours      = $obj.usri3_logon_hours <- Unlcear how to calculate this, see http://technet.microsoft.com/pt-br/aa371338%28v=vs.71%29.aspx
                    BadPwCount      = $obj.usri3_bad_pw_count
                    NumLogons       = $obj.usri3_num_logons
                    LogonServer     = $obj.usri3_logon_server
                    CountryCode     = $obj.usri3_country_code
                    CodePage        = $obj.usri3_code_page
                    UserId          = $obj.usri3_user_id
                    PrimaryGroupId  = $obj.usri3_primary_group_id
                    Profile         = $obj.usri3_profile
                    HomeDirDrive    = $obj.usri3_home_dir_drive
                    PasswordExpired = $obj.usri3_password_expired
                    } #Creates result object
                
                    #Below functions translate various property values to human-readable form
                    $time = New-TimeSpan -Seconds $obj.usri3_password_age
                    #$userObj.PasswordAge = "$($time.days)(days)$($time.hours)(hours)$($time.minutes)(mins)"
                    $userObj.PasswordAge = "$($time.days):$($time.hours):$($time.minutes):$($time.seconds) (D:H:M:S)"

                    foreach($value in [USER_FLAGS].GetEnumValues().value__)
                    {
                        if(($value -band $obj.usri3_flags) -ne 0)
                        {
                            $userObj.Flags += ([USER_FLAGS]$value).ToString() + ";"
                        }
                    }

                    foreach($value in [AUTH_FLAGS].GetEnumValues().value__)
                    {
                        if(($value -band $obj.usri3_auth_flags) -ne 0)
                        {
                            $userObj.AuthFlags += ([AUTH_FLAGS]$value).ToString() + ";"
                        }
                    }

                    $startdate = [datetime]'01/01/1970'
                    $userObj.LastLogoff = ($startdate + (New-TimeSpan -Seconds $obj.usri3_last_logoff)).GetDateTimeFormats()[22]
                    $userObj.LastLogon = ($startdate + (New-TimeSpan -Seconds $obj.usri3_last_logon)).GetDateTimeFormats()[22]
                
                    if($obj.usri3_acct_expires -eq 4294967295)
                    {
                        $userObj.AcctExpires = 'Does not expire'
                    }
                    else
                    {
                        $userObj.AcctExpires = ($startdate + (New-TimeSpan -Seconds $obj.usri3_acct_expires)).GetDateTimeFormats()[22]
                    }

                    if($obj.usri3_max_storage -eq 4294967295)
                    {
                        $userObj.MaxStorage = 'No max storage'
                    }
                    else
                    {
                        $userObj.MaxStorage = $obj.usri3_max_storage
                    }

                    $objArray += $userObj

                    $currentPtr = [System.IntPtr]::Add($currentPtr.ToInt32(), $structSize) #Incrementing pointer for next iteration
                }
            }

            [void]$Netapi32::NetApiBufferFree($bufptr) #Clears NetApi buffer from previous request

            if($objArray)
            {
                $CompObj = Get-ComputerObject -IP $Target
                $CompObj.Users = $objArray

                $Results += $objArray |Select-Object * |Add-Member IPAddress $Target -PassThru #Bulding results object for console output
            }

            if($ShowProgress)
            {
                $Counter.Done++
                Write-Progress -Activity 'Enumerating users' -Status "$($Counter.Done) of $($Counter.Total) targets completed" -PercentComplete (($($Counter.Done)/$($Counter.Total))*100)
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
            Write-Output $Results |Select-object IPAddress,Name,Priv,Comment
        }
    }
}