<#
 
.SYNOPSIS
Test current status of remote computer.
 
.DESCRIPTION
This tool checks the availability of remote hosts, based on the respose to TCP or ICMP queries. The queries are built using the System.Net.Sockets.TcpClient and System.Net.NetworkInformation.Ping dotnet classes.

The tool outputs a Computer object with State information.

.PARAMETER Target
The target computer, specified as a single hostname or IP address. The tool also supports multiple targets as computer objects through the pipeline.

.PARAMETER TCP
Enables TCP as querying protocol.

.PARAMETER TCPPort
The TCP port to query.

.PARAMETER ICMP
Enables ICMP (echo) as querying protocol.

.PARAMETER Timeout
The time, in milliseconds, that the command wait for a response. The default value is 1000.

.PARAMETER MultiThread
Enables multi-threading, where each target is processed by its own thread.

.PARAMETER ThreadLimit
The maximum number of threads that will be assigned when multi-threading. The default value is 20.

.PARAMETER ShowProgress
Enables a progress bar.

.PARAMETER SuppressMessages
Prevents event messages from being printed to the screen.

.PARAMETER DontFeedObject
Prevents results from being saved to the Computer object. By default, results are saved to the "State" property of the object. This is done according to the data update policy defined for this command (see notes).

.EXAMPLE
NME-NET-TestState -Target 192.168.56.22 -ICMP

.EXAMPLE
<computer objects>| NME-NET-TestState -TCP -Port 443 -MultiThread -ShowProgress |Format-Table -AutoSize

.EXAMPLE
<computer objects>|?{$_.IPAddress -like "192.168.5*"} |NME-NET-TestState -TCP -Port 135

.NOTES

Data update policy
------------------
Replaces all data on existing object.

Module dependencies
-------------------
- Environment: HelperFunctions, CreateObjects

#>

Function Test-NETState
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]
        [Alias('IPAddress')]
        [string]$Target,

        [Parameter(Mandatory,ParameterSetName = 'TCP')]
        [switch]$TCP,

        [Parameter(Mandatory,ParameterSetName = 'TCP')]
        [ValidateRange(0,65535)]
        [int]$TCPPort,
        
        [Parameter(Mandatory,ParameterSetName = 'ICMP')]
        [switch]$ICMP,
        
        [Parameter()]
        [int]$TimeOut = 1000,

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
        $CmdName = 'Test-NETState'
        $CmdAlias = 'NME-NET-TestState'
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
            $ScriptBlock = $PSCmdlet.MyInvocation.MyCommand.Definition
            $ImportModules = @('HelperFunctions','CreateObjects')
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
            $Command = [scriptblock]::Create("[powershell]::Create().AddScript(`$ScriptBlock).AddParameter(`"Target`",`$Target)" + $paramString)

            #Creating array for storing threads, handles and job results
            $jobsArray = New-Object System.Collections.ArrayList

            $message = 'Starting multi-thread processing'
            LogEvent -Command $CmdName -Severity Info -Event $message -ToFile -ToConsole

            Function GetResults #Defining function for monitoring jobs and fetching results            {			    param                (                    [switch]$WaitForCompletion                )                			    do                {				    $HasData = $false                    foreach($job in $JobsArray)                    {					    if ($job.Handle.isCompleted)                        {                            $job.Result = $job.Thread.EndInvoke($job.Handle)						    $job.Thread.dispose()						    $job.Handle = $null						    $job.Thread = $null					    }                        elseif ($job.Handle -ne $null)                        {						    $HasData = $true					    }				    }				    if ($HasData -and $WaitForCompletion)                    {                        Start-Sleep -Milliseconds 100                    }			    } while ($HasData -and $WaitForCompletion)		    }
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
                    Write-Verbose "Attempting to resolve $target to an IP address"
                    $Target = ([System.Net.Dns]::GetHostAddresses($Target)).IPAddressToString
                
                    Write-Verbose "IP address successfully obtained ($Target)"
                }
                catch
                {
                    $message = "Unable to resolve target `'$Target`'";
                    LogEvent -command $CmdName -severity Err -Event $message -ToFile -ToConsole

                    return
                }
            }

            $StateObj = New-Object psobject -Property @{
                State         = $null
                QueryProtocol = $null
                QueryPort     = $null
                QueryTime     = $null
            } |Select-Object State,QueryProtocol,QueryPort,QueryTime #Creates results object

            #$stateObj = @{
            #    State    = $null
            #    Protocol = $null
            #    Port     = $null
            #}

            $message = "Determining state"

            if($SuppressMessages)
            {
                LogEvent -source $Target -command $CmdName -severity Info -Event $message -ToFile
            }
            else
            {
                LogEvent -source $Target -command $CmdName -severity Info -Event $message -ToFile -ToConsole
            }

            if($TCP)
            {
                $socket = New-Object System.Net.Sockets.TcpClient

                Write-Verbose 'Sending TCP request'

                $connect = $socket.BeginConnect($Target,$TCPPort,$null,$null)
                $data = $connect.AsyncWaitHandle.WaitOne($Timeout,$false)
                $socket.Close()

                if($data)
                {
                    $stateObj.State = 'Up'
                }
                else
                {
                    $stateObj.State = 'Down'
                }

                $stateObj.QueryProtocol = 'TCP'
                $stateObj.QueryPort     = $TCPPort
                $stateObj.QueryTime     = (Get-Date).ToString()
            }

            if($ICMP)
            {
                $ping = New-Object System.Net.NetworkInformation.Ping
            
                try
                {
                    Write-Verbose 'Sending ICMP request'

                    $data = $ping.Send($Target,$TimeOut)

                    switch ($data.Status)
                    {
                        'TimedOut' {$stateObj.State = 'Down'}
                        'Success'  {$stateObj.State = 'Up'}
                    }

                    $stateObj.QueryProtocol = 'ICMP'
                    $stateObj.QueryPort     = 'N/A'
                    $stateObj.QueryTime     = (Get-Date).ToString()
                }
                catch
                {
                    $message = $_.Exception.Innerexception.Innerexception.Message

                    if($SuppressMessages)
                    {
                        LogEvent -source $Target -command $CmdName -severity Err -Event $message -ToFile

                    }
                    else
                    {
                        LogEvent -source $Target -command $CmdName -severity Err -Event $message -ToFile -ToConsole
                    }

                    Return
                }
            }

            $message = "State check completed ($($stateObj.State))"

            if($SuppressMessages)
            {
                LogEvent -source $Target -command $CmdName -severity Info -Event $message -ToFile
            }
            else
            {
                LogEvent -source $Target -command $CmdName -severity Info -Event $message -ToFile -ToConsole
            }

            if(! $DontFeedObject)
            {
                $CompObj = Get-ComputerObject -IP $Target

                $compObj.State = $StateObj
            }

            #Bulding results object for console output
            $newObj = $stateObj|Select-Object *
            $Results += $newObj |Add-Member IPAddress $Target -PassThru


            if($ShowProgress)
            {
                $Counter.Done++
                Write-Progress -Activity 'Testing computer state' -Status "$($Counter.Done) of $($Counter.Total) targets completed" -PercentComplete (($($Counter.Done)/$($Counter.Total))*100)
            }
        }
    }

    END
    {
        if($MultiThread)
        {
            GetResults -WaitForCompletion

            $message = 'Multi-thread processing completed'
            LogEvent -command $CmdName -severity Info -Event $message -ToFile -ToConsole

            Write-Host ""
            Write-Output $jobsArray.Result
        }
        else
        {
            Write-Output $Results |Select-object IPAddress,State,QueryProtocol,QueryPort,QueryTime
        }
    }
}