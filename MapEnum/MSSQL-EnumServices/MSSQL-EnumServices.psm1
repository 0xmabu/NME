<#
 
.SYNOPSIS
Enumerates MSSQL databases on a Windows computer.
 
.DESCRIPTION
This tool enumerates MSSQL database services on a remote Windows computer. The enumeration can be conducted using TCP- and/or UDP-based MSSQL queries. The queries are built using the System.Net.Sockets.TcpClient, System.Net.Sockets.UdpClient and System.Data.SqlClient.SQLConnection dot net classes.

The tool outputs a MSSQL object.

.PARAMETER Target
The target computer, specified as a single hostname or IP address. The tool also supports multiple targets as computer objects through the pipeline.

.PARAMETER TCP
Enables TCP as querying protocol.

.PARAMETER TCPPort
The TCP port to query. The default value is 1433.

.PARAMETER UDP
Enables UDP as querying protocol.

.PARAMETER TCPPort
The TCP port to query. The default value is 1434.

.PARAMETER Timeout
The time, in seconds, that the command wait for a response. The default value is 3.

.PARAMETER MultiThread
Enables multi-threading, where each target is processed by its own thread.

.PARAMETER ThreadLimit
The maximum number of threads that will be assigned when multi-threading. The default value is 20.

.PARAMETER ShowProgress
Enables a progress bar.

.PARAMETER SuppressMessages
Prevents event messages from being printed to the screen.

.EXAMPLE
<computer objects>|NME-MSSQL-EnumServices -TCP -UDP

.EXAMPLE
NME-MSSQL-EnumServices -Target 192.168.56.22 -UDP |Format-table -Autosize

.EXAMPLE
<computer objects>|?{$_.IPAddress -like "192.168.5*"}|NME-MSSQL-EnumServices -MultiThread -ShowProgress

.NOTES

Data update policy
------------------
Replaces all data for existing object.

Module dependencies
-------------------
- Environment: HelperFunctions, CreateObjects

Other
-----
- The function for the UDP query is based on code by Wes Brown (see link)

.LINK
- http://sqlserverio.com/2013/02/27/finding-sql-server-installs-using-powershell/

#>

Function Get-MSSQLServers
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]
        [Alias('IPAddress')]
        [string]$Target,

        [Parameter()]
        [switch]$TCP,

        [Parameter()]
        [ValidateRange(0,65535)]
        [int]$TCPPort = 1433,
        
        [Parameter()]
        [switch]$UDP,

        [Parameter()]
        [ValidateRange(0,65535)]
        [int]$UDPPort = 1434,

        [Parameter()]
        [int]$Timeout = 3,

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
        $CmdName = 'Get-MSSQLServers'
        $CmdAlias = 'NME-MSSQL-EnumServices'
        $Results = @()

        #Param validation
        if (!$TCP -and !$UDP)
        {
            $message = 'No enumeration method selected'
            LogEvent -Source $CmdName -Severity Err -Event $message -ToConsole 

            break
        }

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
                    $event = "Unable to resolve target `'$Target`'"
                    LogEvent -Command $CmdName -Severity Err -Event $message -ToFile -ToConsole

                    return
                }
            }

            $message = 'Enumerating MSSQL servers'

            if($SuppressMessages)
            {
                LogEvent -Source $Target -Command $CmdName -Severity Info -Event $message -ToFile
            }
            else
            {
                LogEvent -Source $Target -Command $CmdName -Severity Info -Event $message -ToFile -ToConsole
            }

            if($TCP)
            {
                $socket = New-Object System.Net.Sockets.TcpClient

                $connect = $socket.BeginConnect($Target,$TCPPort,$null,$null)
                $data = $connect.AsyncWaitHandle.WaitOne($Timeout*1000,$false)
                
                $socket.Close()
                
                if($data)
                {
                    $DbConnect = New-Object System.Data.SqlClient.SQLConnection
                    $ConString = "Server=tcp:$Target, $TCPPort;Connect Timeout=$Timeout;Pooling=false"
                    $DbConnect.ConnectionString=$ConString

                    try
                    {
                        Write-Verbose 'Sending TCP probe'
                        $DbConnect.Open()
                    }
                    catch
                    {
                        if ($_.Exception.InnerException.Number -eq 18452 -or $_.Exception.InnerException.Number -eq 18456)
                        {
                            $MssqlObj = Get-MSSQLObject -HostIP $Target -TCPPort $TCPPort

                            $Results += $MssqlObj
                        }
                        else
                        {
                            Write-Verbose $_.Exception.InnerException.Number
                        }
                    }
                    finally
                    {
                        $DbConnect.Close()
                    }
                }
            }

            if($UDP)
            {
                $UdpClient = New-Object system.Net.Sockets.Udpclient
                $UdpClient.client.ReceiveTimeout = $Timeout*1000

                Try
                {
                    Write-Verbose 'Sending UDP probe'
                    
                    $UdpClient.Connect($Target,$UDPPort)
                    $ToAscii = New-Object system.text.asciiencoding
                    $UdpPacket = 0x02,0x00,0x00
                
                    $UdpEndpoint = New-Object system.net.ipendpoint([system.net.ipaddress]::Any,0)
                    $UdpClient.Client.Blocking = $True
                    
                    [void]$UdpClient.Send($UdpPacket,$UdpPacket.length)

                    $BytesRecived = $UdpClient.Receive([ref]$UdpEndpoint)
                    [string]$UdpResponse = $ToAscii.GetString($BytesRecived)

                    If ($UdpResponse)
                    {
                        $StrArray = @()

                        $UdpResponse = $UdpResponse.Substring(3,$UdpResponse.Length-3).Replace(';;','~')
                        $UdpResponse.Split("~") |% { $StrArray += $_ }
                        $StrArray = ($StrArray|?{$_}) #Remove empty lines

                        foreach($str in $StrArray)
                        {
                            $str = $str.Split(';')
                            $db = @{}

                            for ($i = 0; $i -lt $str.Count; $i = $i+2)
                            { 
                                $db.Add($str[$i],$str[$i+1])
                            }

                            if($db.tcp)
                            {
                                $MssqlObj = Get-MSSQLObject -HostIP $Target -TCPPort $db.tcp
                            }
                            else
                            {
                                $MssqlObj = Get-MSSQLObject -HostIP $Target -NamedPipe $db.np
                            }

                            $MssqlObj.TCPPort      = $db.tcp
                            $MssqlObj.NamedPipe    = $db.np
                            $MssqlObj.ServerName   = $db.ServerName
                            $MssqlObj.InstanceName = $db.InstanceName
                            $MssqlObj.IsClustered  = $db.IsClustered
                            $MssqlObj.Version      = $db.Version

                            if( (!$Results) -or ($mssqlObj.TCPPort -and !$Results.TCPPort.Contains($mssqlObj.TCPPort)) -or ($mssqlObj.NamedPipe -and !$Results.NamedPipe.Contains($mssqlObj.NamedPipe)))
                            {
                                $Results += $MssqlObj
                            }
                        }
                    }
                }
                catch
                {
                     Write-Verbose $_.Exception.InnerException.NativeErrorCode
                }
                finally
                {
                    $UdpClient.Close()
                }
            }

            $message = 'Enumeration completed'

            if($SuppressMessages)
            {
                LogEvent -source $Target -command $CmdName -severity Info -Event $message -ToFile
            }
            else
            {
                LogEvent -source $Target -command $CmdName -severity Info -Event $message -ToFile -ToConsole
            }

            if($Results) #Verifies or creates a host computer object if services are found
            {
                Get-ComputerObject -IP $target |Out-Null
            }

            if($ShowProgress)
            {
                $Counter.Done++
                Write-Progress -Activity 'Enumerating MSSQL servers' -Status "$($Counter.Done) of $($Counter.Total) targets completed" -PercentComplete (($($Counter.Done)/$($Counter.Total))*100)
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