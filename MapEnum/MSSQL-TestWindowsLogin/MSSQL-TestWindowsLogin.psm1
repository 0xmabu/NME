<#
 
.SYNOPSIS
Attempts to login to a MSSQL server using the Windows credentials.
 
.DESCRIPTION
This tool attempts to login to a remote MSSQL server using the Windows credentials of the running powershell session. The login attemts are build using the System.Data.SqlClient.SQLConnection dot net class. The tool also allows a SQL query to be run in the event of a successful login. 

The tool outputs a Credential object for each valid credential identified and, if enabled, the results from the post-login SQL query.

.PARAMETER HostIP
The IP address of the computer hosting the MSSQL database. The tool also supports multiple IP addresses by means of MSSQL database objects coming through the pipeline.

.PARAMETER TCPPort
The TCP port on which the database service is listening. The tool also supports multiple TCP ports by means of MSSQL database objects coming through the pipeline.

.PARAMETER NamedPipe
The name of the named pipe on which the database service is listening. The tool also supports multiple named pipe names by means of MSSQL database objects coming through the pipeline.

.PARAMETER PostLoginQuery
A SQL statement that is executed in the event of successful login.

.PARAMETER MultiThread
Enables multi-threading, where each target is processed by its own thread.

.PARAMETER ThreadLimit
The maximum number of threads that will be assigned when multi-threading. The default value is 20.

.PARAMETER ShowProgress
Enables a progress bar.

.PARAMETER SuppressMessages
Prevents event messages from being printed to the screen.

.EXAMPLE
<database objects>| NME-MSSQL-TestWindowsLogin

.EXAMPLE
<database objects>| NME-MSSQL-TestWindowsLogin -MultiThread -SuppressMessages

.EXAMPLE
NME-MSSQL-TestWindowsLogin -DatabaseObject $Services.MSSQL.'192.168.56.21:1433' -PostLoginQuery 'Select @@version' -OutVariable results

.NOTES

Data update policy
------------------
- Updates the "AllowLogin" property of the MSSQL database object.
- Creates new Credential objects, updates the "Password" property on existing.

Module dependencies
-------------------
- External: PSReflect
- Environment: HelperFunctions, CreateObjects

.LINK

#>

Function Test-MSSQLWindowsLogin
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]
        [string]$HostIP,

        [Parameter(ValueFromPipelineByPropertyName)]
        [Parameter(ParameterSetName = 'TCP')]
        [string]$TCPPort,

        [Parameter(ValueFromPipelineByPropertyName)]
        [Parameter(ParameterSetName = 'Pipe')]
        [string]$NamedPipe,

        [Parameter()]
        [string]$PostLoginQuery,

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
        $CmdName = 'Test-MSSQLWindowsLogin'
        $CmdAlias = 'NME-MSSQL-TestWindowsLogin'
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
            if($HostIP)
            {
                $message = 'Multithreading not supported for a single target'
                LogEvent -Command $CmdName -Severity Err -Event $message -ToConsole

                break
            }

            #Command-specific input to multithreading
            $ScriptBlock = $MyInvocation.MyCommand.Definition
            $ImportModules = @('HelperFunctions','CreateObjects','PSReflect')
            $ImportVariables = @('NMEObjects','NMEVars','Counter')

            foreach ($key in $MyInvocation.BoundParameters.Keys) #Creates a string of parameters that is passed to the powershell::create() command
            {
                if(($key -ne 'MultiThread') -and ($key -ne 'ThreadLimit') -and ($key -ne 'DatabaseObject'))
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
            $Command = [scriptblock]::Create("[powershell]::Create().AddScript(`$ScriptBlock).AddParameter(`"DatabaseObject`",`$_)" + $ParamString)

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
            if($TCPPort)
            {
                $MSSQLObject = Get-MSSQLObject -HostIP $HostIP -TCPPort $TCPPort -OnlyFromArray
                $SvcId = $TCPPort
                $ConnectAddress = "tcp:"+$HostIP+","+$SvcId
            }
            else
            {
                $MSSQLObject = Get-MSSQLObject -HostIP $HostIP -NamedPipe $NamedPipe -OnlyFromArray
                $SvcId = $NamedPipe
                $ConnectAddress = "np:"+$HostIP+","+$NamedPipe
            }

            if(! $MSSQLObject)
            {
                $message = "Unable to find MSSQL object for '$($HostIP):$($SvcId)'"
                LogEvent -Command $CmdName -Severity Err -Event $message -ToFile -ToConsole

                return
            }

            $DbConnect = New-Object System.Data.SqlClient.SQLConnection
            $ConnectString = "Server=$ConnectAddress;Integrated Security=True;Connect Timeout=$Timeout;Pooling=false"
            $DbConnect.ConnectionString = $ConnectString
                
            $message = 'Attempting Windows login'

            if($SuppressMessages)
            {
                LogEvent -Source "$($HostIP):$($SvcId)" -Command $CmdName -Severity Info -Event $message -ToFile
            }
            else
            {
                LogEvent -Source "$($HostIP):$($SvcId)" -Command $CmdName -Severity Info -Event $message -ToFile -ToConsole
            }

            try
            {
                if($NMEVars.CurrentUser -eq 'ANONYMOUS LOGON')
                {
                    [void]$Advapi32::ImpersonateAnonymousToken($Kernel32::GetCurrentThread())

                    $DbConnect.Open()

                    [void]$Advapi32::RevertToSelf()
                }
                else
                {
                    $DbConnect.Open()
                }

                $message = 'Login successful'
                    
                if($SuppressMessages)
                {
                    LogEvent -Source "$($HostIP):$($SvcId)" -Command $CmdName -Severity Succ -Event $message -ToFile
                }
                else
                {
                    LogEvent -Source "$($HostIP):$($SvcId)" -Command $CmdName -Severity Succ -Event $message -ToFile -ToConsole
                }

                if($NMEVars.CurrentUser.Contains('\'))
                {
                    $CredUser = $NMEVars.CurrentUser.Split('\')[1]
                    $AuthSvc = $NMEVars.CurrentUser.Split('\')[0]
                    $CredType = 'WinDomain'
                }
                else
                {
                    $CredUser = $NMEVars.CurrentUser
                    $AuthSvc = $HostIP
                    $CredType = 'WinSAM'
                }

                $CredObj = Get-CredentialObject -Username $CredUser -CredType $CredType -AuthService $AuthSvc
                $CredObj.Password = $NMEVars.CurrentCred.GetNetworkCredential().Password

                if(! $MSSQLObject.Permissions.AllowLogin.Contains($NMEVars.CurrentUser))
                {
                    $MSSQLObject.Permissions.AllowLogin += $NMEVars.CurrentUser
                }

                if($PostLoginQuery)
                {
                    $Command=new-object system.Data.SqlClient.SqlCommand($PostLoginQuery,$DbConnect)
                    $Command.CommandTimeout = 5
                    $ds=New-Object system.Data.DataSet

                    $message = 'Executing post-login query'

                    if($SuppressMessages)
                    {
                        LogEvent -Source "$($HostIP):$($SvcId)" -Command $CmdName -Severity Info -Event $message -ToFile
                    }
                    else
                    {
                        LogEvent -Source "$($HostIP):$($SvcId)" -Command $CmdName -Severity Info -Event $message -ToFile -ToConsole
                    }
                    
                    $da=New-Object system.Data.SqlClient.SqlDataAdapter($Command)
                    [void]$da.fill($ds)

                    $Results += $CredObj |select * |Add-Member QueryOutput $ds.Tables.Rows -PassThru
                }
                else
                {
                    $Results += $CredObj
                }
            }
            catch
            {
                if($NMEVars.CurrentUser -eq 'ANONYMOUS LOGON')
                {
                    [void]$Advapi32::RevertToSelf()
                }

                if ($_.Exception.InnerException.Number -eq 18452)
                {
                    $message = $_.Exception.InnerException.Message -replace "''","'$($NMEVars.CurrentUser)'"
                }
                elseif($_.Exception.InnerException.Number -eq 18456)
                {
                    $message = $_.Exception.InnerException.Message

                    if($MSSQLObject.Permissions.Login.Contains($NMEVars.CurrentUser))
                    {
                        $MSSQLObject.Permissions.Login = $MSSQLObject.Permissions.Login|?{$_ -ne $NMEVars.CurrentUser}
                    }
                }
                else
                {
                    $message = 'Unhandled error: ' + $_.Exception
                }

                if($SuppressMessages)
                {
                    LogEvent -Source "$($HostIP):$($SvcId)" -Command $CmdName -Severity Err -Event $message -ToFile
                }
                else
                {
                    LogEvent -Source "$($HostIP):$($SvcId)" -Command $CmdName -Severity Err -Event $message -ToFile -ToConsole
                }
            }
            finally
            {
                if($DbConnect)
                {
                    $DbConnect.Close()
                }
            }
        }

        if($ShowProgress)
        {
            $Counter.Done++
            Write-Progress -Activity 'Testing MSSQL logins' -Status "$($Counter.Done) of $($Counter.Total) targets completed" -PercentComplete (($($Counter.Done)/$($Counter.Total))*100)
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