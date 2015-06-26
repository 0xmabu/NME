<#
 
.SYNOPSIS
Attempts to logon to a MSSQL server using the supplied SQL credentials.
 
.DESCRIPTION
This tool attempts to login to a remote MSSQL server using the SQL login credentials provided as arguments. The login attemts are built using the System.Data.SqlClient.SQLConnection dot net class. The tool also allows a SQL query to be run in the event of a successful login.

The tool outputs a Credential object for each valid credential identified and, if enabled, the results from the post-login SQL query.

.PARAMETER HostIP
The IP address of the computer hosting the MSSQL database. The tool also supports multiple IP addresses by means of MSSQL database objects coming through the pipeline.

.PARAMETER TCPPort
The TCP port on which the database service is listening. The tool also supports multiple TCP ports by means of MSSQL database objects coming through the pipeline.

.PARAMETER NamedPipe
The UNC of the named pipe on which the database service is listening. The tool also supports multiple named pipe names by means of MSSQL database objects coming through the pipeline.

.PARAMETER Username
One or multiple usernames to be used for login attempts. This will prevent inclusion of logins stored in the "SQLLogins" property of the database object.

.PARAMETER Password
One or multiple passwords to be tested for each username.

.PARAMETER UserList
The absolute path to a file containing usernames (one username per line)

.PARAMETER PassList
The absolute path to a file containing passwords (one password per line)

.PARAMETER UserSpecial
Adds "special" usernames including:
- InstanceName:  The name of the MSSQL service instance as username
- PipeName: The name of the MSSQL service pipe as username
- DatabaseNames: The name(s) of any databases as usernames

.PARAMETER PassSpecial
Adds "special" passwords including:
- SameAsUser: Lower-case username as password
- Blank: Empty password

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
<database objects>| NME-MSSQL-TestCredentials -Username sa -Password foobar -MultiThread

.EXAMPLE
<database objects>| NME-MSSQL-TestCredentials -Username sa,appuser -Password secret,pass123 -PassSpecial Blank,SameAsUser -PostLoginQuery "select @@version" -OutVariable results

.EXAMPLE
NME-MSSQL-TestCredentials -HostIP 192.168.56.22 -TCPPort 1433 -UserList c:\users.txt -PassList c:\pass.txt' -SuppressMessages

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

Function Test-MSSQLCredentials
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]
        [string]$HostIP,

        [Parameter(ValueFromPipelineByPropertyName)]
        #[Parameter(Mandatory,ParameterSetName = 'TCP')]
        [string]$TCPPort,

        [Parameter(ValueFromPipelineByPropertyName)]
        #[Parameter(Mandatory,ParameterSetName = 'Pipe')]
        [string]$NamedPipe,

        [Parameter()]
        [string[]]$Username,

        [Parameter()]
        [string[]]$Password,

        [Parameter()]
        [string]$UserList,

        [Parameter()]
        [string]$PassList,

        [Parameter()]
        [ValidateSet('InstanceName','PipeName','DatabaseNames')]
        [string[]]$UserSpecial,

        [Parameter()]
        [ValidateSet('SameAsUser','Blank')]
        [string[]]$PassSpecial,

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
        $CmdName = 'Test-MSSQLCredentials'
        $CmdAlias = 'NME-MSSQL-TestCredentials'
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

        if($MultiThread) #Preparing multi-thread environment
        {
            #Command-specific input to multithreading
            $ScriptBlock = $MyInvocation.MyCommand.Definition
            $ImportModules = @('HelperFunctions','CreateObjects','PSReflect')
            $ImportVariables = @('NMEObjects','NMEVars','Counter')

            foreach ($key in $MyInvocation.BoundParameters.Keys) #Creates a string of parameters that is passed to the powershell::create() command
            {
                if(($key -ne 'MultiThread') -and ($key -ne 'ThreadLimit') -and ($key -ne 'HostIP') -and ($key -ne 'TCPPort')-and ($key -ne 'NamedPipe'))
                {
                    if(($($MyInvocation.BoundParameters.Item($key)) -eq $true) -or ($($MyInvocation.BoundParameters.Item($key)) -eq $false)) #Switch params
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

            #Building powershell commands
            $CommandTCP = [scriptblock]::Create("[powershell]::Create().AddScript(`$ScriptBlock).AddParameter(`"HostIP`",`$HostIP).AddParameter(`"TCPPort`",`$TCPPort)" + $ParamString)
            $CommandPipe = [scriptblock]::Create("[powershell]::Create().AddScript(`$ScriptBlock).AddParameter(`"HostIP`",`$HostIP).AddParameter(`"NamedPipe`",`$NamedPipe)" + $ParamString)

            #Creating array for storing threads, handles and job results
            $JobsArray = New-Object System.Collections.ArrayList

            $message = 'Starting multi-thread processing'
            LogEvent -Command $CmdName -Severity Info -Event $message -ToFile -ToConsole

            Function GetResults #Defining function for monitoring jobs and fetching results            {			    param                (                    [switch]$WaitForCompletion                )                			    do                {				    $HasData = $false                    foreach($job in $jobsArray)                    {					    if ($job.Handle.isCompleted)                        {                            $job.Result = $job.Thread.EndInvoke($job.Handle)						    $job.Thread.dispose()						    $job.Handle = $null						    $job.Thread = $null					    }                        elseif ($job.Handle -ne $null)                        {						    $HasData = $true					    }				    }				    if ($HasData -and $WaitForCompletion)                    {                        Start-Sleep -Milliseconds 100                    }			    } while ($HasData -and $WaitForCompletion)		    }
        }
        else #Preparation for normal execution
        {
            #Building initial password array
            $PwdArray = @()

            if($PassList)
            {
                if( !(Test-Path $PassList))
                {
                    $message = 'Cannot find a password list at the provided path'
                    LogEvent -Source $CmdName -Severity Err -Event $message -ToConsole 
                
                    break
                }
                else
                {
                    $PwdArray += (Get-Content $PassList)
                }
            }
        
            if($Password)
            {
                foreach($p in $Password)
                {
                    $PwdArray += $p
                }
            }

            switch ($PassSpecial)
            {
                { ! $_ }                 { break }
                { $_.Contains('Blank') } { $PwdArray += ""; }
            }

            #Building initial username array
            $UserArray = @()

            if($UserList)
            {
                if( !(Test-Path $UserList))
                {
                    $message = 'Cannot find a username list at the provided path'
                    LogEvent -Source $CmdName -Severity Err -Event $message -ToConsole 
                
                    break
                }
                else
                {
                    $UserArray += (Get-Content $UserList)
                }
            }

            if($Username)
            {
                foreach($u in $Username)
                {
                    $UserArray += $u
                }
            }
        }
    }

    PROCESS
    {
        if($MultiThread) #Invoking new thread for each target in pipe and storing threads/handles/results in jobsArray
        {
            if($TCPPort)
            {
                $Command = $CommandTCP
            }
            else
            {
                $Command = $CommandPipe
            }

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
                $ConnectAddress = "np:"+$NamedPipe
            }

            if(! $MSSQLObject)
            {
                $message = "Unable to find MSSQL object for '$($HostIP):$($SvcId)'"
                LogEvent -Command $CmdName -Severity Err -Event $message -ToFile -ToConsole

                return
            }

            #Adding iteration-specific usernames
            switch($UserSpecial)
            {
                { ! $_ }                         { break }
                { $_.Contains('InstanceName') }  { $UserArray += $MSSQLObject.InstanceName; break }
                { $_.Contains('PipeName') }      { $UserArray += $MSSQLObject.NamedPipe; break }
                { $_.Contains('DatabaseNames') } { $UserArray += $MSSQLObject.Databases }
            }

            $UserArray = $UserArray |?{$_} |Select -Unique #Removing empty lines and duplicates

            #If no username data has been provided with params, add any logins stored in the object
            if(! $UserArray)
            {
                $UserArray = $MSSQLObject.SQLLogins
            }

            if($UserArray.count -ne 0)
            {
                $message = 'Attempting SQL login(s)'

                if($SuppressMessages)
                {
                    LogEvent -Source "$($HostIP):$($SvcId)" -Command $CmdName -Severity Info -Event $message -ToFile
                }
                else
                {
                    LogEvent -Source "$($HostIP):$($SvcId)" -Command $CmdName -Severity Info -Event $message -ToFile -ToConsole
                }

                foreach($User in $UserArray) #Iterate through each user
                {
                    #Adding iteration-specific passwords
                    $IterationPwd = @()
                
                    switch ($PassSpecial)
                    {
                        { ! $_ }                      { break }
                        { $_.Contains('SameAsUser') } { $IterationPwd += $User.ToLower() }
                    }

                    $PwdArray += $IterationPwd

                    if($PwdArray.count -ne 0)
                    {
                        foreach($Pass in $PwdArray) #Iterate through each password
                        {
                            $DbConnect = New-Object System.Data.SqlClient.SQLConnection
                            $ConnectString = "Server=$ConnectAddress;User Id=$User; Password=$Pass;Connect Timeout=$Timeout;Pooling=false"
                            $DbConnect.ConnectionString = $ConnectString

                            try
                            {
                                Write-Verbose "Login attempt $user/$pass"
                                $DbConnect.Open()

                                $message = 'Logon successful'

                                if($SuppressMessages)
                                {
                                    LogEvent -Source "$($HostIP):$($SvcId)" -Command $CmdName -Severity Succ -Event $message -ToFile
                                }
                                else
                                {
                                    LogEvent -Source "$($HostIP):$($SvcId)" -Command $CmdName -Severity Succ -Event $message -ToFile -ToConsole
                                }
                                
                                $CredObj = Get-CredentialObject -Username $User -AuthService "$($HostIP):$($SvcId)" -CredType MSSQL
                                $CredObj.Password = $Pass

                                if(! $MSSQLObject.Permissions.AllowLogin.Contains($User))
                                {
                                    $MSSQLObject.Permissions.AllowLogin += $User
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
                    
                                    $da=New-Object system.Data.SqlClient.SqlDataAdapter($command)
                                    [void]$da.fill($ds)

                                    $Results += $CredObj |select * |Add-Member QueryOutput $ds.Tables.Rows -PassThru
                                }
                                else
                                {
                                    $Results += $CredObj
                                }

                                break #Breaks foreach pass loop as password has been found
                            }
                            catch
                            {
                                if ($_.Exception.InnerException.Number -eq 18456)
                                {
                                    $message = $_.Exception.InnerException.Message
                                }
                                else
                                {
                                    $message = $_.Exception.InnerException.Message
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
                                $DbConnect.Close()
                            }
                        }

                        foreach($p in $IterationPwd) #Removes user-specific password from list
                        {
                            $PwdArray = @($PwdArray|?{$_ -ne $p})
                        }
                    }
                    else
                    {
                        Write-Verbose 'No passwords to process'
                        Return
                    }
                }
            }
            else
            {
                Write-Verbose 'No usernames to process'
                Return
            }

            if($ShowProgress)
            {
                $Counter.Done++
                Write-Progress -Activity 'Testing MSSQL logins' -Status "$($Counter.Done) of $($Counter.Total) targets completed" -PercentComplete (($($Counter.Done)/$($Counter.Total))*100)
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