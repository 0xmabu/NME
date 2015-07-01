<#
 
.SYNOPSIS
Enumerates HTTP servers on a target computer.
 
.DESCRIPTION
This tool enumerates HTTP servers on a remote computer. The server is identified by parsing the response of a 'HEAD' HTTP request. The request is built using the System.Net.WebRequest dot net class.

The tool outputs a HTTP server object.

.PARAMETER Target
The target computer, specified as a single hostname or IP address. The tool also supports multiple targets as computer objects through the pipeline.

.PARAMETER TCPPort
The TCP port to query. If not specified, the default value is 80. If not specified and SSL is enabled, the default value is 443.

.PARAMETER SSL
Enables SSL for the web request.

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
<computer objects>|NME-HTTP-EnumServices

.EXAMPLE
NME-HTTP-EnumServices -Target 192.168.56.22 -TCPPort 8080 |Format-table -Autosize

.EXAMPLE
<computer objects>|?{$_.IPAddress -like "192.168.5*"}|NME-HTTP-EnumServices -MultiThread -SSL -ShowProgress

.NOTES

Data update policy
------------------
Replaces all data for existing object.

Module dependencies
-------------------
- Environment: HelperFunctions, CreateObjects

Other
-----

#>

Function Get-HTTPServers
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]
        [Alias('IPAddress')]
        [string]$Target,

        [Parameter()]
        [ValidateRange(0,65535)]
        [int]$TCPPort,

        [Parameter()]
        [switch]$SSL,

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
        $CmdName = 'Get-HTTPServers'
        $CmdAlias = 'NME-HTTP-EnumServices'
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
        
        if($SSL)
        {
            add-type @"
            using System.Net;
            using System.Security.Cryptography.X509Certificates;
            public class TrustAllCertsPolicy : ICertificatePolicy {
                public bool CheckValidationResult(
                    ServicePoint srvPoint, X509Certificate certificate,
                    WebRequest request, int certificateProblem) {
                    return true;
                }
            }
"@

            $DefaultCertPolicy = [Net.ServicePointManager]::CertificatePolicy
            [Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
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

            if($SSL)
            {
                if(! $TCPPort)
                {
                    $TCPPort = 443
                }

                $url = "https://" + "$Target`:$TCPPort"
            }
            else
            {
                if(! $TCPPort)
                {
                    $TCPPort = 80
                }

                $url = "http://" + "$Target`:$TCPPort"
            }
            
            $message = 'Enumerating HTTP server'

            if($SuppressMessages)
            {
                LogEvent -Source "$Target`:$TCPPort" -Command $CmdName -Severity Info -Event $message -ToFile
            }
            else
            {
                LogEvent -Source "$Target`:$TCPPort" -Command $CmdName -Severity Info -Event $message -ToFile -ToConsole
            }

            try
            {
                $request = [System.Net.WebRequest]::Create($url)
                $request.Method = 'HEAD'
                $request.Timeout = $Timeout*1000
                $response = $request.GetResponse()
                
                $HttpObj = Get-HTTPServerObject -HostIP $Target -TCPPort $TCPPort
                $HttpObj.Product = $response.Server
            }
            catch
            {
                if($_.Exception.InnerException.Response)
                {
                    $HttpObj = Get-HTTPServerObject -HostIP $Target -TCPPort $TCPPort
                    $HttpObj.Product = $_.Exception.InnerException.Response.Server

                    Write-Verbose "HTTP server found ($($_.Exception.InnerException.Message))"
                }
                else
                {
                    Write-Verbose "No HTTP server found ($($_.Exception.InnerException.Message))"
                }
            }

            $message = 'Enumeration completed'

            if($SuppressMessages)
            {
                LogEvent -source "$Target`:$TCPPort" -command $CmdName -severity Info -Event $message -ToFile
            }
            else
            {
                LogEvent -source "$Target`:$TCPPort" -command $CmdName -severity Info -Event $message -ToFile -ToConsole
            }

            if($HttpObj)
            {
                if($SSL)
                {
                    $HttpObj.SecureChannel = $true
                }
                else
                {
                    $HttpObj.SecureChannel = $false
                }

                $Results += $HttpObj
                $HttpObj = $null

                Get-ComputerObject -IP $target |Out-Null #Verifies or creates a hosting computer object for HTTP server
            }

            if($ShowProgress)
            {
                $Counter.Done++
                Write-Progress -Activity 'Enumerating HTTP servers' -Status "$($Counter.Done) of $($Counter.Total) targets completed" -PercentComplete (($($Counter.Done)/$($Counter.Total))*100)
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

            [Net.ServicePointManager]::CertificatePolicy = $DefaultCertPolicy
        }
        else
        {
            Write-Output $Results

            if($MyInvocation.CommandOrigin -eq 'Runspace') #'CommandOrigin -eq Runspace' will prevent execution of block when in a threaded context
            {
                [Net.ServicePointManager]::CertificatePolicy = $DefaultCertPolicy
            }
        }
    }
}