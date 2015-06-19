<#
 
.SYNOPSIS
Tests shared folders on the remote Windows host.
 
.DESCRIPTION
This tool can be used to test read and write access to shared folders and conduct file- and string search operations to find specific content. The tool uses built-in cmdlets, including Get-PSDrive, Get-ChildItem and Select-String, for connecting to the remote share and process its information. All test activities is conducted using the Windows credentials of the running powershell session.

The tool saves the results of the search operation in the log files matched_files.log and matched_strings.log (see help on parameters for details). Additionally, the tool outputs Share objects for each share that could be accessed.

.PARAMETER HostIP
The IP address of the computer hosting the share. The tool also supports multiple IP addresses by means of share objects coming through the pipeline.

.PARAMETER ShareName
The name of the share. The tool also supports multiple share names by means of share objects coming through the pipeline.

.PARAMETER TestWrite
Verifies if the current Windows credentials has write access to the share.

.PARAMETER GetSize
Determines the size of the share. The file TestShare_ExcludeFiles.txt, stored in $NMEVars.HomeDir\data\SMB-TestShares\, can be used to specify file types to be excluded from the GetSize operation.

.PARAMETER SearchFiles
Searches the share for files that matches a specific name. The search pattern is provided in TestShare_FileSearch.txt, stored in $NMEVars.HomeDir\data\SMB-TestShares\. The results is saved in matched_files.log in the same folder.

.PARAMETER SearchString
Searches files in the share for a a specific text string. The search pattern is provided in TestShare_StringSearch.txt, stored in $NMEVars.HomeDir\data\SMB-TestShares\. The file TestShare_ExcludeFiles.txt, stored in the same folder, can be used to specify file types to be excluded from the SearchString operation. The results is saved in matched_strings.log.

.PARAMETER DownloadMatched
Downloads a copy of a file if a matching string is found. The files are downloaded to the $NMEVars.HomeDir\data\SMB-TestShares\Downloads\ folder.

.PARAMETER ExcludeSystemShares
Excludes system and default shares from processing, including:
- Administrative shares (such as C$ and Admin$)
- Print queues
- IPC$

.PARAMETER SizeLimit
Maximum size (in megabytes) that, when exceeded, prevents SearchFiles and SearchString operations. This function requires that the size has been determined with the GetSize operation. The default value is 1000 MB.

.PARAMETER TimeLimit
Timeout value (in seconds) that, when hit, gives the user the option to cancel the current GetSize, SearchFile or SearchString operation. The default value is 300 seconds (5 minutes).

.PARAMETER ShowProgress
Enables a progress bar.

.EXAMPLE
<share objects>| NME-SMB-TestShares

.EXAMPLE
<share objects>| NME-SMB-TestShares -TestWrite -GetSize -SizeLimit 3000

.EXAMPLE
NME-SMB-TestShares -Target 192.168.56.22 -ShareName inetpub -SearchFiles -SearchString

.EXAMPLE
<share objects>| NME-SMB-TestShares -SizeLimit 1000 -ExcludeSystemShares -SearchString -DownloadMatched -ShowProgress |Format-Table -AutoSize

.NOTES

Data update policy
------------------
- Updates the "Permissions" and "Size" properties of the SMBShare object.
- Creates new Credential objects, updates the "Password" property on existing.

Module dependencies
-------------------
- Environment: HelperFunctions, CreateObjects

.LINK

#>

Function Test-SMBShares
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]
        [string]$HostIP,

        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]
        [string]$ShareName,

        [Parameter()]
        [switch]$TestWrite,

        [Parameter()]
        [switch]$GetSize,

        [Parameter()]
        [switch]$SearchFiles,

        [Parameter()]
        [switch]$SearchString,

        [Parameter()]
        [switch]$DownloadMatched,

        [Parameter()]
        [switch]$ExcludeSystemShares,
        
        [Parameter()]
        [int]$SizeLimit = 1000,

        [Parameter()]
        [int]$TimeLimit = 300,

        [Parameter()]
        [switch]$ShowProgress
    )

    BEGIN
    {
        #Default functions/variables
        $CmdName = 'Test-SMBShares'
        $CmdAlias = 'NME-SMB-TestShares'
        $Results = @()

        if($ShowProgress)
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

            $Counter = @{
                Total = $TargetsTotal
                Done = 0
            }
        }

        if(!(Test-Path "$($NMEVars.HomeDir)\data\SMB-TestShare")) #Verifies existance of script subfolder for storing the results
        {
            Write-Verbose 'No script folder(s) exist (creating)'
            [void](New-Item "$($NMEVars.HomeDir)\data\SMB-TestShares" -ItemType Directory)
            [void](New-Item "$($NMEVars.HomeDir)\data\SMB-TestShares\Downloads" -ItemType Directory)
            [void](New-Item "$($NMEVars.HomeDir)\data\SMB-TestShares\matched_files.log" -ItemType File)
            [void](New-Item "$($NMEVars.HomeDir)\data\SMB-TestShares\matched_strings.log" -ItemType File)
        }

        $ScriptDir = "$($NMEVars.HomeDir)\data\SMB-TestShares"

        If(!(Test-Path "$($NMEVars.HomeDir)\config\TestShare_ExcludeFiles.txt"))
        {
            New-Item "$($NMEVars.HomeDir)\config\TestShare_ExcludeFiles.txt" -type file |Out-Null
        }

        If(!(Test-Path "$($NMEVars.HomeDir)\config\TestShare_FileSearch.txt"))
        {
            New-Item "$($NMEVars.HomeDir)\config\TestShare_FileSearch.txt" -type file |Out-Null
        }

        If(!(Test-Path "$($NMEVars.HomeDir)\config\TestShare_StringSearch.txt"))
        {
            New-Item "$($NMEVars.HomeDir)\config\TestShare_StringSearch.txt" -type file |Out-Null
        }

        Write-Verbose 'Loading search/grep/exclude configurations'
        $ExcludeFiles = (Get-Content "$($NMEVars.HomeDir)\config\TestShare_ExcludeFiles.txt") -join ','
        $FileSearch = (Get-Content "$($NMEVars.HomeDir)\config\TestShare_FileSearch.txt") -join ','
        $StringSearch = (Get-Content "$($NMEVars.HomeDir)\config\TestShare_StringSearch.txt") -join ','
    }

    PROCESS
    {
        $ShareObject = Get-SMBShareObject -HostIP $HostIP -ShareName $ShareName -OnlyFromArray

        if(! $ShareObject)
        {
            $message = "Unable to find SMBShare object for '$($HostIP):$($ShareName)'"
            LogEvent -Command $CmdName -Severity Err -Event $message -ToFile -ToConsole

            return
        }

        if($ExcludeSystemShares)
        {
            switch ($ShareObject)
            {
                {$_.ShareName -match '^[A-Z]\$$'}    {return}
                {$_.Type -cmatch '^PRINTQ$'}         {return}
                {$_.Remark -cmatch '^Remote IPC$'}   {return}
                {$_.Remark -cmatch '^Remote Admin$'} {return}
            }
        }

        $unc = "\\$HostIP\$ShareName"

        try
        {
            if($ShowProgress)
            {
                Write-Progress -Activity 'Testing shares' -CurrentOperation "currently processing $unc" -Status "$($Counter.Done) of $($Counter.Total) shares completed" -PercentComplete (($($Counter.Done)/$($Counter.Total))*100)
                $Counter.Done++
            }

            $message = 'Attempting to mount'
            LogEvent -source $unc -command $CmdName -severity Info -event $message -ToFile -ToConsole

            [void](New-PSDrive -Name 'W' -PSProvider FileSystem -Root $unc -Persist -ErrorAction Stop)
            Remove-PSDrive -Name 'W'

            $message = 'Successfully mounted'
            LogEvent -source $unc -command $CmdName -severity Info -event $message -ToFile -ToConsole

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

            if(! $ShareObject.Permissions.AllowRead.Contains($NMEVars.CurrentUser))
            {
                $ShareObject.Permissions.AllowRead += $NMEVars.CurrentUser
            }

            if($TestWrite)
            {
                try
                {
                    $message = 'Attempting to write'
                    LogEvent -source $unc -command $CmdName -severity Info -event $message -ToFile -ToConsole

                    [void](New-Item -Path "$unc\write_test.txt" -Type file -ErrorAction Stop)
                    Remove-Item -Path "$unc\write_test.txt"

                    $message = 'Write access allowed'
                    LogEvent -source $unc -command $CmdName -severity Succ -event $message -ToFile -ToConsole


                    if(! $ShareObject.Permissions.AllowWrite.Contains($NMEVars.CurrentUser))
                    {
                        $ShareObject.Permissions.AllowWrite += $NMEVars.CurrentUser
                    }
                }
                catch
                {
                    if($ShareObject.Permissions.AllowWrite.Contains($NMEVars.CurrentUser))
                    {
                        $ShareObject.Permissions.AllowWrite = $ShareObject.Permissions.AllowWrite|?{$_ -ne $NMEVars.CurrentUser}
                    }

                    if ($_.FullyQualifiedErrorId -like '*UnauthorizedAccess*')
                    {
                        $message = 'Write access denied'
                    }
                    else
                    {
                        $message = $_.Exception.Message
                    }

                    LogEvent -source $unc -command $CmdName -severity Err -event $message -ToFile -ToConsole
                }
            }

            if($GetSize)
            {
                try
                {
                    $message = 'Determining size'
                    LogEvent -source $unc -command $CmdName -severity Info -event $message -ToFile -ToConsole

                    $command = "(Get-ChildItem -File -Path $unc -Exclude $ExcludeFiles -Recurse -Force -ErrorAction SilentlyContinue| Measure-Object -Property Length -Sum -ErrorAction SilentlyContinue).Sum /1MB"
                    $thread = [powershell]::Create().AddScript($command)
                        
                    Write-Verbose 'Invoking new thread (size operation)'
                    $handle = $thread.BeginInvoke()

                    if(WatchThread -handle $handle -timeOut $TimeLimit)
                    {
                        $ShareObject.Size = $thread.EndInvoke($handle)
                        $ShareObject.Size = $ShareObject.Size[0] -as [int]

                        $message = "Size determined ($($ShareObject.Size) MB)"
                        LogEvent -source $unc -command $CmdName -severity Info -event $message -ToFile -ToConsole
                    }
                    else
                    {
                        $message = 'Size measurement operation cancelled'
                        LogEvent -source $unc -command $CmdName -severity Warn -event $message -ToFile -ToConsole
                    }

                    $thread.Runspace.Close()
                    $thread.Dispose()                         
                }
                catch
                {
                    $message = $_.Exception.Message
                    LogEvent -source $unc -command $CmdName -severity Err -event $message -ToFile -ToConsole
                }
            }

            if($ShareObject.Size -lt $SizeLimit)
            {
                if($SearchFiles)
                {
                    try
                    {
                        $message = 'Conducting file search'
                        LogEvent -source $unc -command $CmdName -severity Info -event $message -ToFile -ToConsole

                        $command = "Get-ChildItem -File -Include $FileSearch -Path $unc -Recurse -Force -ErrorAction SilentlyContinue"
                        $thread = [powershell]::Create().AddScript($command)
                            
                        Write-Verbose 'Invoking new thread and executing filesearch'
                        $handle = $thread.BeginInvoke()

                        if(WatchThread -handle $handle -timeOut $TimeLimit)
                        {
                            $SearchResult = @($thread.EndInvoke($handle))

                            $message = 'File search completed'
                            LogEvent -source $unc -command $CmdName -severity Info -event $message -ToFile -ToConsole
                        }
                        else
                        {
                            $message = 'File search operation cancelled'
                            LogEvent -source $unc -command $CmdName -severity Warn -event $message -ToFile -ToConsole
                        }

                        $thread.Runspace.Close()
                        $thread.Dispose()

                        if($SearchResult)
                        {
                            Write-Verbose 'Saving results to logfile'
                            $searchResult |% {$_.FullName} |Out-File -FilePath "$ScriptDir\matched_files.log" -Append

                            $message = 'Matched file(s) found'
                            LogEvent -source $unc -command $CmdName -severity Succ -event $message -ToFile -ToConsole
                        }
                        else
                        {
                            Write-Verbose 'No filenames matched search criteria'
                        }
                    }
                    catch
                    {
                        $message = $_.Exception.Message
                        LogEvent -source $unc -command $CmdName -severity Err -event $message -ToFile -ToConsole
                    }
                }

                if($SearchString)
                {
                    try
                    {
                        $message = 'String-matching file content'
                        LogEvent -source $unc -command $CmdName -severity Info -event $message -ToFile -ToConsole

                        $command = "Get-ChildItem -File -Exclude $ExcludeFiles -Path $unc -Recurse -Force -ErrorAction SilentlyContinue| Select-String -pattern $StringSearch -AllMatches -ErrorAction SilentlyContinue" #Maybe should use simplematch, quicker? Or do i need to support regex?
                        $thread = [powershell]::Create().AddScript($command)
                            
                        Write-Verbose 'Invoking new thread (running string search)'
                        $handle = $thread.BeginInvoke()

                        if(WatchThread -handle $handle -timeOut $TimeLimit)
                        {
                            $GrepResult = @($thread.EndInvoke($handle))

                            $message = 'String-matching completed'
                            LogEvent -source $unc -command $CmdName -severity Info -event $message -ToFile -ToConsole
                        }
                        else
                        {
                            $message = 'String-matching operation canceled'
                            LogEvent -source $unc -command $CmdName -severity Warn -event $message -ToFile -ToConsole
                        }

                        $thread.Runspace.Close()
                        $thread.Dispose()

                        if($GrepResult)
                        {
                            Write-Verbose 'Saving results to object and logfile'
                            $grepResult |Out-File -FilePath "$scriptDir\matched_strings.log" -Append

                            $message = 'String-matched file(s) found'
                            LogEvent -source $unc -command $CmdName -severity Succ -event $message -ToFile -ToConsole

                            if($DownloadMatched)
                            {
                                $message = 'Downloading string-matched files'
                                LogEvent -source $unc -command $CmdName -severity Info -event $message -ToFile -ToConsole

                                $files = $GrepResult.Path| Select-Object -Unique

                                foreach($item in $files)
                                {
                                    $lpath = $item.TrimStart('\\').Substring(0, $item.LastIndexOf('\')-2)

                                    if (! (Test-Path "$scriptDir\downloads\$lpath"))
                                    {
                                        [void](New-Item -Path “$scriptDir\downloads\$lpath” -type Directory -ErrorAction SilentlyContinue)
                                    }
                                        
                                    Write-Verbose "Downloading file `'$item`'"
                                    Copy-Item $item "$ScriptDir\downloads\$lpath" # May need -ErrorAction SilentlyContinue or POSSIBLY add a try catch on this one....
                                }

                                $message = 'String-matched file(s) downloaded'
                                LogEvent -source $unc -command $CmdName -severity Info -event $message -ToFile -ToConsole
                            }
                        }
                        else
                        {
                            Write-Verbose 'No filenames matched search criteria'
                        }
                    }
                    catch
                    {
                        $message = $_.Exception.Message
                        LogEvent -source $unc -command $CmdName -severity Err -event $message -ToFile -ToConsole
                    }
                }
            }
            else
            {
                $message = 'Share size exceeds user-provided limit'
                LogEvent -source $unc -command $CmdName -severity Warn -event $message -ToFile -ToConsole
            }

            Write-Verbose 'Preparing results for console output'

            if($GrepResult)
            {
                $GrepLog = 'Matches found (see matched_strings.log)'
            }

            if($SearchResult)
            {
                $SearchLog = 'Matches found (see matched_files.log)'
            }

            $ResultsObj = $ShareObject |Select-Object * |Add-Member StringSearch $grepLog -PassThru |Add-Member FileSearch $searchLog -PassThru
            $Results += $ResultsObj
        }
        catch
        {
            if($ShareObject.Permissions.AllowRead.Contains($NMEVars.CurrentUser))
            {
                $ShareObject.Permissions.AllowRead = $ShareObject.Permissions.AllowRead|?{$_ -ne $NMEVars.CurrentUser}
            }

            if($_.Exception.NativeErrorCode)
            {
                $message = $_.Exception.NativeErrorCode
                LogEvent -source $unc -command $CmdName -event $message -native -ToFile -ToConsole
            }
            else
            {
                $message = $_.Exception.Message
                LogEvent -source $unc -command $CmdName -severity Err -event $message -ToFile -ToConsole
            }
        }
    }

    END
    {
        Write-Output $Results |Select-object HostIP,ShareName,Remark,Size,@{N='AllowRead';E={$_.Permissions.AllowRead}},@{N='AllowWrite';E={$_.Permissions.AllowWrite}},FileSearch,StringSearch
    }
}