<#
 
.SYNOPSIS
Backs up framework objects.
 
.DESCRIPTION
This tool creates a backup of framework objects that are stored in memory. The backups can be restored (using NME-RestoreObjects) to recreate all objects and their data, as needed. The backups are created using the Export-Clixml cmdlet.

The tool can be used to manually create a backup at any given time, or to initialize a job that runs in the background and creates backups at a given interval.

.PARAMETER Objects
Object type(s) to backup, incuding Networks, Computers, Services, DNSDomains, Credentials or All. The default value is "All".

.PARAMETER FolderPath
The path to a folder where the backups will be saved. The default valus is the $NMEVars.HomeDir\backup folder.

.PARAMETER AsJob
Causes the tool to create a backup job runs in the background at a given interval (see JobInterval parameter).

.PARAMETER JobInterval
The time, in minutes, that the background job will wait between each backup.

.PARAMETER StopJob
Stop and removes any active backup jobs.

.EXAMPLE
NME-BackupObjects -Objects Computer,Services,Credentials

.EXAMPLE
NME-BackupObjects -AsJob -JobInterval 10

.EXAMPLE
NME-BackupObjects -StopJob

.NOTES

Module dependencies
-------------------
- Environment: HelperFunctions

#>

Function Backup-Objects
{
    [CmdletBinding()]
    Param
    (
        [Parameter()]
        [ValidateSet('Networks','Computers','Services','DNSDomains','Credentials','All')]
        [string[]]$Objects = ('All'),

        [Parameter()]
        [string]$FolderPath = "$($NMEVars.HomeDir)\backup",

        [Parameter()]
        [switch]$AsJob,

        [Parameter()]
        [int]$JobInterval = 1,

        [Parameter()]
        [switch]$StopJob
    )

    BEGIN
    {
        #Default functions/variables
        $CmdName = $MyInvocation.MyCommand.Name

        if(! (Test-Path $FolderPath))
        {
            $event = "Invalid FolderPath"
            LogEvent -Command $CmdName -Severity Err -Event $event -ToConsole

            break
        }
    }
    
    PROCESS
    {
        $command = {}

        if($StopJob)
        {
            if($NMEVars.BackupJob)
            {
                $NMEVars.BackupJob.Thread.Runspace.Close()
                $NMEVars.BackupJob.Thread.Dispose()
                $NMEVars.BackupJob = $null

                $message = 'Backup job successfully stopped'
                LogEvent -command $CmdName -severity Info -Event $message -ToConsole

                Return
            }
            else
            {
                $message = 'No backup job found'
                LogEvent -command $CmdName -severity Warn -Event $message -ToConsole

                Return
            }
        }

        #Building backup command based on Objects parameter input
        switch ($Objects)
        {
            {$_ -contains 'Networks'}    {$command = [scriptblock]::Create($command.ToString() + "`n" + "Export-Clixml -Path $FolderPath\networks.xml -InputObject `$NMEObjects.Networks -Depth 10")}
            {$_ -contains 'Computers'}   {$command = [scriptblock]::Create($command.ToString() + "`n" + "Export-Clixml -Path $FolderPath\computers.xml -InputObject `$NMEObjects.Computers -Depth 10")}
            {$_ -contains 'Services'}    {$command = [scriptblock]::Create($command.ToString() + "`n" + "Export-Clixml -Path $FolderPath\services.xml -InputObject `$NMEObjects.Services -Depth 10")}
            {$_ -contains 'DNSDomains'}  {$command = [scriptblock]::Create($command.ToString() + "`n" + "Export-Clixml -Path $FolderPath\dnsdomains.xml -InputObject `$NMEObjects.DNSDomains -Depth 10")}
            {$_ -contains 'Credentials'} {$command = [scriptblock]::Create($command.ToString() + "`n" + "Export-Clixml -Path $FolderPath\credentials.xml -InputObject `$NMEObjects.Credentials -Depth 10")}
            {$_ -contains 'All'}         {$command = [scriptblock]::Create($command.ToString() + "`n" + "Export-Clixml -Path $FolderPath\nmeobjects.xml -InputObject `$NMEObjects -Depth 10")}
        }

        if($AsJob)
        {
            if($NMEVars.BackupJob)
            {
                $message = 'Background job already running'
                LogEvent -command $CmdName -severity Warn -Event $message -ToConsole

                Return
            }

            $intSec = $JobInterval*60
            $loopCmd = "while(1 -eq 1){try{$command}catch{`$message = `"`$_ (stopping job)`"; LogEvent -cmd `"NME-BackupObjects`" -msgCat Err -msg `$message -ToConsole}; Start-Sleep $intSec}"
            
            $thread = CreateThread -Command $loopCmd -ImportVariables NMEObjects -ImportModules HelperFunctions
            
            Write-Verbose "Initializing background thread"
            $handle = $thread.BeginInvoke()

            $NMEVars.BackupJob = New-Object psobject -Property @{
                Thread = $thread
                Handle = $handle
            }

            $message = 'Backup job now running in background'
            LogEvent -command $CmdName -severity Info -Event $message -ToConsole
        }
        else
        {
            try
            {
                #Running foreground command
                Invoke-Command $command

                $message = 'Backup completed successfully'
                LogEvent -command $CmdName -severity Info -Event $message -ToConsole
            }
            catch
            {
                $message = "Backup failed: $_"
                LogEvent -command $CmdName -severity Err -Event $message -ToConsole
            }
        }
    }

    END
    {}
}

<#
 
.SYNOPSIS
Restores framework objects from backup.
 
.DESCRIPTION
This tool restores object backups created by the NME-BackupObjects tool. Restores are conducted using the Import-Clixml cmdlet.

.PARAMETER Objects
Object type(s) to restore, incuding Networks, Computers, Services, DNSDomains, Credentials or All. The default value is "All".

.PARAMETER FolderPath
The path to a folder where the backups are located. The default valus is the $NMEVars.HomeDir\backup folder.

.EXAMPLE
NME-RestoreObjects

.EXAMPLE
NME-RestoreObjects -Objects Computer,Services,Credentials

.NOTES

Dependencies
------------
The tool make use of the following internal modules / variables:
- HelperFunctions

#>

Function Restore-Objects
{
    [CmdletBinding()]
    Param
    (
        [Parameter()]
        [ValidateSet('Networks','Computers','Services','DNSDomains','Credentials','All')]
        [string[]]$Objects = ('All'),

        [Parameter()]
        [string]$FolderPath = "$($NMEVars.HomeDir)\backup"
    )

    BEGIN
    {
        #Default functions/variables
        $CmdName = $MyInvocation.MyCommand.Name

        if(! (Test-Path $FolderPath))
        {
            $message = "Invalid FolderPath"
            LogEvent -command $CmdName -severity Err -Event $message -ToConsole

            break
        }
    }
    
    PROCESS
    {
        $command = {}

        #Building resture command based on Objects parameter input
        switch ($Objects)
        {
            {$_ -contains 'Networks'}    {$command = [scriptblock]::Create($command.ToString() + "`n" + "`$Global:Networks = Import-Clixml -Path $FolderPath\networks.xml; `$NMEObjects.Networks = `$Global:Networks")}
            {$_ -contains 'Computers'}   {$command = [scriptblock]::Create($command.ToString() + "`n" + "`$Global:Computers = Import-Clixml -Path $FolderPath\computers.xml; `$NMEObjects.Computers = `$Global:Computers")}
            {$_ -contains 'Services'}    {$command = [scriptblock]::Create($command.ToString() + "`n" + "`$Global:Services = Import-Clixml -Path $FolderPath\services.xml; `$NMEObjects.Services = `$Global:Services")}
            {$_ -contains 'DNSDomains'}  {$command = [scriptblock]::Create($command.ToString() + "`n" + "`$Global:DNSDomains = Import-Clixml -Path $FolderPath\dnsdomains.xml; `$NMEObjects.DNSDomains = `$Global:DNSDomains")}
            {$_ -contains 'Credentials'} {$command = [scriptblock]::Create($command.ToString() + "`n" + "`$Global:Credentials = Import-Clixml -Path $FolderPath\credentials.xml; `$NMEObjects.Credentials = `$Global:Credentials")}
            {$_ -contains 'All'}         {$command = [scriptblock]::Create($command.ToString() + "`n" + "`$Global:NMEObjects = Import-Clixml -Path $FolderPath\nmeobjects.xml;`
            `$Global:Networks = `$NMEObjects.Networks;`
            `$Global:Computers = `$NMEObjects.Computers;`
            `$Global:Services = `$NMEObjects.Services;`
            `$Global:DNSDomains = `$NMEObjects.DNSDomains;`
            `$Global:Credentials = `$NMEObjects.Credentials`
            ")}
        }

        try
        {
            #Running foreground command
            Invoke-Command $command

            $message = 'Objects restored successfully'
            LogEvent -command $CmdName -severity Info -Event $message -ToConsole
        }
        catch
        {
            $message = "Restore failed: $_"
            LogEvent -command $CmdName -severity Err -Event $message -ToConsole
        }
    }

    END
    {}
}