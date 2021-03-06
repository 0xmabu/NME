﻿<#

.SYNOPSIS
Tool to import data from Nessus XML logs

.DESCRIPTION
This tool can be used to import data from an Nessus output log. Based on nessus xml data (the .nessus file), the tool creates computer objects and feeds various types of data to the object properties, including IP address, ports and service information. The tool also has the ability to create service objects based on the nessus output.

.PARAMETER FilePath
Specifies the path to the nessus xml log file to be parsed. The tool also accepts multiple files, as FileInfo objects coming through the pipeline (see examples).

.PARAMETER DataType
Specifies one or multiple data types that should be imported. Options include: 
- Hosts: Parses all hosts in the log and creates computer objects. Host-level data in the nessus xml, such as trace and state information, will also be imported into the computer object.
- Ports: Parses all items related open ports and saves the data in the "Ports" property of the computer object
- Services: Enables parsing of items related to services (see Services parameter)

By default, the tool imports Hosts, Ports and Services data.

.PARAMETER Services
Specifies the services type that should be parsed, currently supporting 'MSSQL' and 'SMBShares'. It also supports 'All' to include all supported services for parsing. This is the default.

.PARAMETER Replace
This switch parameter controls whether the tool should replace any existing data when parsing Ports data. By default, the tool will only import ports data if the port does not currently exists.

.EXAMPLE
NME-ImportNessusXML -FilePath c:\nessus-log.nessus

.EXAMPLE
Get-Location c:\nessuslogs\*.nessus| NME-ImportNessusXML -Items Ports

.EXAMPLE
NME-ImportNessusXML -Items Services -Services MSSQL

.NOTES

Module dependencies
-------------------
- Environment: HelperFunctions, CreateObjects

Issues / Other
--------------

#>


Function Import-NessusXML
{
    Param
    (
        [Parameter(Mandatory,ValueFromPipeline)]
        [string]$FilePath,

        [Parameter()]
        [ValidateSet('Hosts','Services','Ports','All')]
        [string[]]$ParseItems = 'All',

        [Parameter()]
        [ValidateSet('HTTP','SMBShare','MSSQL','All')]
        [string[]]$ServiceType = 'All',

        [Parameter()]
        [switch]$ReplacePortData
    )

    BEGIN
    {
        $CmdName = 'Import-NessusXML'
        $CmdAlias = 'NME-ImportNessusXML'

        $message = 'Starting Nessus data import'
        LogEvent -command $CmdName -severity Info -event $message -ToConsole
    }

    PROCESS
    {
        [xml]$nessusxml = Get-Content $Filepath

        Write-Verbose "Importing data from $Filepath"

        foreach($host in $nessusxml.NessusClientData_v2.Report.ReportHost) #Iterates through each host
        {
            $ip = ($host.HostProperties.tag|?{$_.name -eq 'host-ip'}).'#text'

            if($ParseItems -contains 'Hosts' -or $ParseItems -contains 'All')
            {
                Write-Verbose "Parsing host data ($ip)"

                $compObj = Get-ComputerObject -IP $ip

                $StateObj = New-Object psobject -Property @{
                    State         = 'Up' #Assuming all data in results are live hosts
                    QueryProtocol = 'nessus import'
                    QueryPort     = 'nessus import'
                    QueryTime     = ($host.HostProperties.tag|?{$_.name -eq 'HOST_START'}).'#text'
                } |Select-Object State,QueryProtocol,QueryPort,QueryTime #Creates results object

                $compObj.State = $StateObj
                
                #$compObj.MACAddress = ($host.HostProperties.tag|?{$_.name -eq 'mac-address'}).'#text'

                if($trace = $host.HostProperties.tag|?{$_.name -match 'traceroute-hop'})
                {
                    foreach($hop in $trace)
                    {
                        $traceObj = New-Object psobject -Property @{
                            Hop      = ($hop.name -split '-')[2]
                            IP       = $hop.'#text'
                            HostName = $null
                            RTT      = $null
                        } |Select Hop,IP,HostName,RTT

                        $traceArray += @($traceObj)
                    }

                    $traceArray = $traceArray |Sort-Object -Property Hop
                    $compObj.NetTrace += @($traceArray)
                }
            }
            
            if($ParseItems -contains 'Services' -or $ParseItems -contains 'All')
            {
                Write-Verbose "Parsing service data ($ip)"

                # HTTP parsing
                if($ServiceType -contains 'HTTP' -or $ServiceType -contains 'All')
                {
                    Write-Verbose 'Parsing HTTP data from plugin 22964'

                    $http = $host.ReportItem|?{($_.pluginID -eq '22964') -and ($_.plugin_output -match 'A web server is running on this port')}

                    foreach($i in $http)
                    {
                        $httpObj = Get-HTTPServerObject -HostIP $ip -TCPPort $i.port
                        
                        $version = $host.ReportItem|?{$_.pluginID -eq '10107' -and $_.port -eq $i.port}
                        
                        if($version)
                        {
                            $httpObj.Product = ($version.plugin_output -split '\n')[2]
                        }

                        if($i.plugin_output -match "A web server is running on this port through") #'through' keyword indicate that nessus has identified SSL/TLS support for the service
                        {
                            $httpObj.SecureChannel = $true
                        }
                        else
                        {
                            $httpObj.SecureChannel = $false
                        }
                    }
                }

                #MSSQL parsing
                if($ServiceType -contains 'MSSQL' -or $ServiceType -contains 'All')
                {
                    $mssql = $host.ReportItem|?{($_.pluginID -eq '10144') -or ($_.pluginID -eq '10674')}

                    foreach($item in $mssql)
                    {
                        if($item.pluginID -eq '10144')
                        {
                            Write-Verbose 'Parsing MSSQL data from plugin 10144'

                            $mssqlObj = Get-MSSQLObject -HostIP $ip -TCPPort $item.port
                            $mssqlObj.Version = ([regex]'(?<=version is ).*').Match($item.plugin_output).Value.TrimEnd('.')

                            switch ($mssqlObj.Version)
                            {
                                {$_ -match '^7\.0'}  {$mssqlObj.Product = 'Microsoft SQL Server 7.0'; break}
                                {$_ -match '^8\.0'}  {$mssqlObj.Product = 'Microsoft SQL Server 2000'; break}
                                {$_ -match '^9\.0'}  {$mssqlObj.Product = 'Microsoft SQL Server 2005'; break}
                                {$_ -match '^10\.0'} {$mssqlObj.Product = 'Microsoft SQL Server 2008'; break}
                                {$_ -match '^10\.5'} {$mssqlObj.Product = 'Microsoft SQL Server 2008 R2'; break}
                                {$_ -match '^11\.0'} {$mssqlObj.Product = 'Microsoft SQL Server 2012'; break}
                                {$_ -match '^12\.0'} {$mssqlObj.Product = 'Microsoft SQL Server 2014'; break}
                                Default {}
                            }
                        }
    
                        if($item.pluginID -eq '10674')
                        {
                            Write-Verbose 'Parsing MSSQL data from plugin 10674'

                            $array = (([regex]'(?s)(?<=  ).*?(?=\n\n)').matches($item.plugin_output).Value) #Extracting each instance as a string and storing in array

                            foreach($i in $array)
                            {
                                $sqlport = ([regex]'(?<=tcp          : ).*').Matches($i).value
                                $sqlpipe = ([regex]'(?<=np           : ).*').Matches($i).value

                                if($sqlport -or $sqlpipe)
                                {
                                    if($sqlport)
                                    {
                                        $mssqlObj = Get-MSSQLObject -HostIP $ip -TCPPort $sqlport
                                    }
                                    else
                                    {
                                        $mssqlObj = Get-MSSQLObject -HostIP $ip -TCPPort $sqlpipe
                                    }

                                    $mssqlObj.TCPPort      = $sqlport
                                    $mssqlObj.NamedPipe    = $sqlpipe
                                    $mssqlObj.InstanceName = ([regex]'(?<=InstanceName : ).*').Matches($i).value
                                    $mssqlObj.Version      = ([regex]'(?<=Version      : ).*').Matches($i).value
                                    $mssqlObj.IsClustered  = ([regex]'(?<=IsClustered  : ).*').Matches($i).value
                                    $mssqlObj.ServerName   = ([regex]'(?<=ServerName   : ).*').Matches($i).value

                                    switch ($mssqlObj.version)
                                    {
                                        {$_ -match '^7\.0'}  {$mssqlObj.Product = 'Microsoft SQL Server 7.0'; break}
                                        {$_ -match '^8\.0'}  {$mssqlObj.Product = 'Microsoft SQL Server 2000'; break}
                                        {$_ -match '^9\.0'}  {$mssqlObj.Product = 'Microsoft SQL Server 2005'; break}
                                        {$_ -match '^10\.0'} {$mssqlObj.Product = 'Microsoft SQL Server 2008'; break}
                                        {$_ -match '^10\.5'} {$mssqlObj.Product = 'Microsoft SQL Server 2008 R2'; break}
                                        {$_ -match '^11\.0'} {$mssqlObj.Product = 'Microsoft SQL Server 2012'; break}
                                        {$_ -match '^12\.0'} {$mssqlObj.Product = 'Microsoft SQL Server 2014'; break}
                                        Default {}
                                    }
                                }
                                else
                                {
                                    $message = 'MSSQL object found that is not reachable over TCP or named pipes (skipping)'
                                    LogEvent -Command $CmdName -Severity Warn -Event $message -ToConsole
                                }

                            }
                        }
                    }
                }

                #SMB parsing
                if($ServiceType -contains 'SMBShares' -or $ServiceType -contains 'All')
                {
                    $plugins = $host.ReportItem|?{($_.pluginID -eq '10395') -or ($_.pluginID -eq '42411')} |Sort-Object -Property pluginID #Sorting so that 10395 is processed first (needed to get a full listing of shares prior to procesing of 42411)

                    foreach($item in $plugins)
                    {
                        if($item.pluginID -eq '10395')
                        {
                            Write-Verbose 'Parsing SMBShares data from plugin 10395'

                            $shares = ([regex]'(?<=  - ).*').Matches($item.plugin_output).Value
                            
                            foreach($i in $shares)
                            {
                                $shareObj = Get-SMBShareObject -HostIP $ip -ShareName $i
                            }
                        }

                        if($item.pluginID -eq '42411')
                        {
                            Write-Verbose 'Parsing SMBShares data from plugin 42411'

                            $readable = (([regex]'.*(?=  - \(readable)').Matches($item.plugin_output).Value).trimstart(' -') |?{$_} #Last pipe expression removes empty lines from array
                            $writeable = (([regex]'.*(?=  - \(readable,writable\))').Matches($item.plugin_output).Value).trimstart(' -') |?{$_} #Last pipe expression removes empty lines from array

                            foreach($i in $readable)
                            {
                                $shareObj = Get-SMBShareObject -HostIP $ip -ShareName $i
                                $shareObj.Permissions.AllowRead = $true
                            }

                            foreach($i in $writeable)
                            {
                                $shareObj = Get-SMBShareObject -HostIP $ip -ShareName $i
                                $shareObj.Permissions.AllowRead = $true
                                $shareObj.Permissions.AllowWrite = $true
                            }

                            foreach($i in $compObj.GetServices('SMBShares')|?{$_.Permissions.AllowRead -ne $true})
                            {
                                $i.Permissions.AllowRead = $false
                            }

                            foreach($i in $compObj.GetServices('SMBShares')|?{$_.Permissions.AllowWrite -ne $true})
                            {
                                $i.Permissions.AllowWrite = $false
                            }
                        }
                    }
                }            
            }

            if($ParseItems -contains 'Ports' -or $ParseItems -contains 'All')
            {
                Write-Verbose "Parsing port data ($ip)"

                $openPorts = $host.ReportItem|?{$_.pluginID -eq '11219' -or $_.pluginID -eq '10335' -or  $_.pluginID -eq '34277'} #Captures all ports from Nessus SYN, TCP and UDP scans.
                
                foreach($port in $openPorts) #Iterates through each port item
                {
                    if( !( $portObj = $compObj.Ports|?{($_.Protocol -eq $port.protocol) -and ($_.PortNumber -eq $Port.port)} )) #Binds to existent port object, or creates and binds to new port object if none exist.
                    {
                        $portObj = New-Object psobject -Property @{
                            Protocol    = $null
                            PortNumber  = $null
                            Socket      = $null
                            Service     = $null
                            State       = $null
                        }

                        $compObj.Ports += $portObj
                    }

                    if($ReplacePortData -or ($portObj.Protocol -eq $null)) #Inserts new data if object is new or $replace is enabled
                    {
                        $portObj.Protocol       = $port.protocol
                        $portObj.PortNumber     = $port.port
                        $portObj.Socket         = "$($port.protocol)/$($port.port)"
                    }
                    else
                    {
                        Write-Verbose "Port object data exists (skipping)"
                    }

                    if( !($serviceObj = $portObj.Service)) #Binds to existent service object, or creates and binds to new port object if none exist.
                    {
                        $serviceObj = New-Object psobject -Property @{
                            Name        = $null
                            Product     = $null
                            Tunnel      = $null
                        }

                        $portObj.Service = $serviceObj
                    }

                    if($ReplacePortData -or ($serviceObj.Name -eq $null)) #Inserts new data if object is new or $replace is enabled
                    {
                        $serviceObj.Name      = $port.svc_name
                    }
                    else
                    {
                        Write-Verbose "Port service object exists (skipping)"
                    }

                    if( !($stateObj = $portObj.State)) #Binds to existent service object, or creates and binds to new port object if none exist.
                    {
                        $stateObj = New-Object psobject -Property @{
                            State      = $null
                            Reason     = $null
                            Reason_ttl = $null
                        }

                        $portObj.State = $stateObj
                    }

                    if($ReplacePortData -or ($stateObj.State -eq $null)) #Inserts new data if object is new or $replace is enabled
                    {
                        $stateObj.State = 'up'
                    }
                    else
                    {
                        Write-Verbose "Port state object exists (skipping)"
                    }
                }
            }
        }

        Write-Verbose "Data import from $FilePath completed"
    }         

    END
    {
        $message = 'Nessus data import completed'
        LogEvent -command $CmdName -severity Info -event $message -ToConsole
    }
}