<#

.SYNOPSIS
Tool to import data from nmap XML logs

.DESCRIPTION
This tool can be used to import data from nmap xml output. Based on the nmap xml data, the tool creates computer objects and feeds various types of data to the object properties, including IP address, ports and service information. The tool also has the ability to import data from nmap host- and port script output.

.PARAMETER FilePath
Specifies the path to the nmap xml log file to be parsed. The tool also accepts multiple files as FileInfo objects coming through the pipeline (see examples).

.PARAMETER ParseItems
Specifies one or multiple item types that should be imported. Options include: 
- Hosts: Parses host-level data and creates Computer objects.
- Services: Parses service-level data and creates Service objects (see ServiceTypes parameter for additional details)
- Ports: Parses the entire ports section of the nmap log and saves the results to the "Ports" property of the Computer object
- All: Parses all data. This is the default value.

.PARAMETER ServiceType
Specifies one or multiple service types that should be parsed, including:
- HTTP: Parses data related to HTTP/HTTPS services and creates HTTP server and HTTP virtual host objects
- MSSQL: Parses data related to MSSQL server and creates MSSQL server objects
- SMBShare: Parses data related to SMB file shares and creates SMB share objects
- All: Parses all data. This is the default value.

In order for the tool to parse service data, the nmap scan has to include a version scan (-sV).

.PARAMETER ReplacePortsData
This switch forces the tool to replace any existing data when parsing ports items. By default, the tool will only import ports data if the port does not currently exist.

.EXAMPLE
NME-ImportNmapXML -FilePath c:\nmap-log.xml

.EXAMPLE
Get-Location c:\nmaplogs\*.xml| NME-ImportNmapXML -ParseItem Ports

.EXAMPLE
NME-ImportNmapXML -ParseItems Hosts,Services -ServiceType HTTP,MSSQL

.NOTES

Module dependencies
-------------------
- Environment: HelperFunctions, CreateObjects

Issues / Other
--------------

#>


Function Import-NmapXML
{
    Param
    (
        [Parameter(Mandatory,ValueFromPipeline)]
        [string]$Filepath,

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
        $CmdName = 'Import-NmapXML'
        $CmdAlias = 'NME-ImportNmapXML'

        $message = 'Starting Nmap data import'
        LogEvent -command $CmdName -severity Info -Event $message -ToConsole
    }

    PROCESS
    {
        [xml]$nmapxml = Get-Content $Filepath

        Write-Verbose "Importing data from $Filepath"

        foreach ($host in $nmapxml.nmaprun.host) #Iterates through each host
        {
            $ip = ($host.address|?{$_.addrtype -match 'ip'}).addr

            if($ParseItems -contains 'Hosts' -or $ParseItems -contains 'All')
            {
                Write-Verbose "Parsing host data ($ip)"
                
                $compObj = Get-ComputerObject -IP $ip

                $StateObj = New-Object psobject -Property @{
                    State         = $host.status.state
                    QueryProtocol = 'nmap import'
                    QueryPort     = 'nmap import'
                    QueryTime     = (New-Object datetime(1970,1,1,0,0,0,0,[System.DateTimeKind]::Utc)).AddSeconds($host.starttime).ToString()
                } |Select-Object State,QueryProtocol,QueryPort,QueryTime #Creates results object

                $compObj.State = $StateObj

                #$compObj.MACAddress = ($host.address|?{$_.addrtype -eq 'mac'}).addr

                if($host.trace)
                {
                    foreach($hop in $host.trace.hop)
                    {
                        $traceObj = New-Object psobject -Property @{
                            Hop      = $hop.ttl
                            IP       = $hop.ipaddr
                            HostName = $hop.host
                            RTT      = $hop.rtt
                        } |Select Hop,IP,HostName,RTT

                        $compObj.NetTrace += @($traceObj)
                    }
                }
            }

            if($ParseItems -contains 'Services' -or $ParseItems -contains 'All')
            {
                Write-Verbose "Parsing service data ($ip)"

                $scriptCol = @{}

                foreach ($script in ($host.hostscript.script)) #Extracts host script data
                {
                    $scriptCol += @{$script.id = $script.OuterXml}
                }

                foreach($port in ($host.ports.port)) #Extracts port script data
                {
                    foreach ($script in $port.script)
                    {
                        $scriptCol += @{$script.id = $script.OuterXml}
                    }
                }

                # HTTP parsing
                if($ServiceType -contains 'HTTP' -or $ServiceType -contains 'All')
                {
                    Write-Verbose 'Parsing HTTP data from version scan'

                    $http = $host.ports.port|? {($_.service.name -match 'http.*') -and ($_.service.method -eq 'probed')}

                    foreach($i in $http)
                    {
                        $httpObj = Get-HTTPServerObject -HostIP $ip -TCPPort $i.portid
                        $httpObj.Product = $i.service.product
                        $httpObj.Version = $i.service.version

                        if($i.service.tunnel)
                        {
                            $httpObj.SecureChannel = $true
                        }
                        else
                        {
                            $httpObj.SecureChannel = $false
                        }
                    }

                    if($scriptCol.ContainsKey(''))
                    { }
                }

                # MSSQL parsing
                if($ServiceType -contains 'MSSQL' -or $ServiceType -contains 'All')
                {
                    Write-Verbose 'Parsing MSSQL data from version scan'

                    $mssql = $host.ports.port|? {($_.service.name -eq 'ms-sql-s') -and ($_.service.method -eq 'probed')}

                    foreach($i in $mssql)
                    {
                        $mssqlObj = Get-MSSQLObject -HostIP $ip -TCPPort $i.portid
                        $mssqlObj.Product = $i.service.product
                        $mssqlObj.Version = $i.service.version
                    }

                    if($scriptCol.ContainsKey('ms-sql-info'))
                    {
                        Write-Verbose 'Parsing MSSQL data from script "ms-sql-info"'

                        $data = $scriptCol["ms-sql-info"]
                        $array = $data -split '\[.*?\]' |Select-Object -Skip 1

                        foreach($i in $array)
                        {
                            $sqlport = ([regex]'(?<=TCP port: ).*?(?=&#)').Match($i).Value
                            $sqlpipe = ([regex]'(?<=Named pipe: ).*?(?=&#)').Match($i).Value

                            if($sqlport)
                            {
                                $mssqlObj = Get-MSSQLObject -HostIP $ip -TCPPort $sqlport
                            }
                            else
                            {
                                $mssqlObj = Get-MSSQLObject -HostIP $ip -NamedPipe $sqlpipe
                            }

                            $mssqlObj.TCPPort      = $sqlport
                            $mssqlObj.NamedPipe    = $sqlpipe
                            $mssqlObj.InstanceName = ([regex]'(?<=Instance name: ).*?(?=&#)').Match($i).Value
                            $mssqlObj.IsClustered  = ([regex]'(?<=Clustered: ).*?(?=&#)').Match($i).Value
                            $mssqlObj.Version      = ([regex]'(?<=Version number: ).*?(?=&#)').Match($i).Value
                            $mssqlObj.Product      = ([regex]'(?<=Version: ).*?(?=&#)').Match($i).Value
                        }
                    }

                    if($scriptCol.ContainsKey('broadcast-ms-sql-discover'))
                    {
                        Write-Verbose 'Parsing MSSQL data from script "broadcast-ms-sql-discover"'

                        $data = $scriptCol['broadcast-ms-sql-discover']
                        $array = $data -split '\[.*?\]' |Select-Object -Skip 1

                        foreach($i in $array)
                        {
                            $sqlport = ([regex]'(?<=TCP port: ).*?(?=&#)').Match($i).Value
                            $sqlpipe = ([regex]'(?<=Named pipe: ).*?(?=&#)').Match($i).Value

                            if($sqlport -or $sqlpipe)
                            {
                                if($sqlport -or $sqlpipe)
                                {
                                    $mssqlObj = Get-MSSQLObject -HostIP $ip -TCPPort $sqlport
                                }
                                else
                                {
                                    $mssqlObj = Get-MSSQLObject -HostIP $ip -NamedPipe $sqlpipe
                                }

                                $mssqlObj.TCPPort      = $sqlport
                                $mssqlObj.NamedPipe    = $sqlpipe
                                $mssqlObj.InstanceName = ([regex]'(?<=Name: ).*?(?=&#)').Match($i).Value
                                $mssqlObj.IsClustered  = $null
                                $mssqlObj.Version      = $null
                                $mssqlObj.Product      = ([regex]'(?<=Product: ).*?(?=&#)').Match($i).Value
                            }
                            else
                            {
                                $message = 'MSSQL object found that is not reachable over TCP or named pipes (skipping)'
                                LogEvent -Command $CmdName -Severity Warn -Event $message -ToConsole
                            }
                        }
                    }
                }

                #SMBShare parsing
                if($ServiceType -contains 'SMBShares' -or $ServiceType -contains 'All')
                {
                    if($scriptCol.ContainsKey('smb-enum-shares'))
                    {
                        Write-Verbose 'Parsing SMB share data from script "smb-enum-shares"'

                        $data = $scriptCol['smb-enum-shares']
                        $array = $data -replace '    ' -split '&#xA;  ' |?{$_ -notmatch '<script id=' -and $_ -notmatch 'ERROR: Enumerating shares failed'}

                        foreach($i in $array)
                        {
                            $sharename = ([regex]'.*(?=&#xA;)').Match($i).Value

                            $shareObj = Get-SMBShareObject -HostIP $ip -ShareName $sharename

                            $shareObj.Type       = ([regex]'(?<=&#xA;Type: ).*?(?=&#xA;').Matches($i).Value
                            $shareObj.Remark     = ([regex]'(?<=&#xA;Comment: ).*?(?=&#xA;').Matches($i).Value
                            $shareObj.Permissions.AllowRead = $null #To be fixed when I can test
                            $shareObj.Permissions.AllowWrite = $null #To be fixed when I can test
                        }
                    }
                }
            }

            if($ParseItems -contains 'Ports' -or $ParseItems -contains 'All')
            {
                Write-Verbose "Parsing host data ($ip)"

                foreach($port in ($host.ports.port)) #Iterates through port node data
                {
                    if( !( $portObj = $compObj.Ports|?{($_.Protocol -eq $port.protocol) -and ($_.PortNumber -eq $Port.portid)} )) #Binds to existent port object, or creates and binds to new port object if none exist.
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
                        $portObj.PortNumber     = $port.portid
                        $portObj.Socket         = "$($port.protocol)/$($port.portid)"
                    }
                    else
                    {
                        Write-Verbose 'Port object data exists (skipping)'
                    }

                    if( !($serviceObj = $portObj.Service)) #Binds to existent service object, or creates and binds to new port object if none exist.
                    {
                        $serviceObj = New-Object psobject -Property @{
                            Name        = $null
                            Product     = $null
                            Version     = $null
                            ExtraInfo   = $null
                            Tunnel      = $null
                            Method      = $null
                            Conf        = $null
                            Cpe         = @()
                        }

                        $portObj.Service = $serviceObj
                    }

                    if($ReplacePortData -or ($serviceObj.Name -eq $null)) #Inserts new data if object is new or $replace is enabled
                    {
                        $serviceObj.Name      = $port.service.name
                        $serviceObj.Product   = $port.service.product
                        $serviceObj.Version   = $port.service.version
                        $serviceObj.ExtraInfo = $port.service.extrainfo
                        $serviceObj.Tunnel    = $port.service.tunnel
                        $serviceObj.Method    = $port.service.method
                        $serviceObj.Conf      = $port.service.conf
                        $serviceObj.Cpe       = $port.service.cpe
                    }
                    else
                    {
                        Write-Verbose 'Port service object exists (skipping)'
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
                        $stateObj.State      = $port.state.state 
                        $stateObj.Reason     = $port.state.reason
                        $stateObj.Reason_ttl = $port.state.reason_ttl
                    }
                    else
                    {
                        Write-Verbose 'Port state object exists (skipping)'
                    }
                }
            }
        }

        Write-Verbose "Data import from $Filepath completed"
    }

    END
    {
        $message = 'Nmap data import completed'
        LogEvent -command $CmdName -severity Info -Event $message -ToConsole
    }
}