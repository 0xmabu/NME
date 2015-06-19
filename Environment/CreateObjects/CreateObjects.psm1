<#
.SYNOPSIS
Function to obtain a new or existing Network object.

.DESCRIPTION
This function can be called to create an object of type "Network". Upon creation, the object is stored as a value in the "Networks" hashtable, using the CIDR as key. If the object already exists, that object is returned instead.

.PARAMETER CIDR
Specifies the CIDR notation of the IPv4 or IPv6 network.

.PARAMETER NotToArray
Prevents the object from being added to the global objects array.

.PARAMETER OnlyFromArray
Forces the function to only return an existing object.

.EXAMPLE
NME-GetNetwork 192.168.56.0/24

.EXAMPLE
Get-Content networks.txt| NME-GetNetworkObject

.EXAMPLE
1..10| % {NME-GetNetwork "192.168.$_.0/24}

.NOTES
#>
Function Get-NetworkObject
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory,ValueFromPipeline)]
        [String]$CIDR,

        [Parameter()]
        [switch]$NotToArray,

        [Parameter()]
        [switch]$OnlyFromArray
    )

    BEGIN
    {}

    PROCESS
    {
        #Setting object key
        $Key = $CIDR

        #Checking if object already exists
        if($NMEObjects.Networks.Contains($Key))
        {
            Write-Verbose 'Network object already exists (returning existing)'
            return $NMEObjects.Networks.$Key
        }

        #Stops further processing if existing object is required
        if($OnlyFromArray)
        {
            Write-Verbose 'Network object does not exist (returning)'
            return
        }

        #Param validation
        if($CIDR)
        {
            if( !(IPHelper -ValidateCIDR -CIDR $CIDR))
            {
                Write-Verbose 'Unable to create network object (CIDR invalid)'
                Return $false
            }
        }
        else
        {
            Write-Verbose 'Unable to create network object (CIDR invalid)'
            Return $false
        }

        $ip = $CIDR.Substring(0,$cidr.IndexOf('/'))
        $mask = $CIDR.Substring($cidr.IndexOf('/')+1) -as [int]
        $type = IPHelper -ValidateIP -IPAddress $ip

        #Creating Network object
        $NetObj = New-Object PSObject -Property @{
            CIDR      = $CIDR
            Range     = IPHelper -CIDRToRange -CIDR $CIDR
            Size      = if($type -eq 'IPv4'){[math]::Pow( 2, (32-$mask))}else{[math]::Pow( 2, (128-$mask))}
            Type      = $type
            RIR       = $null
        } |Select CIDR,Type,Range,Size,RIR 

        Add-Member -InputObject $netObj -MemberType ScriptMethod -Name GetComputers {

            $results = @()

            foreach($i in $NMEObjects.Computers)
            {
                if(IPHelper -IsMember -IPAddress $i.($this.Type) -CIDR $this.CIDR)
                {
                    $results += $i
                }
            }

            return $results

        } #Function that returns all Computer objects part of the network

        #Adding object to Networks hashtable
        if(!$NotToArray)
        {
            [void]($NMEObjects.Networks.Add($Key,$NetObj))
            Write-Verbose 'Added Network object to global array'
        }

        Return $netObj
    }
    
    END
    {}
}

<#
.SYNOPSIS
Function to obtain a new or existing Computer object.

.DESCRIPTION
This function can be called to create am object of type "Computer". Upon creation, the object is stored as a value in the "Computers" hashtable, using the IP address as key. If the object already exists, that object is returned instead.

.PARAMETER IP
Specifies the IPv4 or IPv6 address of the computer.

.PARAMETER NotToArray
Prevents the object from being added to the global objects array.

.PARAMETER OnlyFromArray
Forces the function to only return an existing object.

.EXAMPLE
NME-GetComputer 192.168.1.101

.EXAMPLE
Get-Content computers.txt| NME-GetComputer

.EXAMPLE
1..254| % {NME-GetComputer "192.168.1.$_}

.NOTES
#>
Function Get-ComputerObject
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory,ValueFromPipeline)]
        [String]$IP,

        [Parameter()]
        [switch]$NotToArray,

        [Parameter()]
        [switch]$OnlyFromArray
    )

    BEGIN
    {}

    PROCESS
    {
        #Setting object key
        $Key = $IP

        #Checking if object already exists
        if($NMEObjects.Computers.Contains($Key))
        {
            Write-Verbose 'Computer object already exists (returning from array)'
            return $NMEObjects.Computers.$Key
        }

        #Stops further processing if existing object is required
        if($OnlyFromArray)
        {
            Write-Verbose 'Computer object does not exist (returning)'
            return
        }

        #Validating params
        if( !(IPHelper -ValidateIP -IPAddress $IP))
        {
            Write-Verbose 'Unable to create computer object (IP address invalid)'
            Return
        }
    
        #Creating computer object 
        $compObj = New-Object psobject -Property @{
            IPAddress     = $IP
            #MACAddress   = $null
            HostName      = $null
            OSType        = $null
            OSVersion     = $null
            State         = $null
            Uptime        = $null
            Policy        = @()
            Ports         = @()
            Users         = @()
            Groups        = @()
            #Shares       = @()
            #Databases    = @()
            #Services     = @()
            LoggedOn      = @()
            NetStat       = @()
            NetTrace      = @()
        } |Select-Object IPAddress,HostName,OSType,OSVersion,State,Uptime,Policy,Users,Groups,LoggedOn,NetStat,NetTrace,Ports

        #Member function that returns all DNS names related to this IP address
        Add-Member -InputObject $CompObj -MemberType ScriptMethod -Name GetDNSNames {

            function recursive($rec)
            {
                $n = @($rec.Name)
            
                $more = $NMEObjects.DNSDomains.Values.Records|?{$_.Data -eq $rec.Name}

                if($more)
                {
                    foreach($i in $more)
                    {
                        $n += recursive $i
                    }
                }

                return $n
            }

            $names = @()

            $forward = $NMEObjects.DNSDomains.Values.Records|?{$_.Data -eq $this.IPAddress}

            foreach($r in $forward)
            {
                $names += recursive $r
            }

            $reverse = $NMEObjects.DNSDomains.Values.Records|?{$_.Name -eq $this.IPAddress}

            foreach($r in $reverse)
            {
                $names += $r.Data
            }

            $names = $names| select -Unique

            return $names
        }

        #Member function that returns all Services objects related to this IP address (accepting service type as param)
        Add-Member -InputObject $CompObj -MemberType ScriptMethod -Name GetServices {
            Param
            (
                $svc
            )

            if($svc)
            {
                $result = $NMEObjects.Services.$svc.Values|?{$_.HostIP -eq $this.IPAddress}
            }
            else
            {
                $result = foreach($i in $NMEObjects.Services.GetEnumerator()){
                    $i.Value.Values|?{$_.HostIP -eq $this.IPAddress}
                }
            }

            return $result
        }

        #Adding object to Computers array
        if(!$NotToArray)
        {
            [void]($NMEObjects.Computers.Add($Key,$CompObj))
            Write-Verbose 'Added new computer object to array'
        }

        Return $CompObj
    }

    END
    {}
}

<#
.SYNOPSIS
Function to obtain a new or existing MSSQL object.

.DESCRIPTION
This function can be called to create a "MSSQL object". It is used to represent a MSSQL Server service. Upon creation, the object is stored as a value in the Services.MSSQL hashtable, accessible as "<IP>:<TCPPort>" or "<IP>:<PIPE>". If the object already exists, the existing object is returned instead.

.PARAMETER HostIP
Specifies the IPv4 or IPv6 address of the computer hosting the service.

.PARAMETER TCPPort
Specifies the TCP port on which the service is listening.

.PARAMETER NamedPipe
Specifies the named pipe on which the service is listening (only the name of the pipe, not its full UNC path).

.PARAMETER NotToArray
Prevents the object from being added to the global objects array.

.PARAMETER OnlyFromArray
Forces the function to only return an existing object.

.EXAMPLE
NME-GetMSSQLServer -IP 192.168.1.10 -TCPPort 1433

.EXAMPLE
NME-GetMSSQLServer -IP 192.168.1.10 -NamedPipe sqlpipe

.NOTES
#>
Function Get-MSSQLObject
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory)]
        [string]$HostIP,

        [Parameter(Mandatory, ParameterSetName='Port')]
        [int]$TCPPort,

        [Parameter(Mandatory, ParameterSetName='Pipe')]
        [string]$NamedPipe,

        [Parameter()]
        [switch]$NotToArray,

        [Parameter()]
        [switch]$OnlyFromArray
    )

    BEGIN
    {}

    PROCESS
    {
        #Setting object key
        if($TCPPort)
        {
            $Key = "$HostIP`:$TCPPort"
        }
        else
        {
            $Key = "$HostIP`:$PipeName"
        }

        #Checking if object already exists
        if($NMEObjects.Services.MSSQL.Contains($Key))
        {
            Write-Verbose 'MSSQL object already exists (returning from array)'
            return $NMEObjects.Services.MSSQL.$Key
        }
        else #Stops further processing if existing object is required
        {
            if($OnlyFromArray)
            {
                Write-Verbose 'MSSQL object does not exist (returning)'
                return
            }
        }

        #Validating params
        if( !(IPHelper -ValidateIP -IPAddress $HostIP))
        {
            Write-Verbose 'Unable to create MSSQL object (IP address invalid)'
            Return
        }

        if($TCPPort -and ($TCPPort -lt 1 -or $TCPPort -gt 65535))
        {
            Write-Verbose 'Unable to create MSSQL object (TCP port invalid)'
            Return
        }

        #Creating MSSQL object
        $MssqlObj = New-Object psobject -Property @{
            HostIP       = $HostIP
            Service      = 'MSSQL'
            ServerName   = $null
            TCPPort      = $TCPPort
            NamedPipe    = $NamedPipe
            InstanceName = $null
            IsClustered  = $null
            Version      = $null
            Product      = $null
            AuthMode     = $null
            Databases    = [System.Collections.ArrayList]@()
            SQLLogins    = [System.Collections.ArrayList]@()
            Permissions  = @{AllowLogin = @()}
        } |Select-Object HostIP,Service,ServerName,TCPPort,NamedPipe,InstanceName,Product,Version,IsClustered,AuthMode,Databases,SQLLogins,Permissions

        Add-Member -InputObject $MssqlObj -MemberType ScriptMethod -Name GetValidCreds {

            if($this.TCPPort)
            {
                $SvcId = $this.TCPPort
            }
            else
            {
                $SvcId = $this.NamedPipe
            }

            $result = $NMEObjects.Credentials|
            ?{$_.HostIP -eq $this.HostIP}|
            ?{$_.Service -eq $this.Service}|
            ?{$_.SvcID -eq $SvcId}

            return $result
        }

        #Adding object to Services hashtable
        if(!$NotToArray)
        {
            [void]$NMEObjects.Services.MSSQL.Add($Key,$MssqlObj)
            Write-Verbose 'Added MSSQL object to global array'
        }

        Return $MssqlObj
    }

    END
    {}
}

<#
.SYNOPSIS
Function to obtain a new or existing SMB share object.

.DESCRIPTION
This function can be called to create a "SMB share object". It is used to represent a SMB share. Upon creation, the object is stored as a value in the Services.SMBShares hashtable, accessible as "<IP>:<ShareName>". If the object already exists, the existing object is returned instead.

.PARAMETER HostIP
Specifies the IPv4 or IPv6 address of the computer hosting the service.

.PARAMETER ShareName
Specifies the name of the share.

.PARAMETER NotToArray
Prevents the object from being added to the global objects array.

.PARAMETER OnlyFromArray
Forces the function to only return an existing object.

.EXAMPLE
NME-GetSMBShare -IP 192.168.1.10 -ShareName secret$

.NOTES
#>
Function Get-SMBShareObject
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory)]
        [string]$HostIP,

        [Parameter(Mandatory)]
        [string]$ShareName,

        [Parameter()]
        [switch]$NotToArray,

        [Parameter()]
        [switch]$OnlyFromArray
    )

    BEGIN
    {}

    PROCESS
    {
        #Setting object key
        $Key = "$HostIP`:$ShareName"

        #Checking if object already exists
        if($NMEObjects.Services.SMBShares.Contains($Key))
        {
            Write-Verbose 'SMB share object already exists (returning from array)'
            return $NMEObjects.Services.SMBShares.$Key
        }

        #Stops further processing if existing object is required
        if($OnlyFromArray)
        {
            Write-Verbose 'SMB share object does not exist (returning)'
            return
        }

        #Validating params
        if( !(IPHelper -ValidateIP -IPAddress $HostIP))
        {
            Write-Verbose 'Unable to create SMB share object (IP address invalid)'
            Return
        }

        #Creating SMB share object  
        $ShareObj  = New-Object psobject -Property @{
            HostIP      = $HostIP
            Service     = "SMBShare"
            ShareName   = $ShareName
            Type        = $null
            Remark      = $null
            Size        = $null
            #AllowMount  = $null
            #AllowWrite  = $null
            #GrepLog     = @()
            #SearchLog   = @()
            Permissions  = @{AllowRead = @(); AllowWrite = @()}
        } |Select-Object HostIP,Service,ShareName,Type,Remark,Size,Permissions
  
        if(!$NotToArray)
        {
            [void]$NMEObjects.Services.SMBShares.Add($Key,$ShareObj)
            Write-Verbose 'Added SMB share object to global array'
        }

        Return $ShareObj
    }

    END
    {}
}

<#
.SYNOPSIS
Function to obtain a new or existing DNS domain object.

.DESCRIPTION
This function can be called to create a "DNS Domain object". It is used to represent a DNS domain. Upon creation, the object is stored as a value in the "DNSDomains" hashtable, using the domain name as key. If the object already exists, the existing object is returned instead.

.PARAMETER DomainName
Specifies the fully-qualified domain name (FQDN) of the domain.

.PARAMETER NotToArray
Prevents the object from being added to the global objects array.

.PARAMETER OnlyFromArray
Forces the function to only return an existing object.

.EXAMPLE
NME-GetDNSDomain -DomainName google.com

.EXAMPLE
Get-Content domains.txt| NME-GetDNSDomain

.NOTES
#>
Function Get-DNSDomainObject
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory,ValueFromPipeline)]
        [String]$DomainName,
        
        [Parameter()]
        [switch]$NotToArray,

        [Parameter()]
        [switch]$OnlyFromArray
    )

    BEGIN
    {}

    PROCESS
    {
        #Setting object key
        $Key = $DomainName

        #Checking if object already exists
        if($DNSDomains.Contains($Key))
        {
            Write-Verbose 'DNS domain object already exists (returning from array)'
            return $DNSDomains.$Key
        }

        #Stops further processing if existing object is required
        if($OnlyFromArray)
        {
            Write-Verbose 'DNS domain object does not exist (returning)'
            return
        }

        #Param validation
        If( $DomainName -notmatch '(?=^.{4,253}$)(^((?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}$)' )
        {
            Write-Verbose 'Unable to create DNS domain object (invalid FQDN)'
            Return
        }

        #Creating DNS domain object
        $DomainObj = New-Object psobject -Property @{
            DomainName = $DomainName
            SOA        = @{}
            RIR        = @()
            Records    = [System.Collections.ArrayList]@()
        } |Select-Object DomainName,Records,SOA,RIR
    
        #Member function that returns an existing DNSRecord object, based on its name, type and data (supplied as params)
        Add-Member -InputObject $DomainObj -MemberType ScriptMethod -Name RecordExist {
            Param
            (
                $name,
                $type,
                $data
            )

            if($this.Records|?{$_.Name -eq $name -and $_.Type -eq $type -and $_.Data -eq $data})
            {
                return $true
            }
            else
            {
                return $false
            }
        }

        #Adding object to DNSDomains hashtable
        if(!$NotToArray)
        {
            [void]$DNSDomains.Add($Key,$DomainObj)
            Write-Verbose 'Added DNS domain object to global array'
        }

        Return $DomainObj
    }

    END
    {}
}

<#
.SYNOPSIS
Function to obtain a new or existing DNS record object.

.DESCRIPTION
This function can be called to create a "DNS record object". It is used to represent a DNS record in DNS. Upon creation, the object is stored as a value in the "DNSRecords" hashtable, accessible as "<ParentDomain>:<Type>:<Name>:<Data>". If the object already exists, the existing object is returned instead.

.PARAMETER ParentDomain
Specifies the fully-qualified domain name (FQDN) of the domain hosting the record. If this parameter is omitted, the parent will be set to the "orphan.nme" domain (created when the NME is initialized).

.PARAMETER Type
Specifies the type of record, where the valid options are A, AAAA, MX, NS, PTR, SOA, CNAME and Unknown. If this parameter is omitted, the type will be set to "Unknown".

.PARAMETER Name
Specifies the name of the target for which this record applies (for an A record, the hostname)

.PARAMETER Data
Specifies the data to which the "Name" information points (for an A record, the IP address)

.PARAMETER NotToArray
Prevents the object from being added to the global objects array.

.EXAMPLE
NME-GetDNSRecord -ParentDomain google.com -Type A -Name www -Data 64.233.161.105

.EXAMPLE
NME-GetDNSRecord -Name server01 -Type A -Data 192.168.56.20

.NOTES
#>
<#Function Get-DNSRecordObject
{
    [CmdletBinding()]
    Param
    (
        [Parameter()]
        [string]$ParentDomain = 'orphan.nme',
        
        [Parameter()]
        [ValidateSet('A','PTR','MX','NS','SOA','AAAA','CNAME','Unknown')]
        [string]$Type = 'Unknown',
        
        [Parameter(Mandatory)]
        [string]$Name,
        
        [Parameter(Mandatory)]
        [string]$Data,
        
        [Parameter()]
        [switch]$NotToArray
    )

    #Param validation
    If( !$DNSDomains.Contains($ParentDomain) )
    {
        NME-GetDNSDomain -DomainName $ParentDomain
        #Write-Verbose 'Unable to create DNSRecord object (parent domain does not exist)'
        #Return
    }

    #Checking if object already exists
    $key = "$ParentDomain`:$Type`:$Name`:$Data"

    if($DNSRecords.Contains($key))
    {
        Write-Verbose 'Object already exists (returning from array)'
        return $DNSRecords.$key
    }

    #Creating DNS record object
    $RecordObj = New-Object psobject -Property @{
        ParentDomain = $ParentDomain
        Name         = $Name
        Type         = $Type
        Data         = $Data
    } |Select-Object ParentDomain,Name,Type,Data

    #Adding object to DNSRecords hashtable
    if(!$NotToArray)
    {
        [void]$DNSRecords.Add($Key,$RecordObj)
        Write-Verbose 'Added DNSRecord object to global array'
    }

    Return $RecordObj
}#>

<#
.SYNOPSIS
Function to obtain a new or existing credential object.

.DESCRIPTION
This function can be called to create a "Credential object". It is used to represent valid credentials (username and password) in a service. Upon creation, the object is stored as a value in the "Credentials" array. If the object already exists, the existing object is returned instead.

.PARAMETER Username
Specifies the username.

.PARAMETER Password
Specifies the plain-text password.

.PARAMETER HashedPassword
Specifies a hashed representation of the password.

.PARAMETER EncryptedPassword
Specifies an encrypted representation of the password.

.PARAMETER Service
Specifies the service-specific object(s) to which the credential is related.

.PARAMETER NotToArray
Prevents the object from being added to the global objects array.

.PARAMETER OnlyFromArray
Forces the function to only return an existing object.

.EXAMPLE
NME-GetCredential -Username sa -Password sa -Service $Services.MSSQL.'192.168.1.10:1433'

.EXAMPLE
...

.NOTES
#>
Function Get-CredentialObject
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory)]
        [string]$Username,

        #[Parameter(Mandatory)]
        #[string]$HostIP,

        [Parameter(Mandatory)]
        [ValidateSet('WinSAM','WinDomain','MSSQL','Unknown')]
        [string]$CredType,

        [Parameter(Mandatory)]
        [string]$AuthService,

        [Parameter()]
        [switch]$NotToArray,

        [Parameter()]
        [switch]$OnlyFromArray
    )

    BEGIN
    {}

    PROCESS
    {
        #Checking if object already exists
        $ExistingObject = $NMEObjects.Credentials|
            ?{$_.AuthService -eq $AuthService}|
            ?{$_.CredType -eq $CredType}|
            ?{$_.Username -eq $Username}
            #?{$_.HostIP -eq $HostIP}
            
            
        
        if($ExistingObject)
        {
            Write-Verbose 'Credential object already exists (returning from array)'
            return $ExistingObject
        }
        else
        {
            if($OnlyFromArray)
            {
                Write-Verbose 'Credential object does not exist (returning)'
                return
            }
        }

        #Creating credential object
        $CredObj = New-Object psobject -Property @{
            Username    = $Username
            Password    = $null
            PwdHash     = $null
            HashType    = $null
            PwdCrypt    = $null
            CryptType   = $null
            #HostIP      = $HostIP
            CredType    = $CredType
            AuthService = $AuthService
        } |Select-Object AuthService,CredType,Username,Password,PwdHash,HashType,PwdCrypt,CryptType

        #Adding object to Services hashtable
        if(!$NotToArray)
        {
            [void]$NMEObjects.Credentials.Add($CredObj)
            Write-Verbose 'Added credential object to global array'
        }

        Return $CredObj
    }

    END
    {}
}