<#

.SYNOPSIS
A DNS resolver that supports common DNS queries.

.DESCRIPTION
This module implements a DNS client that supports commonly used DNS queries, including A, AAAA, NS, MX, PTR and SOA. The client is based on the DnsQuery function exposed in dnsapi.dll.

.PARAMETER Target
The query target, specified as a hostname, domain name or IP address. Multiple targets can be processed by sending them as objects through the pipeline.

.PARAMETER RecordType
The record type to query for, specified as A, AAAA, MX, NS, PTR or SOA

.PARAMETER QueryOptions
Specific options to apply to the query, including the following
- NoRecurse: Prevents reqursive queries
- NoCache: Prevents the resolver from using any local resources (such as the local cache and hosts file) in the query process
- NoNetBT: Prevents the resolver from using NetBT (NetBIOS over TCP/IP) as fallback in the query process.
- NoLLMNR: Prevents the resolver from using LLMNR (Local-Link Multicast Name Resolution) as fallback in the query process.
- OnlyLLMNR: Forces the resolver to only use the LLMNR protocol in the query process.

.PARAMETER DNSServer
The DNS server(s) to use in the query process (currently not working, see Notes)

.EXAMPLE
NME-DNS-QueryDNS www.google.com

.EXAMPLE
NME-DNS-QueryDNS -RecordType PTR -Target 1.2.3.4

.EXAMPLE
<objects>|?{$_.DomainName -like "google*"}|NME-DNS-QueryDNS -RecordType MX |Format-table -Autosize

.NOTES

Dependencies
------------
This tool makes use of Matthew Graebers PSReflect module (PowerSploit framework) to in order to gain access to the Win32 APIs.

The tool make use of the following internal modules:
- Runtime
- HelperFunctions

Issues / Other
--------------
- Chosing a specific DNS server to query (DNSServer parameter) does not work currently. If a specific DNS server is to be queried, change the DNS server settings for the network interface.
- Does currently not show/return any data part of the "Additional" or "Authority" sections - only "Answer" section is returned.

.LINK
DnsQuery api
- http://msdn.microsoft.com/en-us/library/ms682016%28VS.85%29.aspx

PowerSploit Framework
- https://github.com/mattifestation/PowerSploit

#>

Function Invoke-DNSQuery
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [Alias('IPAddress','DomainName','HostName')]
        [string]$Target,

        [Parameter()]
        [ValidateSet('A','PTR','MX','NS','SOA','AAAA')]
        [string]$RecordType = 'A',

        [Parameter()]
        [ValidateSet('NoRecurse','NoCache','NoNetBT','OnlyLLMNR','NoLLMNR')]
        [string[]]$QueryOptions,

        [Parameter()]
        [string[]]$DNSServer,

        [Parameter()]
        [switch]$DontFeedObject
    )

    BEGIN
    {
        ## Default functions/variables
        $CmdName = 'Invoke-DNSQuery'
        $CmdAlias = 'NME-DNS-QueryDNS'
        $Results = [System.Collections.ArrayList]@()

        ## Script variables

        switch ($RecordType) #Setting query type (wType)
        {
            'A'    { $wType = [DNSRecordTypes]::DNS_TYPE_A -as [int]; break }
            'MX'   { $wType = [DNSRecordTypes]::DNS_TYPE_MX -as [int]; break }
            'NS'   { $wType = [DNSRecordTypes]::DNS_TYPE_NS -as [int]; break }
            'AAAA' { $wType = [DNSRecordTypes]::DNS_TYPE_AAAA -as [int]; break }
            'SOA'  { $wType = [DNSRecordTypes]::DNS_TYPE_SOA -as [int]; break }
            'PTR'  { $wType = [DNSRecordTypes]::DNS_TYPE_PTR -as [int]; break }
        }

        #Setting query options (Options)
        $Options = 0

        switch ($QueryOptions)
        {
            { $_ -contains 'NoRecurse' } { $Options += [DNSQueryOptions]::DNS_QUERY_NO_RECURSION -as [int] }
            { $_ -contains 'NoCache' }   { $Options += [DNSQueryOptions]::DNS_QUERY_WIRE_ONLY -as [int] }
            { $_ -contains 'NoNetBT' }   { $Options += [DNSQueryOptions]::DNS_QUERY_NO_NETBT -as [int] }
            { $_ -contains 'NoLLMNR' }   { $Options += [DNSQueryOptions]::DNS_QUERY_NO_MULTICAST -as [int] }
            { $_ -contains 'OnlyLLMNR' } { $Options += [DNSQueryOptions]::DNS_QUERY_MULTICAST_ONLY -as [int] }
        }

        #Setting additional options (pExtra)
        $pExtra = New-Object -TypeName IP4_ARRAY # Empty IP_ARRAY object causes dnsapi to use the default DNS server
        
        if($DNSServer) #Populates any provided DNS servers to pExtra/IP_ARRAY
        {
            $pExtra.AddrCount = $DNSServer.Count

            if($pExtra.AddrCount -gt 0)
            {
                for ($i = 0; $i -le ($pExtra.AddrCount-1); $i++)
                {
                    $address = [bitconverter]::ToUInt32([ipaddress]::Parse($DNSServer[$i]).GetAddressBytes(), 0)
                    $pExtra.AddrArray += @($false)
                    $pExtra.AddrArray[$i] = $address
                }
            }
        }

        ## Script helper functions

        Function GetParentDomain #Returns a valid domain name for a given FQDN
        {
            Param
            (
                [string]$name
            )

            If( $name -notmatch '(?=^.{4,253}$)(^((?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}$)' )
            {
                Write-Verbose 'Unable to determine domain name'
                return 'placeholder.domain'
            }
            else
            {
                while($name -match '\.')
                {
                    $result = [System.IntPtr]::Zero
                    $ret = $Dnsapi::DnsQuery($name, 2, 0, [ref]$pExtra, [ref]$result, 0)

                    if($ret -eq 0)
                    {
                        $rec = [System.Runtime.InteropServices.Marshal]::PtrToStructure($result, [System.Type]([DNS_RECORD]))
                        [void]$Dnsapi::DnsRecordListFree([System.IntPtr]::Zero, 0)

                        if($rec.wType -eq 2)
                        {
                            return $name
                        }
                        else
                        {
                            $name = $name.Substring($name.IndexOf('.')).trim('.')
                        }
                    }
                    else
                    {
                        $name = $name.Substring($name.IndexOf('.')).trim('.')
                    }
                }

                Write-Verbose "$name not a valid domain"
                return 'placeholder.domain'
            }
        }
    }

    PROCESS
    {
        $lpstrName = $null

        if($RecordType -eq 'PTR') #If PTR, modify the target name to in-addr arpa syntax
        {
            $array = $Target.Split('.')
            [array]::Reverse($array)

            foreach($i in $array)
            {
                $lpstrName += "$i."
            }

            $lpstrName += 'in-addr.arpa'
        }
        else
        {
            $lpstrName = $Target
        }

        $ppQueryResultsSet = [System.IntPtr]::Zero
        $pReserved = 0

        $message = "Enumerating $RecordType record"
        LogEvent -source $target -command $CmdName -severity Info -Event $message -ToFile -ToConsole

        $ret = $Dnsapi::DnsQuery($lpstrName, $wType, $Options, [ref]$pExtra, [ref]$ppQueryResultsSet, $pReserved)
            
        LogEvent -source $target -command $CmdName -Event $ret -Native -ToFile -ToConsole

        if($ret -eq 0)
        {
            for ($curPtr = $ppQueryResultsSet; !$curPtr.Equals([System.IntPtr]::Zero); $curPtr = $rec.pNext)
            {
                $obj = New-Object psobject -Property @{
                    Name = $target
                    Type = $null
                    Data = $null
                } |Select-Object Name,Type,Data

                $rec = [System.Runtime.InteropServices.Marshal]::PtrToStructure($curPtr, [System.Type]([DNS_RECORD])) #Casting current buffer to DNS_RECORD structure

                #Parsing results based on record type
                switch ($rec)
                {
                    { $_.wType -eq [DNSRecordTypes]::DNS_TYPE_A -as [int] }     { $obj.Type = 'A'; $obj.Data = ($rec.Data.A.IpAddress -as [ipaddress]).IPAddressToString; break }
                    { $_.wType -eq [DNSRecordTypes]::DNS_TYPE_NS -as [int] }    { $obj.Type = 'NS'; $obj.Data = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($rec.Data.PTR.pNameHost); break }
                    { $_.wType -eq [DNSRecordTypes]::DNS_TYPE_CNAME -as [int] } { $obj.Type = 'CNAME'; $obj.Data = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($rec.Data.PTR.pNameHost); break }
                    { $_.wType -eq [DNSRecordTypes]::DNS_TYPE_PTR -as [int] }   { $obj.Type = 'PTR'; $obj.Data = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($rec.Data.PTR.pNameHost); break }
                    { $_.wType -eq [DNSRecordTypes]::DNS_TYPE_MX -as [int] }    { $obj.Type = 'MX'; $obj.Data = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($rec.Data.MX.pNameExchange); break }
                    #Default { Write-Error "Unhandled record type: $($rec.wType)"; Return }
                }

                if($rec.wType -eq [DNSRecordTypes]::DNS_TYPE_AAAA -as [int])
                {
                    $obj.Type = 'AAAA';

                    $byte = New-Object Byte[] 16
                    $byte[0] = [byte]($rec.Data.AAAA.Ip6Address0 -band 0x000000FF)
                    $byte[1] = [byte](($rec.Data.AAAA.Ip6Address0 -band 0x0000FF00) -shr 8)
                    $byte[2] = [byte](($rec.Data.AAAA.Ip6Address0 -band 0x00FF0000) -shr 16)
                    $byte[3] = [byte](($rec.Data.AAAA.Ip6Address0 -band 0xFF000000) -shr 24)
                    $byte[4] = [byte](($rec.Data.AAAA.Ip6Address1 -band 0x000000FF))
                    $byte[5] = [byte](($rec.Data.AAAA.Ip6Address1 -band 0x0000FF00) -shr 8)
                    $byte[6] = [byte](($rec.Data.AAAA.Ip6Address1 -band 0x00FF0000) -shr 16)
                    $byte[7] = [byte](($rec.Data.AAAA.Ip6Address1 -band 0xFF000000) -shr 24)
                    $byte[8] = [byte](($rec.Data.AAAA.Ip6Address2 -band 0x000000FF))
                    $byte[9] = [byte](($rec.Data.AAAA.Ip6Address2 -band 0x0000FF00) -shr 8)
                    $byte[10] = [byte](($rec.Data.AAAA.Ip6Address2 -band 0x00FF0000) -shr 16)
                    $byte[11] = [byte](($rec.Data.AAAA.Ip6Address2 -band 0xFF000000) -shr 24)
                    $byte[12] = [byte](($rec.Data.AAAA.Ip6Address3 -band 0x000000FF))
                    $byte[13] = [byte](($rec.Data.AAAA.Ip6Address3 -band 0x0000FF00) -shr 8)
                    $byte[14] = [byte](($rec.Data.AAAA.Ip6Address3 -band 0x00FF0000) -shr 16)
                    $byte[15] = [byte](($rec.Data.AAAA.Ip6Address3 -band 0xFF000000) -shr 24)

                    $obj.Data = ($byte -as [ipaddress]).IPAddressToString
                }

                if($rec.wType -eq [DNSRecordTypes]::DNS_TYPE_SOA -as [int])
                {
                    $obj.Type = 'SOA';
                    
                    $nssrv   = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($rec.Data.SOA.pNamePrimaryServer)
                    $admin   = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($rec.Data.SOA.pNameAdministrator)
                    $serial  = $rec.Data.SOA.dwSerialNo
                    $refresh = $rec.Data.SOA.dwRefresh
                    $retry   = $rec.Data.SOA.dwRetry
                    $expire  = $rec.Data.SOA.dwExpire
                    $ttl     = $rec.Data.SOA.dwDefaultTtl

                    $obj.Data = "$nssrv $admin $serial $refresh $retry $expire $ttl"
                }

                #Determining parent domain for record
                if( $rec.wType -eq [DNSRecordTypes]::DNS_TYPE_PTR -as [int])
                {
                    $parent = $lpstrName.Substring($lpstrName.IndexOf('.')).trim('.')
                }
                else
                {
                    $parent = GetParentDomain $Target
                }

                #Checks if record part of answer section, and if so, adds the records to the results
                if(($rec.Flags.S.data -band 0x3) -eq 1)
                {
                    if(! $DontFeedObject)
                    {
                        $domain = Get-DNSDomainObject $parent

                        if(! $domain.RecordExist($Target,$obj.type,$obj.data))
                        {
                            [void]($domain.Records.Add($obj))
                        }
                    }

                    [void]($Results.Add($obj))
                }

                #If CNAME, update target varialbe to "CNAME Data" so that parent domain for next record is correct
                if($rec.wType -eq [DNSRecordTypes]::DNS_TYPE_CNAME -as [int])
                {
                    $Target = $obj.Data
                }

                #If SOA, populate the SOA property of the associated domain object
                if($rec.wType -eq [DNSRecordTypes]::DNS_TYPE_SOA -as [int])
                {
                    $domain = Get-DNSDomainObject $parent

                    $domain.SOA = [ordered]@{
                        PrimaryDNS  = $nssrv
                        DomainAdmin = $admin
                        Serial      = $serial
                        Refresh     = $refresh
                        Retry       = $retry
                        Expire      = $expire
                        TTL         = $ttl
                    }
                }
            }

            [void]$Dnsapi::DnsRecordListFree([System.IntPtr]::Zero, 0)
        }
    }

    END
    {
        Write-Output $Results
    }
}