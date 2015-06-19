<#
 
.SYNOPSIS
A WHOIS client that supports queries for domain names and IP addresses.
 
.DESCRIPTION
This tool queries WHOIS databases on the Internet for information registered on a specified domain name or IP address. It automatically selects the most appropriate WHOIS server on the Internet based on the query that is issued. The selection is based on the same list of domain and network delegation data that is part of the WHOIS Linux client (version 5.2.4) created by Marco Marco d'Itri. The client also queries RWHOIS servers that are returned in the results data (applicable when querying ARIN). This function was inspired by the "WHOIS Powershell client" by Joel Bennett.

The tool outputs the registrar data found for each network or domain. If TDLSearch is enabled, the tool also outputs the results in $NMEVars.HomeDir\data\WHOIS-QueryWHOIS\tdlsearch.log. In addition, the tool outputs Network and DNSDomain objects when all processing has been completed. In the case of networks, if the data returned by the WHOIS/RWHOIS servers contain multiple matching CIDRs, the tool will create a network object for the most specific CIDR (smallest network).

.PARAMETER Target
The target to query, specified as a single IP address or domain name (FQDN). The tool also supports multiple IP addresses or domain names by means of objects (computer, network or domain) coming through the pipeline.

.PARAMETER WHOISServer
Hostname or IP address of a WHOIS server to explicitly query. By default, a suitable server is automatically selected based on the address in the query.

.PARAMETER TLDSearch
Queries all known WHOIS servers for all TLDs (top-level domains) for a domain that matches the string. For example, if the string "foobar" is supplied, the tool will generate queries for "foobar.<tld>" and send them to the specific WHOIS server that is responsible for that domain. The raw results will be saved to a separate log file.

.PARAMETER DownloadDelegations
Downloads WHOIS server delegation data from Marco d'Itris whois client on github and stores it in the $NMEVars.HomeDir\config directory.

.PARAMETER DontFeedObject
Prevents the creation of Network and DNSDomain objects.

.EXAMPLE
NME-WHOIS-QueryWHOIS -Target google.com

.EXAMPLE
NME-WHOIS-QueryWHOIS -Target 8.8.8.8

.EXAMPLE
<objects>|?{$_.DomainName -like "foobar.*"}|NME-WHOIS-QueryWHOIS

.EXAMPLE
NME-WHOIS-QueryWHOIS -TLDSearch foobar

.NOTES

Module dependencies
-------------------
- Environment: HelperFunctions, CreateObjects


Data update policy
------------------
Replaces "RIR" property data for existing object.

.LINK
WHOIS protocol information:
- http://en.wikipedia.org/wiki/Whois

WHOIS client by Marco d'Itri:
https://github.com/rfc1036/whois

#>

Function Invoke-WHOISQuery
{
    [CmdletBinding()]
    param
    (
        [Parameter(ValueFromPipelineByPropertyName, Mandatory, ParameterSetName = 'Query' )]
        [Alias('DomainName','CIDR','IPAddress')]
        [string]$Target,

        [Parameter(ParameterSetName = 'Query')]
        [string]$WHOISServer,

        [Parameter(ParameterSetName = 'Query')]
        [string]$TLDSearch,

        [Parameter(Mandatory,ParameterSetName = 'Download')]
        [switch]$DownloadDelegations,

        [Parameter(ParameterSetName = 'Query')]
        [switch]$DontFeedObject
    )

    BEGIN
    {
        #Default functions/variables
        $CmdName = 'Invoke-WHOISQuery'
        $CmdAlias = 'NME-WHOIS-QueryWHOIS'
        $ObjectResults = @()

        #Script-specific
        if($DownloadDelegations)
        {
            $message = 'Downloading whois server delegations data'
            LogEvent -Command $CmdName -Severity Info -Event $message -Tofile -Toconsole

            try
            {
                Invoke-WebRequest https://raw.githubusercontent.com/rfc1036/whois/next/tld_serv_list -OutFile "$($NMEVars.HomeDir)\config\QueryWHOIS_tld_serv_list.txt"
                Invoke-WebRequest https://raw.githubusercontent.com/rfc1036/whois/next/new_gtlds_list -OutFile "$($NMEVars.HomeDir)\config\QueryWHOIS_new_gtlds_list.txt"
                Invoke-WebRequest https://raw.githubusercontent.com/rfc1036/whois/next/ip_del_list -OutFile "$($NMEVars.HomeDir)\config\QueryWHOIS_ip_del_list.txt"
                Invoke-WebRequest https://raw.githubusercontent.com/rfc1036/whois/next/ip6_del_list -OutFile "$($NMEVars.HomeDir)\config\QueryWHOIS_ip6_del_list.txt"

                $message = 'Download completed'
                LogEvent -Command $CmdName -Severity Info -Event $message -ToFile -ToConsole
            }
            catch
            {
                $message = $_
                LogEvent -Command $CmdName -Severity Info -Event $message -ToFile -ToConsole
            }
            
            break
        }

        if($TLDSearch)
        {
            if(! (Test-Path "$($NMEVars.HomeDir)\data\WHOIS-QueryWHOIS"))
            {
                [void](New-Item "$($NMEVars.HomeDir)\data\WHOIS-QueryWHOIS" -ItemType Directory)
                [void](New-Item "$($NMEVars.HomeDir)\data\WHOIS-QueryWHOIS\tldsearch.log" -ItemType File)
            }
        }

        if(! ((Test-Path "$($NMEVars.HomeDir)\config\QueryWHOIS_tld_serv_list.txt") -and
              (Test-Path "$($NMEVars.HomeDir)\config\QueryWHOIS_new_gtlds_list.txt") -and 
              (Test-Path "$($NMEVars.HomeDir)\config\QueryWHOIS_ip_del_list.txt") -and
              (Test-Path "$($NMEVars.HomeDir)\config\QueryWHOIS_ip6_del_list.txt")) )
        {
            $message = 'Delegations data missing - download them using the -DownloadDelegations parameter and try again'
            LogEvent -Command $CmdName -Severity Err -Event $message -Tofile -Toconsole

            break
        }

        Write-Verbose 'Importing whois server delegations data'
        $tdls = Get-Content "$($NMEVars.HomeDir)\config\QueryWHOIS_tld_serv_list.txt" |? {$_ -notmatch '^#' -and $_ -notmatch '^$'}
        $tdls += Get-Content "$($NMEVars.HomeDir)\config\QueryWHOIS_new_gtlds_list.txt" |? {$_ -notmatch '^#' -and $_ -notmatch '^$'}
        $ipv4 = Get-Content "$($NMEVars.HomeDir)\config\QueryWHOIS_ip_del_list.txt" |? {$_ -notmatch '^#' -and $_ -notmatch '^$'}
        $ipv6 = Get-Content "$($NMEVars.HomeDir)\config\QueryWHOIS_ip6_del_list.txt" |? {$_ -notmatch '^#' -and $_ -notmatch '^$'}

        Write-Verbose 'Creating hashtables for delegation lookups'
        $tdlLookup = [ordered]@{}
        $ipv4Lookup = [ordered]@{}
        $ipv6Lookup = [ordered]@{}
        
        foreach($i in $tdls)
        {
            $split = ($i -split '#')[0]
            $split = $split -split '[\t ]'

            $key = ($split[0] |Out-String).Trim()
            $val = (($split -match '(?=^.{4,253}$)(^((?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}$)')|Out-String).Trim() #Match FQDN

            switch ($i)
            {
                {$_ -cmatch 'NONE'}    {$val = "NONE"; continue}
                {$_ -cmatch 'ARPA'}    {$val = "ARPA"; continue}
                {$_ -cmatch 'WEB'}     {$val = "WEB " + (($_ -split "WEB")[1]).Trim(); continue}
                {$_ -cmatch 'AFILIAS'} {$val = 'whois.afilias-grs.info'; continue}
                {$_ -notmatch '[\t ]'} {$key = ".$_"; $val = "whois.nic.$_"; continue}
                Default {}
            }

            $tdlLookup.Add($key,$val)
        }

        foreach($i in $ipv4)
        {
            $split = ($i -split '#')[0]
            $split = $split -split '[\t ]'

            $key = ($split[0] |Out-String).Trim()
            $val = (($split -match '(^(ripe|arin|apnic|afrinic|lacnic|twnic|unknown)$)|((?=^.{4,253}$)(^((?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}$))')|Out-String).Trim() #Match RIR name or FQDN (of whois server)

            switch ($val)
            {
                'ripe'    {$val = 'whois.ripe.net'; break}
                'arin'    {$val = 'whois.arin.net'; break}
                'apnic'   {$val = 'whois.apnic.net'; break}
                'afrinic' {$val = 'whois.afrinic.net'; break}
                'lacnic'  {$val = 'whois.lacnic.net'; break}
                'twnic'   {$val = 'whois.twnic.net'; break}
                Default {}
            }

            $ipv4Lookup.Add($key,$val)
        }

        foreach($i in $ipv6)
        {
            $split = ($i -split '#')[0]
            $split = $split -split '[\t ]'

            $key = ($split[0] |Out-String).Trim()
            $val = (($split -match '(^(ripe|arin|apnic|afrinic|lacnic|twnic|unknown)$)|((?=^.{4,253}$)(^((?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}$))')|Out-String).Trim() #Match RIR name or FQDN (of whois server)

            switch ($val)
            {
                'ripe'    {$val = 'whois.ripe.net'; break}
                'arin'    {$val = 'whois.arin.net'; break}
                'apnic'   {$val = 'whois.apnic.net'; break}
                'afrinic' {$val = 'whois.afrinic.net'; break}
                'lacnic'  {$val = 'whois.lacnic.net'; break}
                'twnic'   {$val = 'whois.twnic.net'; break}
                Default {}
            }

            $ipv6Lookup.Add($key,$val)
        }

        #Helper functions
        Function GetWhoisServer
        {
            Param
            (
                [string]$query
            )

            if(($query -as [ipaddress]).AddressFamily -eq 'InterNetwork')
            {
                foreach($i in $ipv4Lookup.GetEnumerator())
                {
                    if(IPHelper -IsMember -IPAddress $query -CIDR $i.key)
                    {
                        Return $i.value
                    }
                }
            }
            elseif(($query -as [ipaddress]).AddressFamily -eq 'InterNetworkV6')
            {
                foreach($i in $ipv6Lookup.GetEnumerator())
                {
                    if(IPHelper -IsMember -IPAddress $query -CIDR $i.key)
                    {
                        Return $i.value
                    }
                }
            }
            else
            {
                foreach($i in $tdlLookup.GetEnumerator())
                {
                    if($query -like ("*"+"$($i.key)"))
                    {
                        Return $i.value
                    }
                }
            }
        }

        Function QueryWhoisServer
        {
            Param
            (
                [string]$server,
                [int]$port,
                [string]$target
            )

            try
            {
                $message = "Connecting to $Server"
                LogEvent -Command $CmdName -Severity Info -Event $message -Tofile -Toconsole

                $client = New-Object System.Net.Sockets.TcpClient $server, $port

                $stream = $client.GetStream()

                if($target -as [ipaddress])
                {
                    switch($server)
                    {
                        'whois.arin.net'         {$query = "n + $Target`r`n"; break}
                        'whois.nic.ad.jp'        {$query = "$Target/e`r`n"; break}
                        Default                  {$query = "$Target`r`n"}
                    }
                }
                else
                {
                    switch($server)
                    {
                        'whois.verisign-grs.com' {$query = "=$Target`r`n"; break}
                        'whois.denic.de'         {$query = "-T dn,ace $Target`r`n"; break}
                        'whois.jprs.jp'          {$query = "$Target/e`r`n"; break}
                        Default                  {$query = "$Target`r`n"}
                    }
                }

                $data = [System.Text.Encoding]::Ascii.GetBytes($query)

                $message = "Obtaining data for `'$target`'"
                LogEvent -Source $server -Command $CmdName -Severity Info -Event $message -Tofile -Toconsole

                $stream.Write($data, 0, $data.Length)

                Write-Verbose "Reading response"
                $reader = New-Object System.IO.StreamReader $stream, [System.Text.Encoding]::ASCII
                $reader.BaseStream.ReadTimeout = 30000 #Setting a read timeout of 30 seconds to avoid hangs...

                $result = $reader.ReadToEnd()
                return $result
            }
            catch
            {
                return $_.Exception.InnerException.Message
            }
            finally
            {
                if($stream)
                {
                    $stream.Close()
                    $stream.Dispose()
                }
            }
        }

        Function PromptDomain
        {
            Write-Host -ForegroundColor DarkYellow "[@] According to whois data, `'$Target`' does not exist. Do you still want to create a domain object?"
            do { $prompt = Read-Host 'Y|N' } until ($prompt -eq 'n' -or $prompt -eq 'y')
        
            if($prompt -eq 'n')
            {
                return $false
            }
        }
    }

    PROCESS
    {
        if($Target.GetEnumerator() -contains '/') #If target is CIDR, extracts the network IP
        {
            $Target = ($Target -split '/')[0]
        }

        if(!$WHOISServer -and !$TLDSearch)
        {
            Write-Verbose "Obtaining WHOIS server for $Target"
            $WHOISServer = GetWhoisServer -query $Target

            switch($WHOISServer)
            {
                {$WHOISServer -match "WEB"} {$event = "No whois server found for `"$Target`" (Web-based service available at$(($WHOISServer -split "WEB")[1]))"; LogEvent -Command $CmdName -Severity Err -Event $message -Tofile -Toconsole; return}
                {$WHOISServer -eq "NONE"}   {$event = "No whois server found for `"$Target`""; LogEvent -Command $CmdName -Severity Err -Event $message -Tofile -Toconsole; return}
                {$WHOISServer -eq "ARPA"}   {$event = "No whois server found for `"$Target`""; LogEvent -Command $CmdName -Severity Err -Event $message -Tofile -Toconsole; return}
                {!$WHOISServer}             {$event = "No whois server found for `"$Target`""; LogEvent -Command $CmdName -Severity Err -Event $message -Tofile -Toconsole; return}
            }
        }

        if($Target -as [ipaddress])
        {
            $RawResults = QueryWhoisServer -server $WHOISServer -port 43 -target $Target

            if($RawResults -match '(?<=ReferralServer: ).*') #Do additional query against referral (rwhois) server, if found in the results data
            {
                $refSrv = $Matches.0

                $refPort = ($refSrv -split ":")[2]

                if(! $refPort)
                {
                    $refPort = 43
                }

                $refAddr = ((($refSrv -split "//")[1]) -split ":")[0]

                $RawResults += QueryWhoisServer -server $refAddr -port $refPort -target $Target
            }

            #The following code extract network CIDR from the RIR-specific results data

            if($RawResults -match 'inetnum:') #Matches results from ripe,apnic,afrinic (ipv4) and lacnic (ipv4 and 6)
            {
                if($RawResults -match 'Joint Whois - whois.lacnic.net') #Matches lacnic only
                {
                    $cidr = (([regex]'(?<=inetnum:).*').Match($RawResults).Value).TrimStart()
                    $ip = $cidr.split('/')[0]
                    $mask = $cidr.split('/')[1]

                    if(! (($ip -as [ipaddress]).AddressFamily -eq 'InterNetworkV6'))
                    {
                        while($ip.Split('.').count -ne 4)
                        {
                            $ip = $ip + ".0"
                        }

                        $cidr = $ip + "/$mask"
                    }
                }
                else
                {
                    $netrange = (([regex]'(?<=inetnum:).*').Match($RawResults).Value).TrimStart()
                    $cidr = IPHelper -RangeToCIDR -IPRange $netrange
                }
            }
            elseif($RawResults -match 'inet6num:') #Matches ripe,apnic,afrinic (ipv6)
            {
                $cidr = (([regex]'(?<=inet6num:).*').Match($RawResults).Value).TrimStart()
            }
            elseif($RawResults -match 'CIDR:') #Matches arin (ipv4 and 6) and referral servers(ipv4 and 6)
            {
                if($RawResults -notmatch 'Joint Whois - whois.lacnic.net') #Excludes lacnic data
                {
                    if($RawResults -match 'network:IP-Network:') #If results are returned from rwhois, assuming that is most specific
                    {
                        $cidr = ([regex]'(?<=network:IP-Network:).*').Matches($RawResults).Value

                        if($cidr.count -gt 1) #Selects most specific match, if multiple matches are returned
                        {
                            $MostSpecific = $cidr[0]

                            foreach($i in $cidr[1..($cidr.count -1)])
                            {
                                if(($i -split '/')[1] -gt ($MostSpecific -split '/')[1])
                                {
                                    $MostSpecific = $i
                                }
                            }

                            $cidr = $MostSpecific
                        }
                    }
                    else
                    {
                        $cidr = (([regex]'(?<=CIDR:).*').Matches($RawResults).Value).TrimStart()

                        if($cidr.count -gt 1) #Selects most specific match, if multiple matches are returned
                        {
                            $MostSpecific = $cidr[0]

                            foreach($i in $cidr[1..($cidr.count -1)])
                            {
                                if(($i -split '/')[1] -gt ($MostSpecific -split '/')[1])
                                {
                                    $MostSpecific = $i
                                }
                            }

                            $cidr = $MostSpecific
                        }
                    }
                }
            }
            elseif($RawResults -match 'IPv[46] Address') #Matches whois.nic.or.kr (ipv4 and 6)
            {
                $cidr = ((((([regex]'(?<=IPv4 Address).*').Match($RawResults).Value).TrimStart(' ,:') -split ' ')[0,3]) -join '') -replace '\(','' -replace '\)',''

                if(! $cidr) #If no ipv4 match, try ipv6
                {
                    $cidr6 = (([regex]'(?<=IPv6 Address).*').Match($RawResults).Value).TrimStart(' ,:')
                }
            }
            elseif($RawResults -match '\[Network Number\]') #Matches whois.nic.ad.jp (ipv4)
            {
                $netrange = (([regex]'(?<=\[Network Number\]).*').Match($RawResults).Value).TrimStart()
                $cidr = IPHelper -RangeToCIDR -IPRange $netrange
            }
            else #Catch-all to highlight when CIDR could not be extracted
            {
                Write-Host $RawResults
                Write-Warning 'Unable to find CIDR value!'

                return
            }

            if(! $DontFeedObject)
            {
                if($cidr -match ',') #If results contain multiple comma-separated CIDR on same line
                {
                    $cidrArray = ($cidr -split ',').TrimStart()

                    foreach($i in $cidrArray) #Create a network object based on the most specific CIDR
                    {
                        if(IPHelper -IsMember -IPAddress $Target -CIDR $i)
                        {
                            $netObj = Get-NetworkObject $i
                            $netObj.RIR = $RawResults
                            
                            break
                        }
                    }
                }
                else
                {
                    $netObj = Get-NetworkObject $cidr
                    $netObj.RIR = $RawResults
                }
            }

            $ObjectResults += $netObj

            Write-Host $RawResults
        }
        elseif($TLDSearch) #Experimental...
        {
            foreach($i in $tdlLookup.GetEnumerator()|?{$_.value -cnotmatch 'WEB|NONE|ARPA'})
            {
                $Target = $Name + $i.key
                $WHOISServer = $i.value

                $RawResults = QueryWhoisServer -server $WHOISServer -port 43 -target $Target
                $RawResults |Out-File "$($NMEVars.HomeDir)\data\WHOIS-QueryWHOIS\tldsearch.log" -Append
            }
        }
        else
        {
            $RawResults = QueryWhoisServer -server $WHOISServer -port 43 -target $Target

            Write-Host $RawResults

            switch($RawResults) #Regexes to detect non-existant domains (to be improved...)
            {
                {$_ -match 'not? found'}                    {if(PromptDomain){break} else{return}}
                {$_ -match '(?<!indicating )no match'}      {if(PromptDomain){break} else{return}}
                {$_ -match 'no entries found'}              {if(PromptDomain){break} else{return}}
                {$_ -match 'not (been )?registe?red'}       {if(PromptDomain){break} else{return}}
                {$_ -match 'no objects? found'}             {if(PromptDomain){break} else{return}}
                {$_ -match 'no data found'}                 {if(PromptDomain){break} else{return}}
                {$_ -match "`"?$target`"? is available"}    {if(PromptDomain){break} else{return}}
                {$_ -match 'status:[\t ]*(available|free)'} {if(PromptDomain){break} else{return}}
                {$_ -match 'cannot be found'}               {if(PromptDomain){break} else{return}}
                {$_ -match 'no such domain'}                {if(PromptDomain){break} else{return}}
                {$_ -match 'is available for purchase'}     {if(PromptDomain){break} else{return}}
                {$_ -match 'invalid (query|domain)'}        {if(PromptDomain){break} else{return}}
                {$_ -match 'nothing found'}                 {if(PromptDomain){break} else{return}}
                {$_ -match "$target is free"}               {if(PromptDomain){break} else{return}}
                {$_ -match 'no records matching'}           {if(PromptDomain){break} else{return}}
                {$_ -match 'does not exist'}                {if(PromptDomain){break} else{return}}
                {$_ -match 'available for purchase'}        {if(PromptDomain){break} else{return}}
            }

            $domainObj = Get-DNSDomainObject $Target
            $domainObj.RIR = $RawResults

            $ObjectResults += $domainObj
        }
    }

    END
    {
        Write-Output $ObjectResults |Select-Object -Property * -ExcludeProperty RIR
    }
}