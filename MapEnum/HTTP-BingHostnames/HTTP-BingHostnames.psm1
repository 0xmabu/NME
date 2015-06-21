<#
 
.SYNOPSIS
Queries Bing to identify hostnames for a given domain name or IP address.
 
.DESCRIPTION
This tool make use of the Bing search API to extract hostnames that are indexed in the Bing search engine database. It does so by issuing search queries (QueryType) for either domain names (Domain) or IP address (IPAddress). Use of this module requires a Bing account key.

When doing a Domain search, the module issues the initial query "site:example.com" and then appends any identified hosts (the left-most part of the FQDN in each search results) as exlusions in each subsequent search query. FIt continues to do so in subsequent queries until no new hostnames are found.

When doing an IP search, the module issues a query with the IP address operator, appending the provided IP address (e.g, the IP Address 1.2.3.4 will yield the search string "IP:1.2.3.4"). Bing will respond to the query with a list of indexed hostnames that correspond to the given IP address.

The number of hostnames returned in either QueryType is currently limited to 50, which is the maximium number of search results returned by Bing in a single query.

The tool outputs objects with "Query" (IP address or domain name) and "HostName" information.

.PARAMETER Domain
The target domain, specified as a single FQDN. The tool also supports multiple domain names by means of DNSDomain objects coming through the pipeline.

.PARAMETER IPAddress
The targeted IP address. The tool also supports multiple IP addresses by means of Computer objects coming through the pipeline.

.PARAMETER FeedDNS
Passes identified names to the Invoke-DNSQuery module, for hostname verification and for saving the results to the corresponding DNSDomain object.

.EXAMPLE
NME-HTTP-BingHostnames -Domain example.com

.EXAMPLE
NME-HTTP-BingHostnames -IPAddress 1.2.3.4

.EXAMPLE
<Objects> | NME-HTTP-BingHostnames

.NOTES

Module dependencies
-------------------
- Environment: HelperFunctions
- MapEnum: Invoke-DNSQuery

.LINK

http://datamarket.azure.com/dataset/bing/search

#>

Function Invoke-BingHostnames
{
    Param
    (
        [Parameter(ValueFromPipelineByPropertyName,Mandatory,ParameterSetName = 'FQDN')]
        [Alias("DomainName")]
        [string]$Domain,

        [Parameter(ValueFromPipelineByPropertyName,Mandatory,ParameterSetName = 'IP')]
        [string]$IPAddress,

        [Parameter(ParameterSetName = 'FQDN')]
        [Parameter(ParameterSetName = 'IP')]
        [switch]$FeedDNS
    )

    BEGIN
    {
        #Default functions/variables
        $CmdName = 'Invoke-BingHostnames'
        $CmdAlias = 'NME-HTTP-BingHostnames'
        $Results = @()

        # Module-specific functions/variables
        Add-Type -Assembly System.Web
        
        if(Test-Path "$($NMEVars.HomeDir)\config\bing_apikey.txt")
        {
            $apikey = Get-Content "$($NMEVars.HomeDir)\config\bing_apikey.txt"
            $pwd = convertto-securestring -String $apikey -AsPlainText -Force
            $user = "bing"
            $cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $user, $pwd
        }
        else
        {
            $message = 'Bing search API key not found'
            LogEvent -command $CmdName -severity Err -Event $message -ToConsole

            break
        }
    }

    PROCESS
    {
        $hostnames = @()

        if($IPAddress)
        {
            $result = $null
            $Target = $IPAddress

            #Constructing query string
            $query = [web.httputility]::UrlEncode("'IP:"+($Target)+"'")
            $search = "https://api.datamarket.azure.com/Bing/SearchWeb/Web?Query=${query}&`$top=50"

            try
            {
                $message = 'Conducting Bing hostname search (IP)'
                LogEvent -source $Target -command $CmdName -severity Info -Event $message -ToFile -ToConsole

                [xml]$result = Invoke-WebRequest -Credential $cred -Uri $search #Querying Bing

                if($result.feed.entry) #Parsing results
                {
                    $hostnames = @($result.feed.entry.content.properties.url."#text" |%{($_ -split ('/'))[2]})|select -Unique #Extracting unique hostnames
                }
            }
            catch
            {
                $message = $_.Exception.Message
                LogEvent -source $Target -command $CmdName -severity Err -Event $message -ToFile -ToConsole
            }
        }

        if($Domain)
        {
            $result = $null
            $Target = $Domain

            try
            {
                $message = 'Conducting Bing hostname search (Domain)'
                LogEvent -source $Target -command $CmdName -severity Info -Event $message -ToFile -ToConsole

                do {
                    if (!$result) #Setting initial search values
                    {
                        $qstr = $Target
                        $last = $qstr
                    }
                    else #Parsing results
                    {
                        $fqdn = @(foreach ($i in $result.feed.entry){((($i.content.properties.url.'#text') -split "/")[2])}) |Select -Unique #Exctacting subdomains/hostnames from query results
                        $hostnames += @($fqdn)

                        $equal = @(Compare-Object $fqdn $last -SyncWindow 0).Length -eq 0 #Checks if current results collection is identical to last
                                
                        if($equal -eq $true) #Breaks do-while-loop if search results are identical (assuming that no more search hits are available)
                        {
                            break
                        }

                        $last = $fqdn

                        foreach($i in $fqdn) #Building new search string with search exclusions (e.g "-www") based on leftmost part of identified fqdns
                        {
                            if($i -ne $Target)
                            {
                                $_i = ($i -split "\.")[0]

                                if ($qstr -notmatch "-$_i\b")
                                {
                                    $qstr += "{0}{1}" -f " -",$_i
                                }
                            }
                        }
                    }

                    #Building query string
                    $query = [web.httputility]::UrlEncode("'SITE:"+$qstr+"'")
                    $search = "https://api.datamarket.azure.com/Bing/SearchWeb/Web?Query=${query}&`$top=50"
                            
                    Write-Verbose 'Sending search query...'

                    [xml]$result = Invoke-WebRequest -Credential $cred -Uri $search #Querying Bing

                } while ($result.feed.entry)
            }
            catch
            {
                $message = $_.Exception.Message
                LogEvent -source $Target -command $CmdName -severity Err -Event $message -ToFile -ToConsole
            }
        }

        $hostnames = ($hostnames |?{$_ -ne $Target})|select -Unique #Compiling list of unique hostnames, exluding the initial query domain

        if($hostnames.Count -gt 0)
        {
            $message = 'Hostnames found'
            LogEvent -source $Target -command $CmdName -severity Succ -Event $message -ToFile -ToConsole

            foreach($i in $hostnames)
            {
                $nameObj = New-Object psobject -Property @{
                    Query    = $Target
                    HostName = $i
                } |Select Query,HostName

                $Results += $nameObj
            }

            if($FeedDNS)
            {
                $message = 'Saving results to DNS'
                LogEvent -source $Target -command $CmdName -severity Info -Event $message -ToFile -ToConsole
                
                [void]($Results |Invoke-DNSQuery -RecordType A) #Assuming that results are A records
            }
        }
        else
        {
            $message = 'No hostnames found'
            LogEvent -source $Target -command $CmdName -severity Info -Event $message -ToFile -ToConsole
        }
    }

    END
    {
        Write-Output $Results
    }
}