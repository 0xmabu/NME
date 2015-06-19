$ip = "127.0.0.1"

#NetUseAdd
$paramErrorIndex = $null
$unc = "`\`\$ip`\ipc$"

$useInfo = New-Object ([NativeTestPasswords+USE_INFO_2]) -Property @{
    ui2_local      = $null
    ui2_remote     = $unc
    ui2_password   = $null
    ui2_asg_type   = 3
    ui2_usecount   = 1
    ui2_username   = $null
    ui2_domainname = $null
}

[void]([NativeTestPasswords]::NetUseAdd($null, 2, [ref]$useInfo, [ref]$paramErrorIndex))
[void]([NativeTestPasswords]::NetUseDel($null, "\\127.0.0.1\ipc$", 2))

#NetUserEnum
$level = 3
$filter = 0
$bufptr = [intPtr]::Zero
$prefmaxlen = -1
$entriesread = 0
$totalentries = 0
$resume_handle = 0

[void]$Netapi32::NetUserEnum($ip,$level,$filter,[ref]$bufptr,$prefmaxlen,[ref]$entriesread,[ref]$totalentries,[ref]$resume_handle)
[void]$Netapi32::NetApiBufferFree($bufptr)

#NetShareEnum
$level = 1
$bufptr = [intPtr]::Zero
$prefmaxlen = -1
$entriesread = 0
$totalentries = 0
$resume_handle = 0

[void]$Netapi32::NetShareEnum($ip,$level,[ref]$bufptr,$prefmaxlen,[ref]$entriesread,[ref]$totalentries,[ref]$resume_handle)
[void]$Netapi32::NetApiBufferFree($bufptr)

#NetUserModalsGet
$bufptr = [intPtr]::Zero

[void]$Netapi32::NetUserModalsGet($ip, 0, [ref]$bufptr)
[void]$Netapi32::NetApiBufferFree($bufptr)

#NetWkstaUserEnum variables
$level = 1
$bufptr = [intPtr]::Zero
$prefmaxlen = -1
$entriesread = 0
$totalentries = 0
$resume_handle = 0

[void]$Netapi32::NetWkstaUserEnum($ip,$level,[ref]$bufptr,$prefmaxlen,[ref]$entriesread,[ref]$totalentries,[ref]$resume_handle)
[void]$Netapi32::NetApiBufferFree($bufptr)

#LookupAccountSid
$s = "S-1-5-21-4151077119-2612160463-1590392273-1011"
$sidObj = [System.Security.Principal.SecurityIdentifier]$s
                    
$bSid = New-Object Byte[] $sidObj.binaryLength
$sidObj.GetBinaryForm($bSid, 0)

$UserName = New-Object System.Text.StringBuilder
$DomainName = New-Object System.Text.StringBuilder
$cchUser = [uint32]$UserName.Capacity
$cchDomain = [uint32]$DomainName.Capacity
$sidType = [SID_NAME_USE]::SidTypeUnknown

[void]([NativeGetLoggedOn]::LookupAccountSid($ip,$bSid,$UserName,[ref]$cchUser,$DomainName,[ref]$cchDomain,[ref]$sidType))
[void]$Netapi32::NetApiBufferFree($bufptr)

#NetLocalGroupEnum
$lg_level = 1
$lg_bufptr = [intPtr]::Zero
$lg_prefmaxlen = -1
$lg_entriesread = 0
$lg_totalentries = 0
$lg_resume_handle = 0

[void]$Netapi32::NetLocalGroupEnum($ip,$lg_level,[ref]$lg_bufptr,$lg_prefmaxlen,[ref]$lg_entriesread,[ref]$lg_totalentries,[ref]$lg_resume_handle)
[void]$Netapi32::NetApiBufferFree($lg_bufptr)

#NetLocalGroupGetMembers
$lgm_group = "administrators"
$lgm_level = 3
$lgm_bufptr = [intPtr]::Zero
$lgm_prefmaxlen = -1
$lgm_entriesread = 0
$lgm_totalentries = 0
$lgm_resume_handle = 0

[void]$Netapi32::NetLocalGroupGetMembers($ip,$lgm_group,$lgm_level,[ref]$lgm_bufptr,$lgm_prefmaxlen,[ref]$lgm_entriesread,[ref]$lgm_totalentries,[ref]$lgm_resume_handle)
[void]$Netapi32::NetApiBufferFree($lgm_bufptr)

#NetGroupEnum
$gg_level = 2
$gg_bufptr = [intPtr]::Zero
$gg_prefmaxlen = -1
$gg_entriesread = 0
$gg_totalentries = 0
$gg_resume_handle = 0

[void]$Netapi32::NetGroupEnum($ip,$gg_level,[ref]$gg_bufptr,$gg_prefmaxlen,[ref]$gg_entriesread,[ref]$gg_totalentries,[ref]$gg_resume_handle)
[void]$Netapi32::NetApiBufferFree($gg_bufptr)

#NetGroupGetUsers
$ggm_group = "administrators"
$ggm_level = 0
$ggm_bufptr = [intPtr]::Zero
$ggm_prefmaxlen = -1
$ggm_entriesread = 0
$ggm_totalentries = 0
$ggm_resume_handle = 0

[void]$Netapi32::NetGroupGetUsers($ip,$ggm_group,$ggm_level,[ref]$ggm_bufptr,$ggm_prefmaxlen,[ref]$ggm_entriesread,[ref]$ggm_totalentries,[ref]$ggm_resume_handle)
[void]$Netapi32::NetApiBufferFree($ggm_bufptr)

#SqlClient
$connection = new-object System.Data.SqlClient.SQLConnection
$connString = "Server=$ip;Integrated Security=True;Connect Timeout=1"
$connection.ConnectionString = $connString           
try{$connection.Open()}catch{}finally{$connection.Close()}