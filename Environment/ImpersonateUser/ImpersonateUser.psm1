<#
 
.SYNOPSIS
Impersonates other user identities.
 
.DESCRIPTION
This tool can be used to impersonate another Windows user when connecting to remote systems. The impersonation is conducted using the LogonUser function exposed in Advapi32. A Username and password is passed to the function and new credentials (type 9, LOGON32_LOGON_NEW_CREDENTIALS) are created. These credentials are then used by powershell when authenticating against remote systems. If no impersonation is conducted with this tool, network authentication will be conducted with the credentials of the user that started powershell.

The tool has rudimentary support for impersonating the anonymous identity. This is not native impersonation of anonymous in itself - rather, it provides a generic way to inform enumeration/testing tools that anonymous impersonation has been requested. This is done by simply setting the $Global:CurrentUser variable to "Anonymous". The variable can then be as a conditional paramteter to implement the anonymous impersonation technique that best fits the tool. Techniques that could be used include calling the Native function ImpersonateAnonymousToken ($Advapi32::ImpersonateAnonymousToken($Kernel32::GetCurrentThread()) before making the network request. If the target endpoints are exposed over SMB only, another way would be to establish a null session to the IPC$ pipe using the NetUseAdd function prior to connecting to the target.

In addition to creating an impersonated environment, the tool also creates a PSCredential object based on the username and password supplied in the impersonation process. This PSCredential object (saved in $Global:CredObj) can be used by tools that supports the PSCredential objects for authentication. The PSCredential object is only applicable for user impersonation (e.g. not anonymous)

.PARAMETER User
The name of the user to be impersonated

.PARAMETER Domain
The name of the domain to which the impersonated user belongs. By default, the domain is set to ".", which is represents the local computer domain.

.PARAMETER Status
This switch parameter returns current impersonation status.

.PARAMETER Revert
This switch parameter ends the any current impersonation and reverts back to the credentials running powershell.

.PARAMETER Anonymous
This switch parameter enables the impersonation of anonymous

.EXAMPLE
NME-ImpersonateUser administrator

.EXAMPLE
NME-ImpersonateUser -User user1 -Domain ad.local

.EXAMPLE
NME-ImpersonateUser -Anonymous

.EXAMPLE
NME-ImpersonateUser -Revert

Dependencies
------------
This tool makes use of Matthew Graebers PSReflect module (PowerSploit framework) to in order to gain access to the Win32 APIs.

The tool make use of the following internal modules / variables:
- Runtime
- HelperFunctions

.NOTES

Issues / Other:
---------------
- Experimentation has been conducted with doing "real" impersonation of anonymous (i.e. ImpersonateAnonymousToken) when setting that option in this tool. Beside causing some issues with file permissions, it also causes some odd behaviour with functions/variables etc that "should" be accessible. Until all these issues has been sorted, the anonymous implementation will be limited to simply setting the $Global:CurrentUser to "Anonymous".
- When impersonating anonymous (using the ImpersonateAnonymousToken function), the both managed and unmanaged functions cannot be initiated unless they have already been loaded by a privileged account. Don't know why this is, but until its been sorted, a quick/dirty script executes (and loads?) all these functions if Anonymous impersonation is invoked by the user...

.LINK
LogonUser (Advapi32):
- https://msdn.microsoft.com/en-us/library/windows/desktop/aa378184%28v=vs.85%29.aspx

ImpersonateAnonymousToken (Advapi32):
- https://msdn.microsoft.com/en-us/library/windows/desktop/aa378610(v=vs.85).aspx

PowerSploit Framework
- https://github.com/mattifestation/PowerSploit

#>

Function Invoke-UserImpersonation
{
    [CmdletBinding()]
    Param
    (
        [Parameter()]
        [string]$User,

        [Parameter()]
        [string]$Domain,

        [Parameter()]
        [switch]$Status,

        [Parameter()]
        [switch]$Revert,

        [Parameter()]
        [switch]$Anonymous
    )

    BEGIN
    {
        #Default functions/variables
        $CmdName = 'Invoke-UserImpersonation'
        $CmdAlias = 'NME-ImpersonateUser'
    }

    PROCESS
    {
        if($Status)
        {
            If (([Security.Principal.WindowsIdentity]::GetCurrent().ImpersonationLevel -eq 'None') -and ($NMEVars.CurrentUser -ne 'ANONYMOUS LOGON'))
            {
                $message = "Currently not impersonating"
                LogEvent -Command $CmdName -severity Info -event $message -ToConsole
            }
            else
            {
                if(! $NMEVars.CurrentUser)
                {
                    $message = 'Currently impersonating but identity could not be determined'
                    LogEvent -Command $CmdName -severity Warn -event $message -ToConsole
                }
                elseif($NMEVars.CurrentUser -eq 'ANONYMOUS LOGON')
                {
                    $message = "Currently running as 'ANONYMOUS LOGON'"
                    LogEvent -Command $CmdName -severity Info -event $message -ToConsole
                }
                else
                {
                    $message = "Currently running as `'$($NMEVars.CurrentUser)`'"
                    LogEvent -Command $CmdName -severity Info -event $message -ToConsole
                }
            }

            break
        }

        if($revert)
        {
            if ($Advapi32::RevertToSelf())
            {
                #$Global:CurrentUser = [Security.Principal.WindowsIdentity]::GetCurrent().Name
                #$NMEVars.CurrentUser = $Global:CurrentUser
                $NMEVars.CurrentUser = [Security.Principal.WindowsIdentity]::GetCurrent().Name
                
                #$Global:CurrentCred = $null
                #$NMEVars.CurrentCred = $Global:CurrentCred
                $NMEVars.CurrentCred = $null
                
                $message = "Reverted back to credentials running powershell"
                LogEvent -Command $CmdName -severity Info -event $message -ToConsole
            }
            else
            {
                $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()

                $message = "A problem was encountered when trying to revert impersonation: $err"
                LogEvent -Command $CmdName -severity Err -event $message -ToConsole
            }

            break
        }

        if ($Anonymous)
        {
            #$Global:CurrentUser = 'ANONYMOUS LOGON'
            #$NMEVars.CurrentUser = $Global:CurrentUser
            $NMEVars.CurrentUser = 'ANONYMOUS LOGON'
            $User = 'ANONYMOUS LOGON'
            $Password = ""

            Write-Verbose 'Pre-loading / running unmanaged functions...'
            & "$($NMEModules.ImpersonateUser)\quick&dirty.ps1"
        }
        else
        {
            if(!$User)
            {
                $message = 'No username provided'
                LogEvent -Command $CmdName -severity Err -event $message -ToConsole

                break
            }

            if($Domain)
            {
                $NMEVars.CurrentUser = "$Domain\$User"
            }
            else
            {
                $NMEVars.CurrentUser = $User
                $Domain = '.'
            }
            
            #$Global:CurrentUser = "$domain\$user"
            #$NMEVars.CurrentUser = $Global:CurrentUser

            $password = (Read-Host "Password for account '$($User)'")

            [IntPtr]$token = [Security.Principal.WindowsIdentity]::GetCurrent().Token

            if(! ($Advapi32::LogonUser($User,"$Domain",$password, 9, 0, [ref]$token)))
            {
                $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                Write-Error "Something went foobar when running LogonUser function: $err" 
            }

            $id = New-Object Security.Principal.WindowsIdentity $token
            $id.Impersonate() |Out-Null
        }

        #Creating PSCredential object that can be used for impersonation with cmdlets that supports the "credential" parameter
        if([string]::IsNullOrEmpty($password))
        {
            $secpwd = new-object System.Security.SecureString
        }
        else
        {
            $secpwd = ConvertTo-SecureString $password -AsPlainText -Force
        }

        $NMEVars.CurrentCred = New-Object System.Management.Automation.PSCredential ($User,$secpwd)
        #$NMEVars.CurrentCred = $CurrentCred

        $message = "Impersonation of `'$($NMEVars.CurrentUser)`' completed"
        LogEvent -Command $CmdName -severity Info -event $message -ToConsole
    }

    END
    {}

}