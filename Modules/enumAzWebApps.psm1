<#
.SYNOPSIS
    This script allow to enumerate web app services in Azure environnement

.DESCRIPTION
    It list the available web apps for the current user and try to find sensitive informations
#>

#Import functions
. "$PSScriptRoot\..\Scripts\Private\managementApiHttpRequest.ps1"
. "$PSScriptRoot\..\Scripts\Private\findCredentials.ps1"
. "$PSScriptRoot\..\Scripts\Private\checkPermission.ps1"

Function enumAppServices{
    param (
        [string]$subscriptionId
    )

    Write-Host "[*] Enumeration of web app services`r`n"


    #Get only app services
    $webApps = Get-AzWebApp | ?{$_.Kind -notmatch "functionapp"}
    if ($null -eq $webApps) {
        Write-Host "[-] No Web App Service Accessible for the current`r`n" -ForegroundColor DarkYellow
    }
    else{
        Write-Host "[+] Web App Service(s) Found, if the service is started, you can to access it through your browser at the following url(s) :`r`n" -ForegroundColor Green
        Write-Host "$($webApps.Hostnames)`r`n"

        Write-Host "[*] Let's check if any github project is linked to these WebApp`r`n" -ForegroundColor Green


        foreach ($webApp in $webApps) {
            Write-Host "[*]Checking web app: $($webApp.Name)"
                findWebAppGitCreds -webApp $webApp
                findWebAppConnectionStrings -webApp $webApp
                checkWebAppSSH -webApp $webApp
            
        }
                
    }

}

# Export functions
Export-ModuleMember -Function enumAppServices