# Import modules
Import-Module "$PSScriptRoot/Modules/findAzResources.psm1" -Force
Import-Module "$PSScriptRoot/Modules/enumAzWebApps.psm1" -Force
Import-Module "$PSScriptRoot/Modules/enumAzStorages.psm1" -Force

#Import functions
. "$PSScriptRoot/Scripts/Private/formatOutput.ps1"


function Connect-AzAccountWithCredential {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]
        $Credential
    )

    try {
        $accountInfo = Connect-AzAccount -Credential $Credential -ErrorAction Stop 
        $subscription = $accountInfo[0].SubscriptionName
        Write-Host "[+] Authentication succeed  `r`n" -ForegroundColor Green
    } catch {
        Write-Error $_.Exception.Message
        Write-Error $_.InvocationInfo.PositionMessage
        Write-Error $_.InvocationInfo.ScriptLineNumber
        Write-Error $_.InvocationInfo.OffsetInLine
        Write-Error $_.InvocationInfo.Line
        Write-Error $_.InvocationInfo.PipelineLength
        Write-Error $_.InvocationInfo.MyCommand.Name
        Write-Error $_.InvocationInfo.MyCommand.CommandType
    }
}


Function enumVM{
    Write-Host "[*] Enumeration of VMs where the current user has at least the Reader role`r`n" -ForegroundColor Green
    Get-AzVM
}

Function enumKeyVaults{
    Write-Host "[*] Enumeration of readable keyvaults for the current user`r`n" -ForegroundColor Green
    Get-AzKeyvault

}


Function enumFunctionApps{
    Write-Host "[*] Enumeration of function apps`r`n" -ForegroundColor Green
    Get-AzFunctionApp

}


#Add auth MFA + simple auth option 
#Connect-AzAccount -Credential $creds 
#or
#Connect-AzAccount -TenantId $tenantId 

$subscriptions = Get-AzSubscription

# Get the Object ID of the current user
$userObjectId = (Get-AzContext).Account.ExtendedProperties.HomeAccountId.Split('.')[0]


if ($subscriptions.Count -eq 0) {
    Write-Host "[-] no subscription for current user `r`n"
    exit
}
else{
 Write-Host "[+] The current user have access to the following suscription(s) : `r`n" -ForegroundColor Green
 $subscriptions.Name
 Write-Host "`r`n"
}

foreach ($subscription in $subscriptions) {

    $subscriptionId = $subscription.Id

    Write-Host "[+] Let's take a look to the $($subscription.Name) resources `r`n" -ForegroundColor Green
     
    Set-AzContext -SubscriptionId $subscriptionId
    Banner -title "Az Resources"

    findResourcesGroups -subscriptionId $subscriptionId -userObjectId $userObjectId
    findResources -subscriptionId $subscriptionId -userObjectId $userObjectId

    Banner -title "Web App Services"
    enumAppServices -subscriptionId $subscriptionId

    Banner -title "Storage Accounts"
    enumStorageAccounts -subscriptionId $subscriptionId
    

}