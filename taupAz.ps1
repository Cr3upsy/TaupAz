# Import modules
Import-Module "$PSScriptRoot\Modules\enumAzResources.psm1" -Force
Import-Module "$PSScriptRoot/Modules/enumAzWebApps.psm1" -Force
Import-Module "$PSScriptRoot/Modules/enumAzStorages.psm1" -Force
Import-Module "$PSScriptRoot/Modules/enumAzKeyVaults.psm1" -Force
Import-Module "$PSScriptRoot/Modules/enumAzVMs.psm1" -Force

#Import functions
. "$PSScriptRoot/Scripts/Private/formatOutput.ps1" -Force

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
        Write-Error $_
    }
}

mainBanner

#Add auth MFA + simple auth option 
#Connect-AzAccount -Credential $creds 
#or
#Connect-AzAccount -TenantId $tenantId -AccountId <email>

$subscriptions = Get-AzSubscription
$exploit = $false

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

    enumResources -userObjectId $userObjectId

    Banner -title "Web App Services"
    enumAppServices -subscriptionId $subscriptionId

    Banner -title "Storage Accounts"
    enumStorageAccounts -subscriptionId $subscriptionId

    Banner -title "Key Vaults"
    enumKeyVaults -userObjectId $userObjectId -subscriptionId $subscriptionId

    Banner -title "VMs"
    enumVMs -userObjectId $userObjectId -exploit $exploit
    

}