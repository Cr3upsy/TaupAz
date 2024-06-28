<#
.SYNOPSIS
    Script to perform various enumeration and exploit tasks on Azure environment.
.DESCRIPTION
    This script supports enumerating storages, vaults, VMs, and resources. 
    It also supports an exploit option.
    This script require a valide Az user account.
.PARAMETER enumStorages
    Optional. Enumerate only storages.
.PARAMETER enumVaults
    Optional. Enumerate only vaults.
.PARAMETER enumVMs
    Optional. Enumerate only VMs.
.PARAMETER enumResources
    Optional. Enumerate only resources.
.PARAMETER exploit
    Optional. Perform exploit operations such as attempt to create new user on VMs if possible.
.PARAMETER all
    Perform all enumeration task
.EXAMPLE
    .\topaz.ps1
    Runs all enumeration tasks (except exploit) by default.
.EXAMPLE
    .\topaz.ps1 -exploit
    Runs all enumeration tasks and run exploit when possible.
.EXAMPLE
    .\topaz.ps1 -enumStorages
    Enumerates storages.
.EXAMPLE
    .\topaz.ps1 -enumVMs -exploit
    Enumerates VMs and performs an exploit operation.
.NOTES
    Author: Creupsy

#>

param (
    [Parameter(Mandatory=$false)]
    [switch] $enumStorages,

    [Parameter(Mandatory=$false)]
    [switch] $enumVaults,

    [Parameter(Mandatory=$false)]
    [switch] $enumVMs,

    [Parameter(Mandatory=$false)]
    [switch] $enumResources,

    [Parameter(Mandatory=$false)]
    [switch] $enumWebApps,

    [Parameter(Mandatory=$false)]
    [switch] $exploit = $false
)

# Import modules
Import-Module "$PSScriptRoot/Modules/enumAzResources.psm1" -Force
Import-Module "$PSScriptRoot/Modules/enumAzWebApps.psm1" -Force
Import-Module "$PSScriptRoot/Modules/enumAzStorages.psm1" -Force
Import-Module "$PSScriptRoot/Modules/enumAzKeyVaults.psm1" -Force
Import-Module "$PSScriptRoot/Modules/enumAzVMs.psm1" -Force

#Import functions
. "$PSScriptRoot/Scripts/Private/formatOutput.ps1" -Force

function Test-AzureConnection {
    try {
        $context = Get-AzContext
        if ($null -eq $context) {
            throw "Not connected to Azure."
        }
        Write-Output "Connected to Azure as $($context.Account)"
    } catch {
        Write-Error "You are not connected to your Azure account."
        exit
    }
}



# Check if no parameters are provided and set defaults
if (-not ($enumStorages.IsPresent -or $enumVaults.IsPresent -or $enumVMs.IsPresent -or $enumResources.IsPresent)) {
    Write-Host "No specific parameters provided. Running all enumeration tasks."
    $enumStorages = $true
    $enumVaults = $true
    $enumVMs = $true
    $enumResources = $true
}

mainBanner

# Check Azure connection
Test-AzureConnection

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

    if ($enumResources) {
        Banner -title "Az Resources"
        enumResources -userObjectId $userObjectId
    }
    if ($enumWebApps) {
         Banner -title "Web App Services"
         enumAppServices -subscriptionId $subscriptionId       
    }
    if ($enumStorages) {
        Banner -title "Storage Accounts"
        enumStorageAccounts -subscriptionId $subscriptionId   
    }
    if ($enumVaults) {
        Banner -title "Key Vaults"
        enumKeyVaults -userObjectId $userObjectId -subscriptionId $subscriptionId      
    }
    if ($enumVMs) {
        Banner -title "VMs"
        enumVMs -userObjectId $userObjectId -exploit $exploit
    }

}
