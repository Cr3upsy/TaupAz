<#
.SYNOPSIS
    This script allow to enumerate storage account in Azure environnement

.DESCRIPTION
    It list the available storage accounts, containers and blobs available by the current user
#>

#Import functions
. "$PSScriptRoot\..\Scripts\Private\managementApiHttpRequest.ps1"
. "$PSScriptRoot\..\Scripts\Private\getBlobs.ps1"
. "$PSScriptRoot\..\Scripts\Private\checkPermission.ps1"



Function enumStorageAccounts{
    param (
        [string]$subscriptionId
    )

    Write-Host "[*] Enumeration of Storage Accounts`r`n" -ForegroundColor Green

    #Get storage accounts
    $storageAccounts = Get-AzStorageAccount
    $storageAccountsNames = $storageAccounts.StorageAccountName

    if ($null -eq $storageAccounts) {
        Write-Host "[-] No storage account accessible for the current user found`r`n" -ForegroundColor DarkYellow
    }
    else{
        Write-Host "[+] Storage account(s) found" -ForegroundColor Green
        Write-Host "$storageAccountsNames`r`n"


        foreach ($storageAccount in $storageAccounts) {

            $storageAccountName = $storageAccount.StorageAccountName
            $storageAccountId = $storageAccount.Id
            Write-Host "[*]Checking storage account : $storageAccountName`r`n"

            # Define the URI to list containers
            $uri = "https://management.azure.com$storageAccountId/blobServices/default/containers?api-version=2019-06-01"

            # Here we use the Azure Resource Manager (ARM) APIs to list the containers 
            # Because if our user have only reader role assignement we won't be able to list the storage account keys
            # So the Get-AzStorageContainer command will return an error about access rights
            $response = managementApiHttpRequest -URI $uri -method "GET"

            # Check the response and print container names
            if ($response) {
                Write-Host "Containers:"
                $response.value | ForEach-Object {
                    $containerName = $_.name
                    Write-Host "- $containerName"

                # Check the access level of each container
                $containerAccessUri = "https://management.azure.com$storageAccountId/blobServices/default/containers/$($containerName)?api-version=2019-06-01"

                $containerProperties = managementApiHttpRequest -URI $containerAccessUri -method "GET"

                if ($containerProperties) {
                    $accessLevel = $containerProperties.properties.publicAccess
                    if ($accessLevel -eq "Container" -Or $accessLevel -eq "Blob") {
                        Write-Host "[+] The content of this container can be accessed anonymously" -ForegroundColor Green
                        Write-Host "Access Level: $accessLevel"

                        #Create directory to store the anonymous blob content found
                        if (!(Test-Path -Path .\$($subscriptionId)_Az_Public_Blob_Content)) {
                             $blobDir = New-Item -Path .\$($subscriptionId)_Az_Public_Blob_Content -ItemType Directory
                        }
                        ListPublicContainerBlobs -storageAccountName $storageAccountName -containerName $containerName

                    } else {
                       Write-Host "[-] The access to the container content is restricted"`r`n -ForegroundColor DarkYellow
                    }
                    
                } else {
                    Write-Host "Could not retrieve properties for container: $containerName"
                }
            }
            } else {
                Write-Host "No container found"
            }

            findBlobs -storageAccount $storageAccount
            
        }
                
    }

}

# Export functions
Export-ModuleMember -Function enumStorageAccounts