Function findBlobs{
    param (
        [psobject]$storageAccount
    )
    
    # Get the Object ID of the current user
    $userObjectId = (Get-AzContext).Account.ExtendedProperties.HomeAccountId.Split('.')[0]


    $requiredActions = @(
        "*",
        "Microsoft.Storage/storageAccounts/*",
        "Microsoft.Storage/storageAccounts/blobServices/containers/read",
        "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"
    )

    # Get role assignments for the user on the az storage resource
    $roleAssignments = Get-AzRoleAssignment -ObjectId $userObjectId -Scope $storageAccount.Id

    # Check if the user has a role that allows access to connection strings
    $hasPermission = checkPermission -permissions $requiredActions -roleAssignments $roleAssignments

    # Output the result
    if ($hasPermission) {
        Write-Host "[+] User has the necessary permissions to check the content of the Az storage accounts."`r`n -ForegroundColor Green
        $storageContext = $storageAccount.Context
        # List containers in the storage account
        $containers = Get-AzStorageContainer -Context $storageContext

        if($containers){
            Write-Host "[*] Some containers found"
            foreach ($container in $containers) {
                Write-Host "`r`n[+] Checking container: $($container.Name)`r`n" -ForegroundColor Green

                readBlobs -container $container -StorageContext $storageContext
            }
            Write-Host "`r`n[*] All the blobs resources found have been dowloaded to the following directory : .\$($subscriptionId)_Az_Blob_Content"
        }else{
            Write-Host "[-] No containers found"
        }

    } else {
        Write-Host "[-] User does not have the necessary permissions to access the content of the storage account."`r`n -ForegroundColor DarkYellow
    }

}

Function readBlobs{
    param (
        [psobject]$container,
        [psobject]$storageContext
    )

    # List blobs in the container
    $blobs = Get-AzStorageBlob -Container $container.Name -Context $storageContext
    
    $download = $false


    if($blobs){
        Write-Host "[*] We found the following resources in this container :"
        #Create directory to store the blob content found
        if (!(Test-Path -Path .\$($subscriptionId)_Az_Blob_Content)) {
             $blobDir = New-Item -Path .\$($subscriptionId)_Az_Blob_Content -ItemType Directory
        }
        foreach ($blob in $blobs) {
            Write-Host "[+] $($blob.Name)" -ForegroundColor Green
            # Read blob content and DL
            $blobContent = Get-AzStorageBlobContent -Blob $blob.Name -Container $container.Name -Context $storageContext -Destination .\$($subscriptionId)_Az_Blob_Content\$($blob.Name)
        }
    } else{
        Write-Host "[-] No blobs found"
    }
}

Function ListPublicContainerBlobs {
    param (
        [string]$storageAccountName,
        [string]$containerName
    )

    # Construct the URL to list blobs in the container
    $containerUrl = "https://$storageAccountName.blob.core.windows.net/$($containerName)?restype=container&comp=list"

    try {
        # Note that in all the program I am using Invoke-RestMethod for Http request
        # But in this case I am using System.Net.WebRequest because I encountered issue to parse XML with Invoke-RestMethod
        $request = [System.Net.WebRequest]::Create($containerUrl)
        $request.Method = "GET"

        # Get the response
        $response = $request.GetResponse()

        # Read the response content
        $responseStream = $response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($responseStream)
        $responseContent = $reader.ReadToEnd()

        [xml]$result = $responseContent
        $blobs = $result.EnumerationResults.Blobs.Blob

        # Clean up resources
        $response.Close()
        $reader.Close()


    } catch {
        Write-Host "Error listing blobs: $_"
    }



    # Check if the response contains blobs
    if ($blobs) {
        Write-Host "[*] Blobs in container '$containerName':"`r`n
        $blobs | ForEach-Object {
            $blobName = $blobs.Name
            Write-Host "- $($blobName)"
        try {
            # Construct the URL
            $blobUrl = "https://$storageAccountName.blob.core.windows.net/$containerName/$blobName"
 
            # Print the URL
            Write-Host "[*] Trying to download the blob at the following URL: $blobUrl"

            # Download the blob content
            Invoke-WebRequest -Uri $blobUrl -OutFile ".\$($subscriptionId)_Az_Public_Blob_Content\$blobName"
            Write-Host "[+] Blob downloaded successfully: .\$($subscriptionId)_Az_Public_Blob_Content\$blobName"`r`n -ForegroundColor Green
        } catch {
            Write-Host "Error downloading blob: $_"
        }
        }
    } else {
        Write-Host "No blobs found or failed to list blobs."
    }
}