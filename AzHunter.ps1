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

function Find-Resources-Groups {
    try {
    # Get resource groups
    $resourceGroups = Get-AzResourceGroup | Select-Object -ExpandProperty ResourceGroupName

    if ($null -eq $resourceGroups) {
        Write-Host  "[-] No resource groups found for the current user`r`n" -ForegroundColor DarkYellow
    } else {
        Write-Host "[+] Resources groups found for the current user`r`n" -ForegroundColor Green

    foreach ($resourceGroup in $resourceGroups) {
        Write-Host "Resource Group: $resourceGroup`r`n"
    
        # Get role assignments for the current user in the current resource group
        $userRoleAssignments = (Get-AzRoleAssignment -ObjectId $userObjectId -ResourceGroupName $resourceGroup).RoleDefinitionName
    
        Write-Host "[+]Role Assignments:`r`n" -ForegroundColor Green

        Write-Host "----"
        $userRoleAssignments
        Write-Host "----"
    
        # Check if the user has a privileged administrator role on the group
        $allRoles = Get-AzRoleDefinition | Select-Object -ExpandProperty Name
        $customRoles = $userRoleAssignments | Where-Object { $_ -notin $allRoles }

        if ($customRoles) {
            foreach ($role in $customRoles) {
                Write-Host "[+] A custom role $role has been assigned to the current user on the resource group $resourceGroup. Sometimes custom roles can have interesting privileges. `r`n" -ForegroundColor DarkYellow
            }
        }

        # Check if the user has a privileged administrator role on the group
        $privilegedRoles = @("Owner", "Contributor", "Access Review Operator Service Role", "Role Based Access Control Administrator", "User Access Administrator")
        foreach ($role in $privilegedRoles) {
            if ($userRoleAssignments -contains $role) {
                Write-Host "[+] You have a privileged administrator role $role on the group $resourceGroup `r`n" -ForegroundColor Red
                break
            }
        }
    
        Write-Host ""
    }
    }

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


function Find-Resources {
try {

    $rolesDict = @{}
    $actionsDict = @{}

    $resources = Get-AzResource
    
    if ($null -eq $resources) {
        Write-Host "[-] No resources found for the current user `r`n" -ForegroundColor DarkYellow
    } else {
        Write-Host "[+] Resources found for the current user `r`n" -ForegroundColor Green
        $scope = $resources | Select-Object -ExpandProperty ResourceId

        Write-Host "[*] Checking for role definition`r`n"
        Write-Host "[*] Checking the actions that can be performed on resources by the current user `r`n"
        Write-Host "Please Wait ... `r`n"

        foreach ($resource in $resources) {

            $scope = $resource.ResourceId

            $roleAssignment = Get-AzRoleAssignment -Scope $scope -ObjectId $userObjectId

            #iterate over resource role
            foreach ($role in $roleAssignment.RoleDefinitionName){

                if (-not $rolesDict.ContainsKey($($resource.Name)) -or $rolesDict[$($resource.Name)] -eq $null -or $rolesDict[$($resource.Name)].Count -eq 0) {
                    # Initialize the key with an empty ArrayList
                    $rolesDict[$($resource.Name)] = [System.Collections.ArrayList]::new()
                }
                
                $rolesDict[$($resource.Name)].Add($role) > $null
            }

            #iterate over role action
            foreach ($id in $($roleAssignment.RoleDefinitionId)){

                $roleDef = Get-AzRoleDefinition -Id $id

                
                if (-not $actionsDict.ContainsKey($($resource.Name)) -or $actionsDict[$($resource.Name)] -eq $null -or $actionsDict[$($resource.Name)].Count -eq 0) {
                    # Initialize the key with an empty ArrayList
                    $actionsDict[$($resource.Name)] = [System.Collections.ArrayList]::new()
                }


                $actionsDict[$($resource.Name)].Add($($roleDef.Actions)) > $null
            }

            }

    Write-Host "[+] Result of roles found on resources"
    # Call the DisplayDict function and store results
    $rolesOutput = DisplayDict -dict $rolesDict -nameColumn1 "Resource" -nameColumn2 "Role"
    $rolesOutput

    Write-Host "[+] Result of actions that the current user can perform on resources `r`n" -ForegroundColor Green

    $actionsOutput = DisplayDict -dict $actionsDict -nameColumn1 "Resource" -nameColumn2 "Actions"
    $actionsOutput
    }

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

Function enumAppServices{
    Write-Host "------------------"
    Write-Host "|Web App Services|"
    Write-Host "------------------`r`n"

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

Function findWebAppGitCreds{
        param (
        [string]$webApp
        )
        # Check if the web app has deployment source settings
        if ($webApp.SiteConfig.ScmType -eq "GitHub") {
            $deploymentSettings = Get-AzResource -ResourceId $webApp.ResourceId/providers/Microsoft.Web/sourcecontrols/web -ApiVersion 2018-02-01

            # Extract GitHub repository URL
            $gitRepoUrl = $deploymentSettings.Properties.repoUrl
            if ($gitRepoUrl){
                Write-Host "[+] GitHub repository found, URL: $gitRepoUrl"
                # Check for leaked credentials (username or password)
                $username = $deploymentSettings.Properties.username
                $password = $deploymentSettings.Properties.password

                if ($username -or $password) {
                    Write-Host "[+] Some credentials are exposed!"`r`n -ForegroundColor Red
                    if ($username) {
                        Write-Host " - Username: $username"
                    }
                    if ($password) {
                        Write-Host " - Password: $password"
                    }
                } else {
                    Write-Host "[-] No credentials are exposed." -ForegroundColor DarkYellow
                }
            } else {
                Write-Host "[-] No GitHub project is linked to this web app." -ForegroundColor DarkYellow
            }

            Write-Host "------------------------"
        } else {
                Write-Host "[-] No GitHub project is linked to this web app." -ForegroundColor DarkYellow
        }
}

Function findWebAppConnectionStrings{
    param (
        [psobject]$webApp
    )

    $webAppResourceId = $webApp.Id

    # Check role assignments for the current user at the web app level
    $roleAssignments = Get-AzRoleAssignment -ObjectId $userObjectId -Scope $webAppResourceId

    # List of required action to access secrets
    $requiredActions = @(
        "*",
        "Microsoft.Web/sites/config/list/action",
        "Microsoft.Web/sites/config/write",
        "Microsoft.Web/sites/*"
        )

    # Check if the user has a role that allows access to connection strings
    $hasPermission = checkPermission -permissions $requiredActions -roleAssignments $roleAssignments

    # If user have sufficient permission, check env var and connection strings
    if ($hasPermission) {
        Write-Host "[+] User has the required permissions to access connection strings and env variables." -ForegroundColor Green

        $envURI = "https://management.azure.com$webAppResourceId/config/appsettings/list?api-version=2021-02-01"
        $conectionStringURI = "https://management.azure.com$webAppResourceId/config/connectionstrings/list?api-version=2021-02-01"

        $envHttpResponse = managementApiHttpRequest -URI $envURI -method "POST"
        $conectionStringHttpResponse = managementApiHttpRequest -URI $conectionStringURI -method "POST"


        # Display environment variables if they exist
        if ($envHttpResponse.properties) {
            Write-Host "[+] Environment Variable(s) (App Settings) found ! some credentials may be stored in this variables" -ForegroundColor Green
            $envHttpResponse.properties
        } else {
            Write-Host "[-] No environment variables found in App Settings." -ForegroundColor DarkYellow
        }

        if ($conectionStringHttpResponse.properties) {
            # Display connection strings if exist
            Write-Host "[+] Connection string(s) found ! some credentials may be stored in this variables" -ForegroundColor Green
            $conectionStringHttpResponse.properties
        } else {
            Write-Host "[-] No connection strings found." -ForegroundColor DarkYellow
        }
    } else {
        Write-Host "[-] The current user does NOT have the required permissions to access connection strings and env variables." -ForegroundColor DarkYellow
    }
}

Function checkWebAppSSH{
    param (
        [psobject]$webApp
    )

    $requiredActions = @(
        "*",
        "Microsoft.Web/sites/ssh/action",
        "Microsoft.Web/sites/*"
    )

    # Get role assignments for the user on the web app resource
    $roleAssignments = Get-AzRoleAssignment -ObjectId $userObjectId -Scope $webApp.Id

    # Check if the user has a role that allows access to connection strings
    $hasPermission = checkPermission -permissions $requiredActions -roleAssignments $roleAssignments

    # Output the result
    if ($hasPermission) {
        Write-Host "[+] User has the necessary permissions to create an SSH session on the web app."`r`n -ForegroundColor Green
        Write-Host "[*] If the app service is up and have been deployed through direct code and NOT as docker container, you can try to open SSH session with az cli :"
        Write-Host "    - az webapp create-remote-connection --resource-group <resourceGroup> --name $webAppName" 
    } else {
        Write-Host "[-] User does not have the necessary permissions to create an SSH session on the web app service." -ForegroundColor DarkYellow
    }
}

Function enumStorageAccounts{
    Write-Host "[*] Enumeration of Storage Accounts`r`n" -ForegroundColor Green

    #Get storage accounts
    $storageAccounts = Get-AzStorageAccount
    if ($null -eq $storageAccount) {
        Write-Host "[-] No storage account accessible for the current user found`r`n" -ForegroundColor DarkYellow
    }
    else{
        Write-Host "[+] Storage account(s) found" -ForegroundColor Green
        Write-Host "$($storageAccounts.StorageAccountName)`r`n"


        foreach ($storageAccount in $storageAccounts) {
            Write-Host "[*]Checking storage account : $($storageAccount.StorageAccountName)`r`n"

            Write-Host "[*] We found the following blob endpoint URL :"
            $blobEndpoint = $storageAccount.Context.BlobEndPoint
            Write-Host "$blobEndpoint`r`n"

            findBlobs -storageAccount $storageAccount
            
        }
                
    }

}

Function enumFunctionApps{
    Write-Host "[*] Enumeration of function apps`r`n" -ForegroundColor Green
    Get-AzFunctionApp

}

Function findBlobs{
    param (
        [psobject]$storageAccount
    )
    $requiredActions = @(
        "*",
        "Microsoft.Storage/storageAccounts/*",
        "Microsoft.Storage/storageAccounts/blobServices/containers/read",
        "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"
    )

    # Get role assignments for the user on the web app resource
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
        Write-Host "[-] User does not have the necessary permissions to access the content of the storage account." -ForegroundColor DarkYellow
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

Function checkPermission{
    param (
        [array]$permissions,
        [psobject]$roleAssignments
        )

    $hasPermission = $false

    foreach ($roleAssignment in $roleAssignments) {
        $roleDefinition = Get-AzRoleDefinition -Id $roleAssignment.RoleDefinitionId
        foreach ($action in $requiredActions) {
            if ($roleDefinition.Actions -contains $action) {
                $hasPermission = $true
                break
            }
        }
    }

    return $hasPermission
}

Function managementApiHttpRequest{
        param (
        [string]$URI,
        [string]$method
    )

    $Token = (Get-AzAccessToken).Token

    # Define request parameters
    $RequestParams = @{
        Method = "$method"
        Uri = "$URI"
        Headers = @{
            'Authorization' = "Bearer $Token"
        }
    }

    try{
        $response = Invoke-RestMethod @RequestParams 
    } catch {
        Write-Output "Error fetching app settings: $_"
    }

    return $response
}



Function DisplayDict{

    param (
        [hashtable]$dict,
        [string]$nameColumn1,
        [string]$nameColumn2
    )

    $customObjects = @()
    $full_controled_resources = @()


    foreach ($key in $dict.Keys) {

        if ($dict[$key] -contains "*") { 
            $full_controled_resources += $key
         }

                  
        $customObjects += [PSCustomObject]@{
            $nameColumn1 = $key
            $nameColumn2 = ($dict[$key] -join ", ")
        }
    }

    # Check if the resources array is non-empty
    if ($full_controled_resources.Count -gt 0) {
        # Print the contents of the array
        Write-Host "[+] You have full control on the following resources :" -ForegroundColor Red
        Write-Host "$full_controled_resources `r`n" -ForegroundColor Red
}
    
    $displayDict = $customObjects | Format-Table -AutoSize
    return $displayDict
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

    enumStorageAccounts

    Find-Resources-Groups
    Find-Resources

    enumAppServices
    

}