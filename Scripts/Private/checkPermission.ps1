# In this function you can note that we check the permission of the user and not the RBAC roles.
# We made this choice because it is possible to add custom roles. 
# So if we only look at the user role, we may miss a custom role that has important rights over a resource.
Function checkPermission{
    param (
        [array]$permissions,
        [psobject]$roleAssignments,
        [string]$actionField = "Actions"  # Optional parameter with default value
        )

    $hasPermission = $false

    foreach ($roleAssignment in $roleAssignments) {
        $roleDefinition = Get-AzRoleDefinition -Id $roleAssignment.RoleDefinitionId
        foreach ($action in $permissions) {
            if ($roleDefinition.$actionField -contains $action) {
                $hasPermission = $true
                break
            }
        }
    }

    return $hasPermission
}

Function checkWebAppSSH{
    param (
        [psobject]$webApp
    )

    $userObjectId = (Get-AzContext).Account.ExtendedProperties.HomeAccountId.Split('.')[0]

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
        Write-Host "[-] User does not have the necessary permissions to create an SSH session on the web app service."`r`n -ForegroundColor DarkYellow
    }
}