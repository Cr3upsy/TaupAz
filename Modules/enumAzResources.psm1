<#
.SYNOPSIS
    This script allow to collect information about the resources available for the current user

.DESCRIPTION
    It list the available resource groups, resources, role assignments and actions.
#>

#Import functions
. "$PSScriptRoot\..\Scripts\Private\formatOutput.ps1"

Function enumResources {
    param (
        [string]$userObjectId
    )

    $resources = getResources
    $resourcesGroup = getResourceGroups -userObjectId $userObjectId
    getRoles -userObjectId $userObjectId -resources $resources
}

Function getResources {
    try {
        $resources = Get-AzResource
        
        if ($resources) {
            Write-Host "[*] Resources found for the current user `r`n"
            $scope = $resources | Select-Object -ExpandProperty ResourceId
        } else {
            Write-Host "[-] No resources found for the current user `r`n" -ForegroundColor DarkYellow
        }
    } catch {
        Write-Error "An error occured while getting Az reources : $_"
    }
    return $resources
}

Function getResourceGroups{
    param(
        [string]$userObjectId
        )

    try{
        $resourceGroups = Get-AzResourceGroup
    }catch{
        Write-Error $_
    }

    if ($resourceGroups) {
        Write-Host "[*] Resources groups found for the current user`r`n"
        $formattedOutput = $resourceGroups.ResourceGroupName | ForEach-Object { "- $_" }
            Write-Host "$formattedOutput" 
            Write-Host "`r`n"
    }

    else {
        Write-Host  "[-] No resource groups found for the current user`r`n" -ForegroundColor DarkYellow
    }
    return $resourceGroups
}



function getRoles {
    param (
        [string]$userObjectId,
        [array]$resources

    )

    Write-Host "[*] Checking for role definition`r`n"
    Write-Host "[*] Checking the actions that can be performed on resources by the current user `r`n"
    Write-Host "Please Wait ... `r`n"

    # Initialize dictionaries
    $resourceNamesDict = @{}
    $actionsDict = @{}
    $resourceGroupNamesDict = @{}

    try{
        # Iterate over resources
        foreach ($resource in $resources) {
            $scope = $resource.ResourceId
            $roleAssignments = Get-AzRoleAssignment -Scope $scope -ObjectId $userObjectId

            foreach ($roleAssignment in $roleAssignments) {
                # Add roles to resourceNamesDict
                if (-not $resourceNamesDict.ContainsKey($resource.Name)) {
                    $resourceNamesDict[$resource.Name] = @()
                }
                $resourceNamesDict[$resource.Name] += $roleAssignment.RoleDefinitionName

                # Add actions to actionsDict
                if (-not $actionsDict.ContainsKey($resource.Name)) {
                    $actionsDict[$resource.Name] = @()
                }
                $roleDef = Get-AzRoleDefinition -Id $roleAssignment.RoleDefinitionId
                $actionsDict[$resource.Name] += $roleDef.Actions
            }
        }

        Write-Host "[*] Result of roles found on resources"
        DisplayDict -dict $resourceNamesDict -nameColumn1 "Resource" -nameColumn2 "Role"
        

        Write-Host "[*] Result of actions that the current user can perform on resources `r`n" 
        DisplayDict -dict $actionsDict -nameColumn1 "Resource" -nameColumn2 "Actions"
        

        } catch {
            Write-Error $_
        }

}

# Export functions
Export-ModuleMember -Function enumResources
