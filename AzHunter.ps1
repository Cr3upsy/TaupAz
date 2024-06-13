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
        Write-Host "[-] No resources found for the current user `r`n"
    } else {
        Write-Host "[+] Resources found for the current user `r`n"
        $scope = $resources | Select-Object -ExpandProperty ResourceId

        Write-Host "[+] Checking for role definition`r`n" -ForegroundColor Green
        Write-Host "[+] Checking the actions that can be performed on resources by the current user `r`n" -ForegroundColor Green
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

Function DisplayDict{

    param (
        [hashtable]$dict,
        [string]$nameColumn1,
        [string]$nameColumn2
    )

    $customObjects = @()

    foreach ($key in $dict.Keys) {

        $testValue = if ($dict[$key] -contains "*") { "-> You have full control on this resource" }
        $dict[$key].Add($testValue) > $null
                  
            $customObjects += [PSCustomObject]@{
                $nameColumn1 = $key
                $nameColumn2 = ($dict[$key] -join ", ")
        }
    }
    
    $displayDict = $customObjects | Format-Table -AutoSize
    return $displayDict
}


Connect-AzAccountWithCredential -Credential $creds

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

    Write-Host "[+] Let's take a look to the $($subscription.Name) resources `r`n" -ForegroundColor Green
     
    Set-AzContext -SubscriptionId $subscription.Id

    Find-Resources-Groups
    Find-Resources

}