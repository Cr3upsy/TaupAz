
Function findWebAppGitCreds{
        param (
        [string]$webApp
        )
        $userObjectId = (Get-AzContext).Account.ExtendedProperties.HomeAccountId.Split('.')[0]

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
    $userObjectId = (Get-AzContext).Account.ExtendedProperties.HomeAccountId.Split('.')[0]

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
            Write-Host "$($envHttpResponse.properties)"
        } else {
            Write-Host "[-] No environment variables found in App Settings." -ForegroundColor DarkYellow
        }

        if ($conectionStringHttpResponse.properties) {
            # Display connection strings if exist
            Write-Host "[+] Connection string(s) found ! some credentials may be stored in this variables" -ForegroundColor Green
            Write-Host "$($conectionStringHttpResponse.properties.secret)"
        } else {
            Write-Host "[-] No connection strings found." -ForegroundColor DarkYellow
        }
    } else {
        Write-Host "[-] The current user does NOT have the required permissions to access connection strings and env variables." -ForegroundColor DarkYellow
    }
}