<#
.SYNOPSIS
    This script allow to enumerate key vaults in Azure environnement

.DESCRIPTION
    It list the available key vault available by the current user and try to extract keys, certificates, or secrets
#>

#Import functions
. "$PSScriptRoot\..\Scripts\Private\checkPermission.ps1"
. "$PSScriptRoot\..\Scripts\Private\managementApiHttpRequest.ps1"



Function enumKeyVaults{
    param(
    [string]$userObjectId,
    [string]$subscriptionId

        )

    #List of actions needed to read keys, cert, or secrets into key vaults
    $ownerAction = @("*")
    $fullVaultAccessAction = @("Microsoft.KeyVault/vaults/*/read", "Microsoft.KeyVault/vaults/*")
    $certificatesAccessAction = @("Microsoft.KeyVault/vaults/certificates/*")
    $keysAccessAction = @("Microsoft.KeyVault/vaults/keys/*")
    $secretAccessAction = @("Microsoft.KeyVault/vaults/secrets/*")
    $secretReadOnlyAction = @("Microsoft.KeyVault/vaults/secrets/getSecret/action")

	Write-Host "[*] Enumeration of keyvaults`r`n"

    #Get key vaults
    $keyVaults = Get-AzKeyvault
    if ($null -eq $keyVaults) {
        Write-Host "[-] No keyVaults Accessible for the current user`r`n" -ForegroundColor DarkYellow
    }
    else{
        GetPermission -keyVaults $keyVaults    
    }
}

Function GetPermission{
    param(
        [psobject]$keyVaults
    )
        # Get role assignments for the user on the web app resource
        $roleAssignments = Get-AzRoleAssignment -ObjectId $userObjectId -Scope $keyVaults.ResourceId

        #Unlike the other permission controls, which concern the 'action' field, this time it's the 'DataActions' attribute which is controlled.
        $actionField = "DataActions"

        Write-Host "[+] Key Vault(s) Found :`r`n" -ForegroundColor Green
        
        Write-Host "$($keyVaults.VaultName)`r`n"


        foreach ($keyVault in $keyVaults) {
            $vaultName = $keyVault.VaultName
            Write-Host "[*]Checking key vault: $vaultName"

            $hasRbacPermission = checkPermission -permissions $ownerAction -roleAssignments $roleAssignments
            $hasFullVaultAccess = checkPermission -permissions $fullVaultAccessAction -roleAssignments $roleAssignments -actionField $actionField
            $hasCertificatesAccess = checkPermission -permissions $certificatesAccessAction -roleAssignments $roleAssignments -actionField $actionField
            $hasKeysAccess = checkPermission -permissions $keysAccessAction -roleAssignments $roleAssignments -actionField $actionField
            $hasSecretAccess = checkPermission -permissions $secretAccessAction -roleAssignments $roleAssignments -actionField $actionField
            $hasSecretReadAccess = checkPermission -permissions $secretReadOnlyAction -roleAssignments $roleAssignments -actionField $actionField

            Write-Host "$hasRbacPermission $hasFullVaultAccess $hasCertificatesAccess $hasKeysAccess $hasSecretAccess $hasSecretReadAccess"

            if($hasFullVaultAccess) {

                $access = "full"

                Write-Host "[+] The user have full vault access and can extract keys, certificates, and secrets"
                getSecrets -vaultName $VaultName
                getKeys -vaultName $VaultName -subscriptionId $subscriptionId
                getCertificates -vaultName $VaultName -subscriptionId $subscriptionId -access $access
                
            }elseif($hasCertificatesAccess) {
                $access = "limited"

                Write-Host "[+] The user have only access to certificates management (read / add /remove)"
                getCertificates -vaultName $VaultName -subscriptionId $subscriptionId -access $access
                
            }elseif($hasKeysAccess) {

                Write-Host "[+] The user have only access to keys management (read / add /remove)"
                getKeys -vaultName $VaultName -subscriptionId $subscriptionId
            
            }elseif($hasSecretAccess) {

                Write-Host "[+] The user have only access to secrets (read / add /remove)"
                getSecrets -vaultName $VaultName
 
            }elseif($hasSecretReadAccess) {

                Write-Host "[+] The user have read only access to secrets"
                getSecrets -vaultName $VaultName
                
            }elseif($hasRbacPermission){
                Write-Host "===================================================="
                Write-Host "[+] The user don't have the right to see secret, keys, or certificates, however the current user seems to have Owner role assignment on this key vault, this mean that he can change RBAC to add to himself the role of Key Vault administrator"
                Write-Host " - To do this you can run the following command, and relaunch the script to extract secret"
                Write-Host "    |-> az role assignment create --assignee 6d317b27-9d6b-490b-bec9-8c0fe09118b0 --role 'Key Vault Administrator' --scope /subscriptions/$subscriptionId/resourceGroups/$($keyVault.ResourceGroupName)/providers/Microsoft.KeyVault/vaults/$($VaultName)"
                Write-Host "/!\ After running this command it can tae some times before the propagation of the role"
                Write-Host "- If it doesn't work, check in details the role assignement that you have on this resource."
                Write-Host "===================================================="
            } else {
                Write-Host "[-] User does not have the necessary permissions to access this key vault."`r`n -ForegroundColor DarkYellow
            }

        }
}

Function getKeys{
    param (
        [string]$vaultName,
        [string]$subscriptionId
        )
    # Get public keys from the vault
    $vaultKeys = Get-AzKeyVaultKey -VaultName $vaultName
    $vaultKeys | ForEach-Object {
        $vaultKeyName = $_.Name
        Write-Host -NoNewline "[+ Key Found !]" -ForegroundColor Green
        Write-Host " Name : $($vaultKeyName) "
        try {
            $path = "$PSScriptRoot\..\$($subscriptionId)_Az_Public_Keys\"
            $fileName = "$($vaultKeyName)_pubkey.pem"

            #Create directory to store the public keys found
            if (!(Test-Path -Path $path)) {
                 New-Item -Path $path -ItemType Directory
            }
            $keyData = Get-AzKeyVaultKey -VaultName $vaultName -KeyName $vaultKeyName -OutFile "$($path)$($fileName)"
     
            Write-Host "[+] Public key successfully downloaded at the following path: $($path)$($fileName)"`r`n -ForegroundColor Green

            } catch {

                    Write-Error "Error to during public key download: $_"
            }
    }
}

Function getCertificates{
    param (
        [string]$vaultName,
        [string]$subscriptionId,
        [string]$access
        )
    # Get secrets names from the vault
    $vaultCerts = Get-AzKeyVaultCertificate -VaultName $vaultName
    $vaultCerts | ForEach-Object {
        $vaultCertName = $_.Name
        Write-Host -NoNewline "[+ Certificate Found !]" -ForegroundColor Green
        Write-Host " Name : $($vaultCertName) " 
        try {
            $path = "$PSScriptRoot\..\$($subscriptionId)_Az_Certificates\"

            #Create directory to store the public keys found
            if (!(Test-Path -Path $path)) {
                 New-Item -Path $path -ItemType Directory
            }
            if ($access -eq "full"){
                $fileName = "$($vaultCertName)_cert.pfx"
                $CertBase64 = Get-AzKeyVaultSecret -VaultName $vaultName -Name $vaultCertName -AsPlainText
                $CertBytes = [Convert]::FromBase64String($CertBase64)
                Set-Content -Path "$($path)$($fileName)" -Value $CertBytes -Encoding Byte                
            }
            elseif($access -eq "limited"){
                $fileName = "$($vaultCertName)_cert.cer"
                $certUrl = "https://$vaultName.vault.azure.net/certificates/$vaultCertName/export?api-version=7.0"
                $scope = "https://vault.azure.net"
                $response = managementApiHttpRequest -URI $certUrl -method "GET" -scope $scope
                $certificateContent = $response.cer
                $certificateContent | Set-Content -Path "$($path)$($fileName)" -Encoding UTF8
            }

            Write-Host "[+] Certificate successfully downloaded at the following path: $($path)$($fileName)"`r`n -ForegroundColor Green

        } catch {

            Write-Error "Error to during certificate download: $_"
        }
    }
}

Function getSecrets{
    param (
        [string]$vaultName
        )
    # Get secrets names from the vault
    $vaultSecrets = Get-AzKeyVaultSecret -VaultName $vaultName
    $vaultSecrets | ForEach-Object {
        $vaultSecretsName = $_.Name
        try {
            # Get secret values
            $secret = Get-AzKeyVaultSecret -VaultName $vaultName -Name $vaultSecretsName -AsPlainText
            Write-Host -NoNewline "[+ Secret Found !] " -ForegroundColor Green
            Write-Host -NoNewline "$($vaultSecretsName) : $secret `r`n" 

        }catch {
            Write-Host "Error to retrieve secret $_" 
        }
    }
}
