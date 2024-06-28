![Taupaz Logo](Resources/logo.png)

# TaupAz

## Project description

Taupaz is a tool for enumerating Azure resources with initial access to the tenant.

Currently, the enumeration is focused on storage (containers and blobs), key vaults, web applications and VMs.

**If you encounter any unexpected behaviour with the script, don't hesitate to report the problem by creating an "issue".**

## Prerequisites

To use this script you must have the following prerequisites :

- Az Powershell

You can install it as follows :

```powershell
Install-Module -Name Az -Repository PSGallery -Force
```

* A valid user account for the targeted tenant

* Be authenticated

You can authenticate as follows :

```powershell
$passwd = ConvertTo-SecureString "<password>" -AsPlainText -Force 
$creds = New-Object System.Management.Automation.PSCredential ("<username>", $passwd)
Connect-AzAccount -Credential $creds
```

In case of MFA enable, you can use interactive login as follows :

```powershell
Connect-AzAccount -Tenant <tenantID> -AccountId <accountemail>
```

## Commands

After cloning the project, you can run the script with several options.

If no option is specified, all enumeration modules will be launched.

* Run all enumeration tasks

```powershell
.\taupAz.ps1
```

* Program options to enum specific resources

```
.\taupAz.ps1 [-enumStorages] [-enumVaults] [-enumVaults] [-enumVMs] [-enumResources] [-exploit]
```

* The `exploit` options is disable by default. When enable it can try to create new user account on VMs where the user have sufficient access rights.
  
  The default credentials of the new user account are : 
  
  * On windows VMs  `taupaz:Azerty123!`
  
  * On linux VMs `taupaz`
  
  You can edit them in the `Scripts\Public\adduser` files.



## Examples

* enum only vault and storages

```
.\taupAz.ps1 -enumStorages -enumVaults
```

* enum all resources and enable exploit 

```
.\taupAz.ps1 -exploit 
```



## To Do

```markdown
- [ ] Handle case where key vaults certificates are deleted by not purges
- [ ] Handle case where access control to the key vault is not carried out by RBAC
- [ ] Check if user can start a Shutdown VM
- [ ] Check SSH access
- [ ] Check WinRM access
- [ ] Exploit SSH access
- [ ] Exploit WinRM access
```



## Advisory

The TaupAz scripts should be used for authorized penetration testing and/or educational purposes only. Any misuse of this software will not be the responsibility of the author or of any other collaborator. Use it at your own networks and/or with the network owner's permission.
