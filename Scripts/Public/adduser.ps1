# Create new VM User
$passwd = ConvertTo-SecureString "Azerty123!" -AsPlainText -Force
New-LocalUser -Name taupaz -Password $passwd 
Add-LocalGroupMember -Group Administrators -Member taupaz