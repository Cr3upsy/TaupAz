# Define the SSH directory path in the current directory
$currentDirectory = Get-Location
$sshDirectoryPath = Join-Path $currentDirectory "SSH"

# Create the SSH directory if it doesn't exist
if (-Not (Test-Path -Path $sshDirectoryPath)) {
    New-Item -Path $sshDirectoryPath -ItemType Directory | Out-Null
}

# Define the file paths for the key pair
$privateKeyPath = Join-Path $sshDirectoryPath "id_rsa"
$publicKeyPath = "$privateKeyPath.pub"

# Generate the SSH key pair
ssh-keygen -t rsa -b 2048 -f $privateKeyPath -q -N ""

# Output the file paths
Write-Host "SSH key pair generated:"
Write-Host "Private key: $privateKeyPath"
Write-Host "Public key: $publicKeyPath"
