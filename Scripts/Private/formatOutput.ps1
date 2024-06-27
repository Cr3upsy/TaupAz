Function mainBanner{
    $filePath = "$PSScriptRoot\..\..\Resources\banner.txt"
    
    # Check if the file exists
    if (Test-Path $filePath) {
        # Read the content of the file
        $bannerContent = Get-Content $filePath
        # Output the content to the terminal
        Write-Output $bannerContent
    } else {
        Write-Error "File not found: $filePath"
    }
}

Function Banner{
    param (
        [string]$title
    )

    # Calculate the space padding required
    $paddingSize = 52 - 6 - $title.Length  # 6 is the length of "|    " and "|"

    # Ensure the padding size is non-negative
    if ($paddingSize -lt 0) {
        Write-Error "Title is too long to fit within the banner."
        exit
    }
    $banner = "|    $title" + (" " * $paddingSize) + "|"
    Write-Host " __________________________________________________"
    Write-Host "|                                                  |"
    Write-Host "$banner"
    Write-Host "|__________________________________________________|`r`n"

    Write-Host "------------------`r`n"
}

# Function to display dictionary content
Function DisplayDict {
    param (
        [hashtable]$dict,
        [string]$nameColumn1,
        [string]$nameColumn2
    )

    $customObjects = @()
    $fullControledResources = @()

    if($nameColumn2 -eq "Role"){
        $flagString = @("Owner", "Contributor", "Access Review Operator Service Role", "Role Based Access Control Administrator", "User Access Administrator")
        $columnType = "Role"
        $comment = "[+] You have privileged administrator role on the following resources :"

    }elseif ($nameColumn2 -eq "Actions"){
        $flagString = @("*")
        $columnType = "Action"
        $comment = "[+] You have full control on the following resources :"

    }else{
        $flagString = @()
    }
    
    foreach ($key in $dict.Keys) {
        foreach ($flag in $flagString) {
            if ($flag -in $dict[$key]) {
                $fullControledResources += $key
                break
            }
        }

        $customObjects += [PSCustomObject]@{
            $nameColumn1 = $key
            $nameColumn2 = ($dict[$key] -join ", ")
        }
    }

    # Check if the custom objects array is non-empty before printing
    if ($customObjects.Count -gt 0) {
        $customObjects | Format-Table -AutoSize

        if ($fullControledResources.Count -gt 0) {
            Write-Host "$comment" -ForegroundColor Green

            $formattedOutput = $fullControledResources | ForEach-Object { "- $_ `r`n" }
            Write-Host "$formattedOutput"
    }

    } else {
        Write-Host "[-] No data to display." -ForegroundColor DarkYellow
    }
}




