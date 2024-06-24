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

Function DisplayDict{

    param (
        [hashtable]$dict,
        [string]$nameColumn1,
        [string]$nameColumn2
    )

    $customObjects = @()
    $full_controled_resources = @()


    foreach ($key in $dict.Keys) {

        if ($dict[$key] -contains "*") { 
            $full_controled_resources += $key
         }

                  
        $customObjects += [PSCustomObject]@{
            $nameColumn1 = $key
            $nameColumn2 = ($dict[$key] -join ", ")
        }
    }

    # Check if the resources array is non-empty
    if ($full_controled_resources.Count -gt 0) {
        # Print the contents of the array
        Write-Host "[+] You have full control on the following resources :" -ForegroundColor Red
        Write-Host "$full_controled_resources `r`n" -ForegroundColor Red
}
    
    $displayDict = $customObjects | Format-Table -AutoSize
    return $displayDict
}