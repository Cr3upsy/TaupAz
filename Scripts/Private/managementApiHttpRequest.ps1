Function managementApiHttpRequest{
        param (
        [string]$URI,
        [string]$method,
        [string]$scope
    )
    if($scope){
        $Token = (Get-AzAccessToken -resource $scope).Token
    }else{
        $Token = (Get-AzAccessToken).Token       
    }



    # Define request parameters
    $RequestParams = @{
        Method = "$method"
        Uri = "$URI"
        Headers = @{
            'Authorization' = "Bearer $Token"
        }
    }

    try{
        $response = Invoke-RestMethod @RequestParams 
    } catch {
        Write-Host "Error fetching app settings: $_"
    }

    return $response
}