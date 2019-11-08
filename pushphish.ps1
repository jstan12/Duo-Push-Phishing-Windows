function New-duoRequest(){
    param(
        [Parameter(Mandatory=$true,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
            [ValidateNotNull()]
            $apiHost,
        
        [Parameter(Mandatory=$true,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
            [ValidateNotNull()]
            $apiEndpoint,
        
        [Parameter(Mandatory=$true,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
            [ValidateNotNull()]
            $apiKey,
        
        [Parameter(Mandatory=$true,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
            [ValidateNotNull()]
            $apiSecret,
        
        [Parameter(Mandatory=$false,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
            [ValidateNotNull()]
            $requestMethod = 'GET',
        
        [Parameter(Mandatory=$false,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
            [ValidateNotNull()]
            [System.Collections.Hashtable]$requestParams
    )

    $date = (Get-Date).ToUniversalTime().ToString("ddd, dd MMM yyyy HH:mm:ss -0000")

    $formattedParams = ($requestParams.Keys | Sort-Object | ForEach-Object {$_ + "=" + [uri]::EscapeDataString($requestParams.$_)}) -join "&"
    
    #DUO Params formatted and stored as bytes with StringAPIParams
    $requestToSign = (@(
        $Date.Trim(),
        $requestMethod.ToUpper().Trim(),
        $apiHost.ToLower().Trim(),
        $apiEndpoint.Trim(),
        $formattedParams
    ).trim() -join "`n").ToCharArray().ToByte([System.IFormatProvider]$UTF8)

    #Hash out some secrets 
    $hmacsha1 = [System.Security.Cryptography.HMACSHA1]::new($apiSecret.ToCharArray().ToByte([System.IFormatProvider]$UTF8))
    $hmacsha1.ComputeHash($requestToSign) | Out-Null
    $authSignature = [System.BitConverter]::ToString($hmacsha1.Hash).Replace("-", "").ToLower()

    #Create the Authorization Header
    $authHeader = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes(('{0}:{1}' -f $apiKey, $authSignature)))

    #Create our Parameters for the webrequest - Easy @Splatting!
    $httpRequest = @{
        URI         = ('https://{0}{1}' -f $apiHost, $apiEndpoint)
        Headers     = @{
            "X-Duo-Date"    = $Date
            "Authorization" = "Basic: $authHeader"
        }
        Body = $requestParams
        Method      = $requestMethod
        ContentType = 'application/x-www-form-urlencoded'
    }
    
    $httpRequest
}

# Duo Keys
$api_host = 'api-xxxxxxxx.duosecurity.com'
$admin_skey = 'xxxxxxxxxxxxxxxxxxxxxxxx'
$admin_ikey = 'xxxxxxxxxxxxxxxxxxxxxxxx'
$auth_skey = 'xxxxxxxxxxxxxxxxxxxxxxxx'
$auth_ikey = 'xxxxxxxxxxxxxxxxxxxxxxxx'

$limit = 5
$Params = $null
$Params = @{  
    offset = 0
    limit = $limit
    }
while ($Params.offset -ne $null){
    
    $Request = New-DuoRequest -apiHost $api_host -apiEndpoint '/admin/v1/groups' -apiKey $admin_ikey -apiSecret $admin_skey -requestParams $Params
    $groups = Invoke-RestMethod @Request
    
    $i = 1
    foreach($group in $groups.response){
        Write-Host $i ' ' $group.name
        $i++
        }
    
    if ($groups.metadata.next_offset -ne $null) {
        $Params = $null
        $Params = @{  
            offset = $groups.metadata.next_offset
            limit = $limit
            }
        $groupInput = Read-Host 'Enter Group Number or press Enter for more groups'
        if($groupInput -eq ''){
     
            $Request = New-DuoRequest -apiHost $api_host -apiEndpoint '/admin/v1/groups' -apiKey $admin_ikey -apiSecret $admin_skey -requestParams $Params
            $groups = Invoke-RestMethod @Request
            }
        else{
            $groupToPhish = $groups.response[$groupInput - 1].group_id
            Write-Host 'Phishing Group: ' $groups.response[$groupInput - 1].name
            break
            }
        }
    else{
        $groupInput = Read-Host 'Enter Group Number'
        $groupToPhish = $groups.response[$groupInput - 1].group_id
        Write-Verbose ('Phishing group: {0} ' -f $groups.response[$groupInput - 1].name) -Verbose
        $Params.offset = $null
        }
    } 

# user_limit is 300 per page
$user_limit = 300
$Params = $null
$Params = @{  
    offset = 0
    limit = $user_limit
    }
while ($Params.offset -ne $null){
    $user_api = '/admin/v2/groups/' + $groupToPhish + '/users'
    $Request = New-DuoRequest -apiHost $api_host -apiEndpoint $user_api -apiKey $admin_ikey -apiSecret $admin_skey -requestParams $Params
     $users = Invoke-RestMethod @Request

      foreach ($user in $users.response){
 
    $Params = $null
    Write-Verbose ('Phishing User: {0} ' -f $user.username) -Verbose
    $Params = @{  
        username = $user.username
        factor = 'auto'
        device = 'auto'
        async = '1'
        }
    
    $request = New-DuoRequest -apiHost $api_host -apiKey $auth_ikey -apiSecret $auth_skey -apiEndpoint '/auth/v2/auth' -requestParams $Params -requestMethod POST
     $response = Invoke-RestMethod @request
     }

     if ($users.metadata.next_offset -ne $null) {
        $Params = $null
        $Params = @{  
            offset = $users.metadata.next_offset
            limit = $limit
            }
        }
     else{
        break
     }  
} 
