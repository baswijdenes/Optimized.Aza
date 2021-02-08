#region main
function Connect-Aza {
    <#
    .LINK
    https://github.com/baswijdenes/Optimized.Aza/tree/main

    .SYNOPSIS
    Connect-Aza will retreive a RefreshToken from Microsoft Graph.
    
    .DESCRIPTION
    By selecting one of these parameters you log on with the following:

    ClientSecret: Will log you on with a ClientSecret.
    Certificate: Will log you on with a Certificate.
    Thumbprint: Will search for a Certificate under thumbprint on local device and log you on with a Certificate.
    UserCredentials: Will log you on with basic authentication.
    RedirectUri: Will log you on with MFA Authentication.
    The OauthToken is automatically renewed when you use cmdlets.

    .PARAMETER Thumbprint
    Use a certificate thumbprint to log on with. Connec-Aza will search for the certificate in the cert store.
    
    .PARAMETER Certificate
    Use a Cert to log on. you can use where X's is the certificate thumbprint:
    $Cert = get-ChildItem 'Cert:\LocalMachine\My\XXXXXXXXXXXXXXXXXXX'
    Connect-Aza -Certificate $Cert -ApplicationID 'XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXX' -Tenant 'XXXXXXXX.onmicrosoft.com'
    
    .PARAMETER ClientSecret
    Parameter description
    
    .PARAMETER RedirectUri
    Use the RedirectUri in your AzureAD app to connect with MFA. 
    RedirectUri should look something like this:
    'msalXXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXX://auth' 

    If you want to know more about how to log in via MFA with a RedirectUri, go to my blog:
    https://bwit.blog/how-to-start-with-microsoft-graph-in-powershell/#I_will_use_credentials
    
    
    .PARAMETER UserCredentials
    Use Get-Credential to log on with Basic Authentication. 
    
    .PARAMETER ApplicationID
    ApplicationID is the ID for the AzureAD application. It should look like this:
    'XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXX'

    .PARAMETER Tenant
    Tenant is the TenantID or onmicrosoft.com address. Don't confuse this with ApplicationID.

    I should look like this:
    'XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXX'
    Or
    XXXXXXX.onmicrosoft.com
    
    .PARAMETER LoginScope
    You can only use LoginScope with RedirectUri, but unfortunately the token will always include all permissions the app has.
    
    .PARAMETER Force
    Use -Force when you want to overwrite another connection (or Accept the confirmation).
    
    .EXAMPLE
    Connect-Aza -ClientSecret '1yD3h~.KgROPO.K1sbRF~XXXXXXXXXXXXX' -ApplicationID 'XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXX' -Tenant 'XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXX' 

    .EXAMPLE
    $Cert = get-ChildItem 'Cert:\LocalMachine\My\XXXXXXXXXXXXXXXXXXX'
    Connect-Aza -Certificate $Cert -ApplicationID 'XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXX' -Tenant 'XXXXXXXX.onmicrosoft.com'

    .EXAMPLE
    Connect-Aza -Thumbprint '3A7328F1059E9802FAXXXXXXXXXXXXXX' -ApplicationID 'XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXX' -Tenant 'XXXXXXXX.onmicrosoft.com' 

    .EXAMPLE
    Connect-Aza -UserCredentials $Cred -Tenant 'XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXX' -ApplicationID 'XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXX'

    .EXAMPLE
    Connect-Aza -redirectUri 'msalXXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXX://auth' -Tenant 'XXXXXXXX.onmicrosoft.com'  -ApplicationID 'XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXX'
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'Thumbprint')]
        [ValidateScript( { $_.length -eq 40 })]
        [string]
        $Thumbprint, 
        [Parameter(Mandatory = $true, ParameterSetName = 'Certificate')]
        $Certificate,
        [Parameter(Mandatory = $true, ParameterSetName = 'ClientSecret')]
        [string]
        $ClientSecret, 
        [Parameter(Mandatory = $true, ParameterSetName = 'RedirectUri')]
        [String]
        $RedirectUri,
        [Parameter(Mandatory = $true, ParameterSetName = 'Credentials')]
        [System.Net.ICredentials]
        $UserCredentials,
        [Parameter(Mandatory = $true)]
        [String]
        $ApplicationID,
        [Parameter(Mandatory = $true)]
        [String]
        $Tenant,
        [Parameter(Mandatory = $false, ParameterSetName = 'RedirectUri')]
        [AllowEmptyString()]  
        [Object]
        $LoginScope,
        [Parameter(Mandatory = $false)]
        [Switch]
        $Force
    )
    begin {
        if ($Force) {
            Write-Verbose 'Connect-Aza: -Force parameter found. Running Disconnect-Aza to force a log on.'
            $null = Disconnect-Aza
        }
        else {
            Initialize-AzaConnect
        }
    }
    process {
        if ($Thumbprint) {
            Write-Verbose "Connect-Aza: Thumbprint: Logging in with Thumbprint."
            Receive-AzaOauthToken `
                -ApplicationID $ApplicationID `
                -Tenant $Tenant `
                -Thumbprint $Thumbprint 
        }
        elseif ($Certificate) {
            Write-Verbose "Connect-Aza: Certificate: Logging in with certificate."
            Receive-AzaOauthToken `
                -ApplicationID $ApplicationID `
                -Tenant $Tenant `
                -Certificate $Certificate 
        }
        elseif ($ClientSecret) {
            Write-Verbose "Connect-Aza: RedirectUri: Logging in with RedirectUri."
            Receive-AzaOauthToken `
                -ApplicationID $ApplicationID `
                -Tenant $Tenant `
                -ClientSecret $ClientSecret
        }
        elseif ($RedirectUri) {
            Write-Verbose "Connect-Aza: MFA UserCredentials: Logging in with MFA UserCredentials."
            Receive-AzaOauthToken `
                -ApplicationID $ApplicationID `
                -Tenant $Tenant `
                -RedirectUri $RedirectUri `
                -LoginScope $LoginScope
        }
        elseif ($UserCredentials) {
            Write-Verbose "Connect-Aza: Basic UserCredentials: Logging in with Basic UserCredentials."
            Receive-AzaOauthToken `
                -ApplicationID $ApplicationID `
                -Tenant $Tenant `
                -UserCredentials $UserCredentials 
        }
    }
    end {
        return "You've successfully logged in to Azure.Service.Management.API."
    }
}

function Disconnect-Aza {
    <#
    .LINK
    https://github.com/baswijdenes/Optimized.Aza/tree/main

    .SYNOPSIS
    Use this to log off Azure Service Management API.
    
    .DESCRIPTION
    To update the OauthToken I fill the global scope with a number of properties. 
    The properties are emptied by Disconnect-Aza.
    
    .EXAMPLE
    Disconnect-Aza
    #>
    [CmdletBinding()]
    param (
    )
    begin {
        if ($global:AzaLoginType.length -ge 1) {
            Write-Verbose "Disconnect-Aza: Disconnecting from Azure.Service.Management.API."
        }
    }
    process {
        try {
            $Null = Get-Variable -Name "Aza*" -Scope Global | Remove-Variable -Force -Scope Global
        }
        catch {
            throw $_.Exception.Message
        }
    }
    end {
        return "You've successfully logged out."
    }
}

function Get-Aza {
    <#
    .LINK
    https://github.com/baswijdenes/Optimized.Aza/tree/main

    .SYNOPSIS
    Get-Aza speaks for itself. All you have to provide is the URL.
    
    .DESCRIPTION
    You can grab the URL via the browser developer tools, Fiddler, or from the Azure Service Management API docs.
    It will automatically use the Next Link when there is one in the returned request.
    
    .PARAMETER URL
    The URL to get data from Microsoft Graph.
    
    .PARAMETER Once
    If you only want to retrieve data once, you can use the -Once parameter.
    
    .EXAMPLE
    Get-Aza -URL 'https://management.azure.com/subscriptions/81bdb7e0-2010-4c36-ba35-71c560e3b317/resourceGroups/RG-2019/providers/Microsoft.Automation/automationAccounts/AA-2019-01/runbooks/POST-DC-2019-01?api-version=2015-10-31'
  

    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string]
        $URL,
        [Parameter(Mandatory = $false)]      
        [switch]
        $Once
    )
    begin {
        Update-AzaOauthToken
    }
    process {
        try {
            Write-Verbose "Get-Aza: Getting results from $URL."
            $Result = Invoke-WebRequest -UseBasicParsing -Headers $global:AzaHeaderParameters -Uri $URL -Method get
            if ($result.Headers.'Content-Type' -like "application/octet-stream*") {
                Write-Verbose "Get-Aza: Result is in Csv format. Converting to Csv and returning end result."
                $EndResult = ConvertFrom-Csv -InputObject $Result
            }
            if ($result.Headers.'Content-Type' -like "application/json*") {   
                Write-Verbose "Get-Aza: Result is in JSON format. Converting to JSON."
                $Result = ConvertFrom-Json -InputObject $Result
                if ($Result.'@odata.nextLink') {
                    if (!($Once)) {
                        Write-Verbose "Get-Aza: There is an @odata.nextLink for more output. We will run Get-Aza again with the next data link."
                        $EndResult = @()
                        foreach ($Line in ($Result).value) {
                            $EndResult += $Line
                        }
                        While ($Result.'@odata.nextLink') {
                            Write-Verbose "Get-Aza: There is another @odata.nextLink for more output. We will run Get-Aza again with the next data link."
                            Update-AzaOauthToken
                            $Result = (Invoke-WebRequest -UseBasicParsing -Headers $global:AzaHeaderParameters -Uri $Result.'@odata.nextLink' -Method Get).Content | ConvertFrom-Json
                            foreach ($Line in ($Result).value) {
                                $EndResult += $Line
                            }
                            Write-Verbose "Get-Aza: Count is: $($EndResult.count)."
                        }
                    }
                    else {
                        $EndResult = @()
                        foreach ($Line in ($Result).value) {
                            $EndResult += $Line
                        }
                        Write-Verbose 'Get-Aza: Parameter -Once found. Even if there is an @odata.nextLink for more output, we will not extract more data.'
                    }
                }
                elseif ($Result.value) {
                    Write-Verbose "Get-Aza: There is no @odata.nextLink. We will add the data to end result."
                    $EndResult = $Result.value
                }
                else {
                    Write-Verbose "Get-Aza: There is no @odata.nextLink. We will add the data to end result."
                    $EndResult = $Result
                }
            }
        }
        catch [System.Net.WebException] {
            Write-Warning "WebException Error message! This could be due to throttling limit."
            $WebResponse = $_.Exception.Response
            if ($WebResponse.StatusCode -eq 429) {
                [int]$RetryValue = $WebResponse.Headers['Retry-After']
                Write-Warning "WebException Error message! Throttling error. Retry-After header value: $($RetryValue) seconds. Sleeping for $($RetryValue + 1)s"
                Start-Sleep -Seconds $($RetryValue + 1) 
                if ($Result.'@odata.nextLink') {
                    Get-Aza -URL $Result.'@odata.nextLink'
                }
                else {
                    Get-Aza -URL $URL
                }
            }
            else {
                throw $_.Exception.Message
            }
        }
        catch {
            throw $_.Exception.Message
        }
    }
    end {
        return $EndResult
    }
}

function Post-Aza {
    <#
    .LINK
    https://github.com/baswijdenes/Optimized.Aza/tree/main

    .SYNOPSIS
    Post-Aza can be seen as the 'new' Verb.
    With this cmdlet you can create objects in Azure.

    .PARAMETER URL
    URL to 'POST' to.
    
    .PARAMETER InputObject
    -InputObject will accept a PSObject or JSON.

    .PARAMETER Put
    Use the -Put switch when the method is a Put instead of Post.
    
    .EXAMPLE
    Post-Aza `
        -URL 'https://management.azure.com/subscriptions/81bdb7e0-2010-4c36-ba35-71c560e3b317/resourceGroups/RG-2019/providers/Microsoft.Automation/automationAccounts/AA-2019-01/runbooks/New-PUT-PSScript?api-version=2015-10-31' `
        -InputObject $InputObject `
        -Put
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string]
        $URL,
        [Parameter(Mandatory = $false)]
        [object]
        $InputObject,
        [Parameter(Mandatory = $false)]
        [switch]
        $Put
    )
    begin {
        Update-AzaOauthToken
        $InputObject = ConvertTo-AzaJson -InputObject $InputObject
    }
    process {
        try {
            if ($InputObject) {
                if (!($Put -eq $true)) {
                    Write-Verbose "Post-Aza: Posting InputObject to Azure.Service.Management.API."
                    $Result = Invoke-RestMethod -Uri $URL -Headers $global:AzaheaderParameters -Method post -Body $InputObject -ContentType application/json
                } 
                else {
                    Write-Verbose "Post-Aza: Putting InputObject to Azure.Service.Management.API."
                    $Result = Invoke-RestMethod -Uri $URL -Headers $global:AzaheaderParameters -Method put -Body $InputObject -ContentType application/json
    
                }
            }
            else {
                if (!($Put -eq $true)) {
                    $Result = Invoke-RestMethod -Uri $URL -Headers $global:AzaheaderParameters -Method post -ContentType application/json   
                } 
                else {
                    $Result = Invoke-RestMethod -Uri $URL -Headers $global:AzaheaderParameters -Method put -ContentType application/json   
                } 
            }
        }
        catch [System.Net.WebException] {
            Write-Warning "WebException Error message! This could be due to throttling limit."
            $WebResponse = $_.Exception.Response
            if ($WebResponse.StatusCode -eq 429) {
                [int]$RetryValue = $WebResponse.Headers['Retry-After']
                Write-Warning "WebException Error message! Throttling error. Retry-After header value: $($RetryValue) seconds. Sleeping for $($RetryValue + 1)s"
                Start-Sleep -Seconds $($RetryValue + 1) 
                $Result = Post-Aza -URL $URL -InputObject $InputObject
            }
            else {
                throw $_.Exception.Message
            }
        }
        catch {
            throw $_.Exception.Message
        }
    }
    end {
        Write-Verbose "Post-Aza: We've successfully Posted the data to Azure.Service.Management.API."
        return $Result
    }
}

function Patch-Aza {
    <#
    .LINK
    https://github.com/baswijdenes/Optimized.Aza/tree/main

    .SYNOPSIS
    Patch-Aza can be seen as the 'Update' Verb.
    In the below example I change the description of a runbook in Azure Automation.

    .PARAMETER URL
    URL to 'PATCH' to.

    .PARAMETER InputObject
    -InputObject will accept a PSObject or JSON.

    .EXAMPLE
    $InputObject = [PSCustomObject]@{
        properties = [PSCustomObject]@{
            description = 'Update description with Patch-Aza'
        }
    }
    Patch-Aza `
        -URL 'https://management.azure.com/subscriptions/81bdb7e0-2010-4c36-ba35-71c560e3b317/resourceGroups/RG-2019/providers/Microsoft.Automation/automationAccounts/AA-2019-01/runbooks/New-PUT-PSScript?api-version=2015-10-31' `
        -InputObject $InputObject
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string]
        $URL,
        [Parameter(Mandatory = $true)]
        [object]
        $InputObject
    )
    begin {
        Update-AzaOauthToken
        $ValidateJson = ConvertTo-AzaJson -InputObject $InputObject -Validate
    }
    process {
        try {
                $InputObject = ConvertTo-AzaJson -InputObject $InputObject
                Write-Verbose "Patch-Aza: Patching InputObject to Azure.Service.Management.API."
                $Result = Invoke-RestMethod -Uri $URL -Headers $global:AzaheaderParameters -Method Patch -Body $InputObject -ContentType application/json
        }
        catch [System.Net.WebException] {
            Write-Warning "WebException Error message! This could be due to throttling limit."
            $WebResponse = $_.Exception.Response
            if ($WebResponse.StatusCode -eq 429) {
                [int]$RetryValue = $WebResponse.Headers['Retry-After']
                Write-Warning "WebException Error message! Throttling error. Retry-After header value: $($RetryValue) seconds. Sleeping for $($RetryValue + 1)s"
                Start-Sleep -Seconds $($RetryValue + 1) 
                $Result = Patch-Aza -URL $URL -InputObject $InputObject
            }
            else {
                throw $_.Exception.Message
            }
        }
        catch {
            throw $_.Exception.Message
        }
    }
    end {
        Write-Verbose "Patch-Aza: We've successfully Patched the data to Azure.Service.Management.API."
        return $Result
    }
}

function Delete-Aza {
    <#
    .LINK
    https://github.com/baswijdenes/Optimized.Aza/tree/main

    .SYNOPSIS
    Delete speaks for itself.
    With this cmdlet you can remove objects from Azure. 

    .PARAMETER URL
    -URL is the URL for the item to delete.
    
    .PARAMETER InputObject
    -InputObject will accept a PSObject or JSON.
    
    .EXAMPLE
    Delete-Aza `
        -URL 'https://management.azure.com/subscriptions/81bdb7e0-2010-4c36-ba35-71c560e3b317/resourceGroups/RG-2019/providers/Microsoft.Automation/automationAccounts/AA-2019-01/runbooks/New-PUT-PSScript?api-version=2015-10-31'
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string]
        $URL,
        [Parameter(Mandatory = $false)]
        [string]
        $InputObject
    )
    begin {
        Update-AzaOauthToken
    }
    process {
        try {
            if ($InputObject) {
                Write-Verbose "Delete-Aza: Deleting InputObject on $URL to Azure.Service.Management.API."
                $InputObject = ConvertTo-AzaJson -InputObject $InputObject
                $Result = Invoke-RestMethod -Uri $URL -body $InputObject -Headers $global:AzaheaderParameters -Method Delete -ContentType application/json
            }
            else {
                Write-Verbose "Delete-Aza: Deleting conent on $URL to Azure.Service.Management.API."
                $Result = Invoke-RestMethod -Uri $URL -Headers $global:AzaheaderParameters -Method Delete -ContentType application/json
            }
        }
        catch [System.Net.WebException] {
            Write-Warning "WebException Error message! This could be due to throttling limit."
            $WebResponse = $_.Exception.Response
            if ($WebResponse.StatusCode -eq 429) {
                [int]$RetryValue = $WebResponse.Headers['Retry-After']
                Write-Warning "WebException Error message! Throttling error. Retry-After header value: $($RetryValue) seconds. Sleeping for $($RetryValue + 1)s"
                Start-Sleep -Seconds $($RetryValue + 1) 
                if ($InputObject) {
                    $Result = Delete-Aza -URL $URL -InputObject $InputObject
                }
                else {
                    $Result = Delete-Aza -URL $URL
                }
            }
            else {
                throw $_.Exception.Message
            }
        }
        catch {
            throw $_.Exception.Message
        }
    }
    end {
        Write-Verbose "Delete-Aza: We've successfully deleted the data on Azure.Service.Management.API."
        return $Result
    }
}
#endregion main

#region internal
function Initialize-AzaConnect {
    [CmdletBinding()]
    param (
    )
    if ($global:AzaLoginType.length -ge 1) {
        Write-Verbose "Initialize-AzaConnect: You're already logged on."
        $Confirmation = Read-Host 'You already logged on. Are you sure you want to proceed? Type (Y)es to continue.'
        if (($Confirmation -eq 'y') -or ($Confirmation -eq 'yes') -or ($Confirmation -eq 'true') -or ($Confirmation -eq '(Y)es')) {
            Write-Verbose "Initialize-AzaConnect: We will continue logging in."
            $null = Disconnect-Aza
        }
        else {
            Write-Verbose "Initialize-AzaConnect: Aborting log in."
            throw 'Login aborted.'
        }
    }
}

function Update-AzaOauthToken {  
    [CmdletBinding()]
    param (
    )
    if ($null -ne $global:AzaAppPass) {
        Receive-AzaOauthToken `
            -ApplicationID $global:AzaApplicationID `
            -Tenant $global:AzaTenant `
            -ClientSecret $global:AzaSecret
    }
    elseif ($null -ne $global:AzaCert) {
        Receive-AzaOauthToken `
            -ApplicationID $global:AzaApplicationID `
            -Tenant $global:AzaTenant `
            -Certificate $global:AzaCertificate
    }
    elseif ($null -ne $global:AzaTPrint) {
        Receive-AzaOauthToken `
            -ApplicationID $global:AzaApplicationID `
            -Tenant $global:AzaTenant `
            -Thumbprint $global:AzaThumbprint 
    }
    elseif ($null -ne $global:AzaRU) {
        Receive-AzaOauthToken `
            -ApplicationID $global:AzaApplicationID `
            -Tenant $global:AzaTenant `
            -RedirectUri $global:AzaRedirectUri `
            -LoginScope $global:AzaLoginScope
    }
    elseif ($null -ne $global:AzaBasic) {
        Receive-AzaOauthToken `
            -ApplicationID $global:AzaApplicationID `
            -Tenant $global:AzaTenant `
            -UserCredentials $global:AzaUserCredentials 
    }
    else {
        Throw "You need to run Connect-Aza before you can continue. Exiting script..."
    }
}

function Receive-AzaOauthToken {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $ApplicationID,
        [Parameter(Mandatory = $true)]
        [string]
        $Tenant,
        [Parameter(Mandatory = $true, ParameterSetName = 'Thumbprint')]
        [string]
        $Thumbprint, 
        [Parameter(Mandatory = $true, ParameterSetName = 'Certificate')]
        $Certificate, 
        [Parameter(Mandatory = $true, ParameterSetName = 'ClientSecret')]
        $ClientSecret, 
        [Parameter(Mandatory = $true, ParameterSetName = 'Redirecturi')]
        [string]
        $RedirectUri,
        [Parameter(Mandatory = $false, ParameterSetName = 'Redirecturi')]
        [AllowEmptyString()]  
        [Object]
        $LoginScope,
        [Parameter(Mandatory = $true, ParameterSetName = 'UserCredentials')]
        [System.Net.ICredentials]
        $UserCredentials
    )
    begin {
        try { 
            $global:AzaTenant = $Tenant
            $global:AzaApplicationID = $ApplicationID
            if ($null -eq $LoginScope) {
                [System.Collections.Generic.List[String]]$LoginScope = @('https://management.azure.com/.default')
            }
            else {
                $Data = @('https://management.azure.com/.default')
                foreach ($Scp in $LoginScope) {
                    $Data += $Scp
                }
                [System.Collections.Generic.List[String]]$LoginScope = ([string]$Data).replace('/ ', '/')
            }
            [datetime]$UnixDateTime = '1970-01-01 00:00:00'
            $Date = Get-Date
            $UTCDate = [System.TimeZoneInfo]::ConvertTimeToUtc($Date)
            if ($thumbprint.length -gt 5) { 
                Write-Verbose "Receive-AzaOauthToken: Certificate: We will continue logging in with Certificate."
                if (($null -eq $global:AzaTPCertificate) -or ($Thumbprint -ne ($global:AzaTPCertificate).Thumbprint)) {
                    Write-Verbose "Receive-AzaOauthToken: Certificate: Starting search in CurrentUser\my."
                    $TPCertificate = Get-Item Cert:\CurrentUser\My\$Thumbprint -ErrorAction SilentlyContinue
                    if ($null -eq $TPCertificate) {
                        Write-Verbose "Receive-AzaOauthToken: Certificate not found in CurrentUser. Continuing in LocalMachine\my."
                        $TPCertificate = Get-Item Cert:\localMachine\My\$Thumbprint -ErrorAction SilentlyContinue
                    }
                    if ($null -eq $TPCertificate) {
                        throw "We did not find a certificate under: $Thumbprint. Exiting script..."
                    }
                }
                else {
                    $TPCertificate = $global:AzaTPCertificate
                    Write-Verbose "Receive-AzaOauthToken: Certificate: We already obtained a certificate from a previous login. We will continue logging in."
                }
            }
        }
        catch {
            throw $_.Exception.Message          
        }
    }
    process {
        try {
            if ($ClientSecret) {
                if ($clientsecret.gettype().name -ne 'securestring') {
                    $Secret = $ClientSecret | ConvertTo-SecureString -AsPlainText -Force
                }
                else {
                    $Secret = $ClientSecret
                }
                $TempPass = [PSCredential]::new(".", $Secret).GetNetworkCredential().Password
                if (!($global:AzaAppPass)) {
                    Write-Verbose "Receive-AzaOauthToken: ApplicationSecret: This is the first time logging in with a ClientSecret."
                    $Builder = [Microsoft.Identity.Client.ConfidentialClientApplicationBuilder]::Create($ApplicationID).WithTenantId($Tenant).WithClientSecret($TempPass).Build()
                    $global:AzaAppPass = $Builder.AcquireTokenForClient($LoginScope).ExecuteAsync()
                    if ($null -eq $global:AzaAppPass.result.AccessToken) {
                        throw 'We did not retrieve an Oauth access token to continue script. Exiting script...'
                    }
                    else {
                        $global:AzaheaderParameters = @{
                            Authorization = $global:AzaAppPass.result.CreateAuthorizationHeader()
                        }
                        $global:AzaLoginType = 'ClientSecret'
                        $global:AzaSecret = $Secret
                    }
                }
                else {
                    Write-Verbose "Receive-AzaOauthToken: ApplicationSecret: Oauth token already exists from previously running cmdlets."
                    Write-Verbose "Receive-AzaOauthToken: ApplicationSecret: Running test to see if Oauth token expired."
                    $OauthExpiryTime = $global:AzaAppPass.Result.ExpiresOn.UtcDateTime
                    if ($OauthExpiryTime -le $UTCDate) {
                        Write-Verbose "Receive-AzaOauthToken: ApplicationSecret: Oauth token expired. Emptying Oauth variable and re-running function."
                        $global:AzaAppPass = $null
                        Receive-AzaOauthToken `
                            -ApplicationID $ApplicationID `
                            -Tenant $Tenant `
                            -ClientSecret $ClientSecret           
                    }
                    else {
                        Write-Verbose "Receive-AzaOauthToken: ApplicationSecret: Oauth token from last run is still active."
                    }
                }
            }
            elseif ($Certificate) {
                if (!($global:AzaCert)) {
                    Write-Verbose "Receive-AzaOauthToken: Certificate: This is the first time logging in with a Certificate."
                    $Builder = [Microsoft.Identity.Client.ConfidentialClientApplicationBuilder]::Create($ApplicationID).WithTenantId($tenant).WithCertificate($Certificate).Build()  
                    $global:AzaCert = $Builder.AcquireTokenForClient($LoginScope).ExecuteAsync()
                    if ($null -eq $global:AzaCert.result.AccessToken) {
                        throw 'We did not retrieve an Oauth access token to continue script. Exiting script...'
                    }
                    else {
                        $global:AzaheaderParameters = @{
                            Authorization = $global:AzaCert.result.CreateAuthorizationHeader()
                        }
                        $global:AzaLoginType = 'Certificate'
                        $global:AzaCertificate = $Certificate
                    }
                }
                else {
                    Write-Verbose "Receive-AzaOauthToken: Certificate: Oauth token already exists from previously running cmdlets."
                    Write-Verbose "Receive-AzaOauthToken: Certificate: Running test to see if Oauth token expired."
                    $OauthExpiryTime = $global:AzaCert.Result.ExpiresOn.UtcDateTime
                    if ($OauthExpiryTime -le $UTCDate) {
                        Write-Verbose "Receive-AzaOauthToken: Certificate: Oauth token expired. Emptying Oauth variable and re-running function."
                        $global:AzaCert = $null
                        Receive-AzaOauthToken `
                            -ApplicationID $ApplicationID `
                            -Certificate $Certificate `
                            -Tenant $Tenant
                    }
                    else {
                        Write-Verbose "Receive-AzaOauthToken: Certificate: Oauth token from last run is still active."
                    }
                }
            }
            elseif ($Thumbprint) {
                if (!($global:AzaTPrint)) {
                    Write-Verbose "Receive-AzaOauthToken: Certificate: This is the first time logging in with a Certificate."
                    $Builder = [Microsoft.Identity.Client.ConfidentialClientApplicationBuilder]::Create($ApplicationID).WithTenantId($tenant).WithCertificate($TPCertificate).Build()  
                    $global:AzaTPrint = $Builder.AcquireTokenForClient($LoginScope).ExecuteAsync()
                    if ($null -eq $global:AzaTPrint.result.AccessToken) {
                        throw 'We did not retrieve an Oauth access token to continue script. Exiting script...'
                    }
                    else {
                        $global:AzaheaderParameters = @{
                            Authorization = $global:AzaTPrint.result.CreateAuthorizationHeader()
                        }
                        $global:AzaLoginType = 'Thumbprint'
                        $global:AzaThumbprint = $Thumbprint
                        $global:AzaTPCertificate = $TPCertificate
                    }
                }
                else {
                    Write-Verbose "Receive-AzaOauthToken: Certificate: Oauth token already exists from previously running cmdlets."
                    Write-Verbose "Receive-AzaOauthToken: Certificate: Running test to see if Oauth token expired."
                    $OauthExpiryTime = $global:AzaTPrint.Result.ExpiresOn.UtcDateTime
                    if ($OauthExpiryTime -le $UTCDate) {
                        Write-Verbose "Receive-AzaOauthToken: Certificate: Oauth token expired. Emptying Oauth variable and re-running function."
                        $global:AzaTPrint = $null
                        Receive-AzaOauthToken `
                            -ApplicationID $ApplicationID `
                            -Thumbprint $Thumbprint `
                            -Tenant $Tenant
                    }
                    else {
                        Write-Verbose "Receive-AzaOauthToken: Certificate: Oauth token from last run is still active."
                    }
                }
            }
            elseif ($RedirectUri) { 
                if (!($global:AzaRU)) {
                    $Builder = [Microsoft.Identity.Client.PublicClientApplicationBuilder]::Create($ApplicationID).WithTenantId($Tenant).WithRedirectUri($RedirectUri).Build()
                    $global:AzaRU = $Builder.AcquireTokenInteractive($LoginScope).ExecuteAsync()
                    if ($null -eq $global:AzaRU.result.AccessToken) {
                        throw 'We did not retrieve an Oauth access token to continue script. Exiting script...'
                    }
                    else {
                        $global:AzaheaderParameters = @{
                            Authorization = $global:AzaRU.Result.CreateAuthorizationHeader()
                        }
                        $global:AzaLoginType = 'RedirectUri'
                        $global:AzaRedirectUri = $RedirectUri
                        $global:AzaLoginScope = $LoginScope
                    }
                }
                else {
                    Write-Verbose "Receive-AzaOauthToken: MFA UserCredentials: Oauth token already exists from previously running cmdlets."
                    Write-Verbose "Receive-AzaOauthToken: MFA UserCredentials: Running test to see if Oauth token expired."
                    $OauthExpiryTime = $global:AzaRU.Result.ExpiresOn.UtcDateTime
                    if ($OauthExpiryTime -le $UTCDate) {
                        Write-Verbose "Receive-AzaOauthToken: MFA UserCredentials: Oauth token expired. Emptying Oauth variable and re-running function."
                        $global:AzaRU = $null
                        Receive-AzaOauthToken `
                            -ApplicationID $ApplicationID `
                            -Tenant $Tenant `
                            -RedirectUri $RedirectUri `
                            -LoginScope $LoginScope
                    }
                    else {
                        Write-Verbose "Receive-AzaOauthToken: MFA UserCredentials: Oauth token from last run is still active."
                    }
                }
            }
            elseif ($userCredentials) {
                $loginURI = "https://login.microsoft.com"
                $Resource = 'https://management.azure.com'
                $Body = @{
                    grant_type = 'password';
                    resource   = $Resource;
                    username   = $($userCredentials.UserName)
                    password   = $($UserCredentials.Password)
                    client_id  = $ApplicationID;
                    scope      = 'openid'
                }
                if (!($global:AzaBasic)) {
                    $global:AzaBasic = Invoke-RestMethod -Method Post -Uri $loginURI/$Tenant/oauth2/token?api-version=1.0 -Body $Body -UseBasicParsing
                    if ($null -eq $global:AzaBasic.access_token) {
                        throw 'We did not retrieve an Oauth access token to continue script. Exiting script...'
                    }
                    else {
                        $global:AzaheaderParameters = @{
                            Authorization = "$($global:AzaBasic.token_type) $($global:AzaBasic.access_token)"
                        }
                        $global:AzaLoginType = 'UserCredentials'
                        $global:AzaUserCredentials = $UserCredentials
                    }
                }
                else {
                    Write-Verbose "Receive-AzaOauthToken: Basic UserCredentials: Oauth token already exists from previously running cmdlets."
                    Write-Verbose "Receive-AzaOauthToken: Basic UserCredentials: Running test to see if Oauth token expired."
                    $OauthExpiryTime = $UnixDateTime.AddSeconds($global:AzaBasic.expires_on)
                    if ($null -ne $global:AzaBasic.refresh_token) {
                        Write-Verbose "Receive-AzaOauthToken: "
                        $Body = @{
                            refresh_token = $global:AzaBasic.refresh_token
                            grant_type    = 'refresh_token'
                        }
                        $global:AzaBasic = Invoke-RestMethod -Method Post -Uri $loginURI/$Tenant/oauth2/token?api-version=1.0 -Body $Body -UseBasicParsing
                        if ($null -eq $global:AzaBasic.access_token) {
                            Write-Warning 'We did not retrieve an Oauth access token from the refresh_token. Re-trying to log in with new token.'
                        }
                        else {
                            $global:AzaheaderParameters = @{
                                Authorization = "$($global:AzaBasic.token_type) $($global:AzaBasic.access_token)"
                            }
                            $global:AzaLoginType = 'UserCredentials'
                            $global:AzaUserCredentials = $UserCredentials
                        }
                    }
                    if ($OauthExpiryTime -le $UTCDate) {
                        $global:AzaBasic = $null
                        Receive-AzaOauthToken `
                            -UserCredentials $UserCredentials `
                            -Tenant $Tenant `
                            -ApplicationID $ApplicationID
                    }
                    else {
                        Write-Verbose "Receive-AzaOauthToken: Basic UserCredentials: Oauth token from last run is still active."
                    }
                }
            }
        }
        catch {
            throw $_.Exception.Message
        }
    }
    end {
    }
}

function ConvertTo-AzaJson {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        $InputObject,
        [Parameter(Mandatory = $false)]
        [switch]
        $Validate
    )
    begin {
        
    }  
    process {
        try {
            $null = ConvertFrom-Json -InputObject $InputObject -ErrorAction Stop
            $ValidateJson = $true
        }
        catch {
            if ($Validate -ne $true) {
                $InputObject = ConvertTo-Json -InputObject $InputObject -Depth 100
            }
            else {
                $ValidateJson = $false
            }
        }    
    }
    end {
        if ($Validate -ne $true) {
            return $InputObject
        }
        else {
            return $ValidateJson
        }
    }
}
#endregion internal