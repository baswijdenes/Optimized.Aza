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

    .PARAMETER ManagedIdentity
    This is a switch for when it's a Managed Identity authenticating to Azure REST API.

    .PARAMETER Tenant
    Tenant is the TenantID or onmicrosoft.com address. Don't confuse this with ApplicationID.

    I should look like this:
    'XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXX'
    Or
    XXXXXXX.onmicrosoft.com

    .PARAMETER Resource
    Default Resource is the Azure REST API.
    -Resource accepts other Azure REST APIs like the Azure Storage API: https://docs.microsoft.com/en-us/rest/api/storageservices/.
    Resource URL is:'https://storage.azure.com/.default'.
    
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
    Connect-Aza -UserCredentials $Cred -Tenant 'XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXX' -ApplicationID 'XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXX'

    .EXAMPLE
    Connect-Aza -redirectUri 'msalXXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXX://auth' -Tenant 'XXXXXXXX.onmicrosoft.com'  -ApplicationID 'XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXX'
    
    .EXAMPLE
    Connect-Aza -ClientSecret '1yD3h~.KgROPO.K1sbRF~XXXXXXXXXXXXX' -ApplicationID 'XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXX' -Tenant 'XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXX' -Resource 'https://storage.azure.com/.default'

    .EXAMPLE
    Connect-Aza -ManagedIdentity -Resource 'https://management.azure.com'
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'Certificate')]
        [ValidateScript( { ($_.length -eq 40) -or ([System.Security.Cryptography.X509Certificates.X509Certificate2]$_) })]
        [Alias('Thumbprint')]
        $Certificate,
        [Parameter(Mandatory = $true, ParameterSetName = 'PAT')]
        $PAT,
        [Parameter(Mandatory = $true, ParameterSetName = 'ClientSecret')]
        [string]
        $ClientSecret, 
        [Parameter(Mandatory = $true, ParameterSetName = 'RedirectUri')]
        [String]
        $RedirectUri,
        [Parameter(Mandatory = $true, ParameterSetName = 'Credentials')]
        [System.Net.ICredentials]
        $UserCredentials,
        [Parameter(Mandatory = $true, ParameterSetName = 'Thumbprint')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Certificate')]
        [Parameter(Mandatory = $true, ParameterSetName = 'ClientSecret')]
        [Parameter(Mandatory = $true, ParameterSetName = 'RedirectUri')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Credentials')]
        [String]
        $ApplicationID,
        [Parameter(Mandatory = $true, ParameterSetName = 'Thumbprint')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Certificate')]
        [Parameter(Mandatory = $true, ParameterSetName = 'ClientSecret')]
        [Parameter(Mandatory = $true, ParameterSetName = 'RedirectUri')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Credentials')]
        [String]
        $Tenant,
        [Parameter(Mandatory = $false, ParameterSetName = 'Thumbprint')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Certificate')]
        [Parameter(Mandatory = $false, ParameterSetName = 'ClientSecret')]
        [Parameter(Mandatory = $false, ParameterSetName = 'RedirectUri')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Credentials')]
        [Parameter(Mandatory = $false, ParameterSetName = 'ManagedIdentity')]
        [string]
        $Resource = 'https://management.azure.com/.default',
        [Parameter(Mandatory = $false)]
        [Switch]
        $Force,
        [Parameter(Mandatory = $false, ParameterSetName = 'ManagedIdentity')]
        [Switch]
        $ManagedIdentity
    )
    begin {
        if ($Force) {
            Write-Verbose 'Connect-Aza: -Force parameter found. Running Disconnect-Aza to force a log on.'
            $null = Disconnect-Aza
        }
        else {
            Initialize-AzaConnect
        }
        if ($Certificate.length -eq 40) {
            $Thumbprint = $Certificate
        }
    }
    process {
        if ($Thumbprint) {
            Write-Verbose "Connect-Aza: Thumbprint: Logging in with Thumbprint."
            Receive-AzaOauthToken `
                -ApplicationID $ApplicationID `
                -Tenant $Tenant `
                -Thumbprint $Thumbprint `
                -Resource $Resource 
        }
        elseif ($Certificate) {
            Write-Verbose "Connect-Aza: Certificate: Logging in with certificate."
            Receive-AzaOauthToken `
                -ApplicationID $ApplicationID `
                -Tenant $Tenant `
                -Certificate $Certificate `
                -Resource $Resource 
        }
        elseif ($ClientSecret) {
            Write-Verbose "Connect-Aza: ClientSecret: Logging in with ClientSecret."
            Receive-AzaOauthToken `
                -ApplicationID $ApplicationID `
                -Tenant $Tenant `
                -ClientSecret $ClientSecret `
                -Resource $Resource
        }
        elseif ($RedirectUri) {
            Write-Verbose "Connect-Aza: MFA UserCredentials: Logging in with MFA UserCredentials."
            Receive-AzaOauthToken `
                -ApplicationID $ApplicationID `
                -Tenant $Tenant `
                -RedirectUri $RedirectUri `
                -Resource $Resource
        }
        elseif ($UserCredentials) {
            Write-Verbose "Connect-Aza: Basic UserCredentials: Logging in with Basic UserCredentials."
            Receive-AzaOauthToken `
                -ApplicationID $ApplicationID `
                -Tenant $Tenant `
                -UserCredentials $UserCredentials `
                -Resource $Resource
        }
        elseif ($PAT) {
            $Resource = 'Azure DevOps'
            Write-Verbose "Connect-Aza: PAT: Logging in with Personal Access Token (Azure DevOps)."
            Receive-AzaOauthToken `
                -PAT $PAT
        }
        elseif ($ManagedIdentity) {
            Receive-AzaOauthToken `
                -Resource $Resource `
                -ManagedIdentity
        }
    }
    end {
        return "You've successfully logged in to $Resource."
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
            Write-Verbose "Disconnect-Aza: Disconnecting from $global:AzaResource."
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
    
    .PARAMETER CustomHeader
    Use -CustomHeader to add extra headers, after the cmdlet ran it will convert back to original header.

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
        $Once,
        [Parameter(Mandatory = $false)]
        [object]
        $CustomHeader
    )
    begin {
        Update-AzaOauthToken
        if ($CustomHeader) {
            Enable-AzaCustomHeader -CustomHeader $CustomHeader
        }
    }
    process {
        try {
            Write-Verbose "Get-Aza: Getting results from $URL."
            $Result = Invoke-WebRequest -UseBasicParsing -Headers $global:AzaHeaderParameters -Uri $URL -Method get
            if ($result.Headers.'Content-Type' -like "application/octet-stream*") {
                Write-Verbose "Get-Aza: Result is in Csv format. Converting to Csv and returning end result."
                $EndResult = ConvertFrom-Csv -InputObject $Result
            }
            elseif ($result.Headers.'Content-Type' -like "application/xml*") {
                Write-Verbose "Get-Aza: Result is in XML format. Converting to XML and returning end result."     
                $Content = $Result.Content.Substring(3, $Response.Content.Length - 3)
                $XmlToJSon = [Newtonsoft.Json.JsonConvert]::SerializeXmlNode([xml]$Content)
                $JsonToObject = ConvertFrom-Json -InputObject $XmlToJson
                Write-Warning 'Get-Mga: To see different data types (Object, JSON, XML, Original) use $global:AzaDataType.'
                $global:AzaDataType = [PSCustomObject]@{
                    Object = $JsonToObject
                    JSON   = $XmlToJSon
                    XML    = $Content
                    OG     = $Result
                }
                $Result = $JsonToObject | Format-Custom -Depth 1000000000
                $EndResult = $Result
            }
            elseif ($result.Headers.'Content-Type' -like "application/json*") {   
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
            else {
                $EndResult = $Result
                throw "Result is in an unrecognizable format: $($Result.Headers)."
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
            if ($CustomHeader) {
                Disable-AzaCustomHeader
            }
            throw $_.Exception.Message
        }
    }
    end {
        if ($CustomHeader) {
            Disable-AzaCustomHeader
        }
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
        
    .PARAMETER CustomHeader
    Use -CustomHeader to add extra headers, after the cmdlet ran it will convert back to original header.

    .PARAMETER Put
    Use the -Put switch when the method is a Put instead of Post.

    .PARAMETER KeepFormat
    By default the InputObject is converted to JSON. With the -KeepFormat switch it will keep the original format.
    
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
        $Put,
        [Parameter(Mandatory = $false)]
        [object]
        $CustomHeader,
        [Parameter(Mandatory = $false)]
        [switch]
        $KeepFormat
    )
    begin {
        Update-AzaOauthToken
        if ($KeepFormat -ne $true) {
            $InputObject = ConvertTo-AzaJson -InputObject $InputObject
        } 
        else {
            Write-verbose 'Post-Aza: begin: KeepFormat switch found. Data will not be converted to JSON.'
        }
        if ($CustomHeader) {
            Enable-AzaCustomHeader -CustomHeader $CustomHeader
        }
    }
    process {
        try {
            if ($InputObject) {
                if (!($Put -eq $true)) {
                    Write-Verbose "Post-Aza: Posting InputObject to $global:AzaResource."
                    $Result = Invoke-RestMethod -Uri $URL -Headers $global:AzaHeaderParameters -Method post -Body $InputObject -ContentType application/json
                } 
                else {
                    Write-Verbose "Post-Aza: Putting InputObject to $global:AzaResource."
                    $Result = Invoke-RestMethod -Uri $URL -Headers $global:AzaHeaderParameters -Method put -Body $InputObject -ContentType application/json
                }
            }
            else {
                if (!($Put -eq $true)) {
                    $Result = Invoke-RestMethod -Uri $URL -Headers $global:AzaHeaderParameters -Method post -ContentType application/json   
                } 
                else {
                    $Result = Invoke-RestMethod -Uri $URL -Headers $global:AzaHeaderParameters -Method put -ContentType application/json   
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
                if ($CustomHeader) {
                    Disable-AzaCustomHeader
                }
                throw $_.Exception.Message
            }
        }
        catch {
            if ($CustomHeader) {
                Disable-AzaCustomHeader
            }
            throw $_.Exception.Message
        }
    }
    end {
        if ($CustomHeader) {
            Disable-AzaCustomHeader
        }
        Write-Verbose "Post-Aza: We've successfully Posted the data to $global:AzaResource."
        return $Result
    }
}

function Put-Aza {
    <#
    .LINK
    https://github.com/baswijdenes/Optimized.Aza/tree/main

    .SYNOPSIS
    Put-Aza can be seen as the 'new' Verb.
    With this cmdlet you can create objects in Azure.

    .PARAMETER URL
    URL to 'PUT' to.
    
    .PARAMETER InputObject
    -InputObject will accept a PSObject or JSON.
    
    .PARAMETER CustomHeader
    Use -CustomHeader to add extra headers, after the cmdlet ran it will convert back to original header.
     
    .PARAMETER KeepFormat
    By default the InputObject is converted to JSON. With the -KeepFormat switch it will keep the original format.
    
    .EXAMPLE
    $CustomHeader = @{
    'x-ms-blob-type' = 'BlockBlob'
    'content-type' = 'application/octet-stream'
    }

    $StorageAccount = 'baswijdenes'
    $Container = 'testblob'
    $Blob = 'cert.cer'

    #$Test = Get-Content  C:\Temp\10days.cer -Raw
    $test = [System.IO.File]::OpenRead('C:\Temp\10days.cer')
    $URL = 'https://{0}.blob.core.windows.net/{1}/{2}' -f $StorageAccount, $Container, $blob
    Put-Aza -URL $URL -CustomHeader $CustomHeader -InputObject $test -KeepFormat -Verbose
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
        [object]
        $CustomHeader,
        [Parameter(Mandatory = $false)]
        [switch]
        $KeepFormat
    )  
    begin {
        Write-Verbose 'Put-Aza: begin: Put-Aza uses Post-Aza in the backend.'
        $Splatting = @{
            URL = $URL
            Put = $true
        }
        if ($InputObject) {
            $Splatting.Add('InputObject', $InputObject)
        }
        if ($CustomHeader) {
            $Splatting.Add('CustomHeader', $CustomHeader)
        }
        if ($KeepFormat) {
            $Splatting.Add('KeepFormat', $KeepFormat)         
        }
    }
    process {
        try {
            Post-Aza @Splatting
            <#  if ($InputObject) {
                if ($CustomHeader) {
                    $Result = Post-Aza -URL $URL -InputObject $InputObject -put -CustomHeader $CustomHeader
                }
                else {
                    $Result = Post-Aza -URL $URL -InputObject $InputObject -put
                }
            }
            else {
                if ($CustomHeader) {
                    $Result = Post-Aza -URL $URL -Put -CustomHeader $CustomHeader
                }
                else {
                    $Result = Post-Aza -URL $URL -Put                    
                }
            }
            #>
        }
        catch {
            throw $_.Exception.Message
        }

    }
    end {
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

    .PARAMETER CustomHeader
    Use -CustomHeader to add extra headers, after the cmdlet ran it will convert back to original header.

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
        $InputObject,
        [Parameter(Mandatory = $false)]
        [object]
        $CustomHeader
    )
    begin {
        Update-AzaOauthToken
        $ValidateJson = ConvertTo-AzaJson -InputObject $InputObject -Validate
        if ($CustomHeader) {
            Enable-AzaCustomHeader -CustomHeader $CustomHeader
        }
    }
    process {
        try {
            $InputObject = ConvertTo-AzaJson -InputObject $InputObject
            Write-Verbose "Patch-Aza: Patching InputObject to $global:AzaResource."
            $Result = Invoke-RestMethod -Uri $URL -Headers $global:AzaHeaderParameters -Method Patch -Body $InputObject -ContentType application/json
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
            if ($CustomHeader) {
                Disable-AzaCustomHeader
            }
            throw $_.Exception.Message
        }
    }
    end {
        if ($CustomHeader) {
            Disable-AzaCustomHeader
        }
        Write-Verbose "Patch-Aza: We've successfully Patched the data to $global:AzaResource."
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
        
    .PARAMETER CustomHeader
    Use -CustomHeader to add extra headers, after the cmdlet ran it will convert back to original header.
    
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
        $InputObject,
        [Parameter(Mandatory = $false)]
        [object]
        $CustomHeader
    )
    begin {
        Update-AzaOauthToken
        if ($CustomHeader) {
            Enable-AzaCustomHeader -CustomHeader $CustomHeader
        }
    }
    process {
        try {
            if ($InputObject) {
                Write-Verbose "Delete-Aza: Deleting InputObject on $URL to $global:AzaResource."
                $InputObject = ConvertTo-AzaJson -InputObject $InputObject
                $Result = Invoke-RestMethod -Uri $URL -body $InputObject -Headers $global:AzaHeaderParameters -Method Delete -ContentType application/json
            }
            else {
                Write-Verbose "Delete-Aza: Deleting conent on $URL to $global:AzaResource."
                $Result = Invoke-RestMethod -Uri $URL -Headers $global:AzaHeaderParameters -Method Delete -ContentType application/json
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
            if ($CustomHeader) {
                Disable-AzaCustomHeader
            }
            throw $_.Exception.Message
        }
    }
    end {
        if ($CustomHeader) {
            Disable-AzaCustomHeader
        }
        Write-Verbose "Delete-Aza: We've successfully deleted the data on $global:AzaResource."
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
            -ClientSecret $global:AzaSecret `
            -Resource $($global:AzaResource)
    }
    elseif ($null -ne $global:AzaCert) {
        Receive-AzaOauthToken `
            -ApplicationID $global:AzaApplicationID `
            -Tenant $global:AzaTenant `
            -Certificate $global:AzaCertificate `
            -Resource $($global:AzaResource)
    }
    elseif ($null -ne $global:AzaTPrint) {
        Receive-AzaOauthToken `
            -ApplicationID $global:AzaApplicationID `
            -Tenant $global:AzaTenant `
            -Thumbprint $global:AzaThumbprint `
            -Resource $($global:AzaResource) 
    }
    elseif ($null -ne $global:AzaRU) {
        Receive-AzaOauthToken `
            -ApplicationID $global:AzaApplicationID `
            -Tenant $global:AzaTenant `
            -RedirectUri $global:AzaRedirectUri `
            -Resource $($global:AzaResource)
    }
    elseif ($null -ne $global:AzaBasic) {
        Receive-AzaOauthToken `
            -ApplicationID $global:AzaApplicationID `
            -Tenant $global:AzaTenant `
            -UserCredentials $global:AzaUserCredentials `
            -Resource $($global:AzaResource)
    }
    elseif ($null -ne $global:AzaPAT) {
    }
    elseif ($null -ne $global:AzaManagedIdentity) {
        Receive-AzaOauthToken `
            -ManagedIdentity `
            -Resource $($global:AzaResource)
    }
    else {
        Throw "You need to run Connect-Aza before you can continue. Exiting script..."
    }
}

function Receive-AzaOauthToken {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'Thumbprint')]
        [string]
        $Thumbprint, 
        [Parameter(Mandatory = $true, ParameterSetName = 'Certificate')]
        $Certificate, 
        [Parameter(Mandatory = $true, ParameterSetName = 'ClientSecret')]
        $ClientSecret, 
        [Parameter(Mandatory = $true, ParameterSetName = 'PAT')]
        $PAT, 
        [Parameter(Mandatory = $true, ParameterSetName = 'ManagedIdentity')]
        [switch]
        $ManagedIdentity,
        [Parameter(Mandatory = $true, ParameterSetName = 'Redirecturi')]
        [string]
        $RedirectUri,
        [Parameter(Mandatory = $true, ParameterSetName = 'UserCredentials')]
        [System.Net.ICredentials]
        $UserCredentials,
        [Parameter(Mandatory = $true, ParameterSetName = 'UserCredentials')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Thumbprint')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Certificate')]
        [Parameter(Mandatory = $true, ParameterSetName = 'ClientSecret')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Redirecturi')]
        [Parameter(Mandatory = $true, ParameterSetName = 'ManagedIdentity')]
        $Resource,
        [Parameter(Mandatory = $true, ParameterSetName = 'UserCredentials')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Thumbprint')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Certificate')]
        [Parameter(Mandatory = $true, ParameterSetName = 'ClientSecret')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Redirecturi')]
        [string]
        $ApplicationID,
        [Parameter(Mandatory = $true, ParameterSetName = 'UserCredentials')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Thumbprint')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Certificate')]
        [Parameter(Mandatory = $true, ParameterSetName = 'ClientSecret')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Redirecturi')]
        [string]
        $Tenant
    )
    begin {
        try { 
            $global:AzaResource = $Resource
            [System.Collections.Generic.List[String]]$Resource = @($($Resource))
            if ($null -eq $PAT) {
                $global:AzaTenant = $Tenant
                $global:AzaApplicationID = $ApplicationID
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
                    $global:AzaAppPass = $Builder.AcquireTokenForClient($Resource).ExecuteAsync()
                    if ($null -eq $global:AzaAppPass.result.AccessToken) {
                        throw 'We did not retrieve an Oauth access token to continue script. Exiting script...'
                    }
                    else {
                        if (($($Resource) -like "*storage.azure.com*") -or ($($Resource) -like "*blob.core.windows.net*")) {
                            Write-Verbose "Receive-OauthToken: ApplicationSecret: Resource is $Resource. Creating the header parameter."
                            $global:AzaHeaderParameters = @{
                                Authorization  = $global:AzaAppPass.result.CreateAuthorizationHeader()
                                'x-ms-version' = '2019-02-02'
                                'x-ms-date'    = $([datetime]::UtcNow.ToString('R'))
                                Accept         = 'application/xml;charset=utf8'
                            }
                        } 
                        else {
                            $global:AzaHeaderParameters = @{
                                Authorization = $global:AzaAppPass.result.CreateAuthorizationHeader()
                            }
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
                            -ClientSecret $ClientSecret `
                            -Resource $Resource         
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
                    $global:AzaCert = $Builder.AcquireTokenForClient($Resource).ExecuteAsync()
                    if ($null -eq $global:AzaCert.result.AccessToken) {
                        throw 'We did not retrieve an Oauth access token to continue script. Exiting script...'
                    }
                    else {
                        $global:AzaHeaderParameters = @{
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
                            -Tenant $Tenant `
                            -Resource $Resource
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
                    $global:AzaTPrint = $Builder.AcquireTokenForClient($Resource).ExecuteAsync()
                    if ($null -eq $global:AzaTPrint.result.AccessToken) {
                        throw 'We did not retrieve an Oauth access token to continue script. Exiting script...'
                    }
                    else {
                        $global:AzaHeaderParameters = @{
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
                            -Tenant $Tenant `
                            -Resource $Resource
                    }
                    else {
                        Write-Verbose "Receive-AzaOauthToken: Certificate: Oauth token from last run is still active."
                    }
                }
            }
            elseif ($RedirectUri) { 
                if (!($global:AzaRU)) {
                    $Builder = [Microsoft.Identity.Client.PublicClientApplicationBuilder]::Create($ApplicationID).WithTenantId($Tenant).WithRedirectUri($RedirectUri).Build()
                    $global:AzaRU = $Builder.AcquireTokenInteractive($Resource).ExecuteAsync()
                    if ($null -eq $global:AzaRU.result.AccessToken) {
                        throw 'We did not retrieve an Oauth access token to continue script. Exiting script...'
                    }
                    else {
                        $global:AzaHeaderParameters = @{
                            Authorization = $global:AzaRU.Result.CreateAuthorizationHeader()
                        }
                        $global:AzaLoginType = 'RedirectUri'
                        $global:AzaRedirectUri = $RedirectUri
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
                            -Resource $Resource
                    }
                    else {
                        Write-Verbose "Receive-AzaOauthToken: MFA UserCredentials: Oauth token from last run is still active."
                    }
                }
            }
            elseif ($userCredentials) {
                $loginURI = "https://login.microsoft.com"
                if ($Resource -like "*.default*") {
                    $Resource = $Resource.Replace('.default', '')
                }
                $Body = @{
                    grant_type = 'password'
                    resource   = $($Resource)
                    username   = $($userCredentials.UserName)
                    password   = $($UserCredentials.Password)
                    client_id  = $ApplicationID
                }
                if (!($global:AzaBasic)) {
                    $global:AzaBasic = Invoke-RestMethod -Method Post -Uri $loginURI/$Tenant/oauth2/token?api-version=1.0 -Body $Body -UseBasicParsing
                    if ($null -eq $global:AzaBasic.access_token) {
                        throw 'We did not retrieve an Oauth access token to continue script. Exiting script...'
                    }
                    else {
                        $global:AzaHeaderParameters = @{
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
                        Write-Verbose "Receive-AzaOauthToken: Using the refresh token to get a new Oauth Token."
                        $Body = @{
                            refresh_token = $global:AzaBasic.refresh_token
                            grant_type    = 'refresh_token'
                        }
                        $global:AzaBasic = Invoke-RestMethod -Method Post -Uri $loginURI/$Tenant/oauth2/token?api-version=1.0 -Body $Body -UseBasicParsing
                        if ($null -eq $global:AzaBasic.access_token) {
                            Write-Warning 'We did not retrieve an Oauth access token from the refresh_token. Re-trying to log in with new token.'
                        }
                        else {
                            $global:AzaHeaderParameters = @{
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
                            -ApplicationID $ApplicationID `
                            -Resource $Resource
                    }
                    else {
                        Write-Verbose "Receive-AzaOauthToken: Basic UserCredentials: Oauth token from last run is still active."
                    }
                }
            }
            elseif ($ManagedIdentity) {
                $loginURI = $env:IDENTITY_ENDPOINT
                if ($Resource -like "*.default*") {
                    $Resource = $Resource.Replace('.default', '')
                }
                $Body = @{
                    resource = $($Resource)
                }
                $GetTokenHeader = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
                $GetTokenHeader.add('X-IDENTITY-HEADER', $env:IDENTITY_HEADER)
                $GetTokenHeader.Add('Metadata', 'True')
                if (!($global:AzaManagedIdentity)) {
                    $global:AzaManagedIdentity = Invoke-RestMethod -Method Post -Uri $loginURI -Headers $GetTokenHeader -Body $Body -ContentType 'application/x-www-form-urlencoded'
                    if ($null -eq $global:AzaManagedIdentity.access_token) {
                        throw 'We did not retrieve an Oauth access token to continue script. Exiting script...'
                    }
                    else {
                        $global:AzaHeaderParameters = @{
                            Authorization = "$($global:AzaManagedIdentity.token_type) $($global:AzaManagedIdentity.access_token)"
                        }
                        $global:AzaLoginType = 'ManagedIdentity'
                    }
                }
                else {
                    Write-Verbose "Receive-AzaOauthToken: ManagedIdentity: Oauth token already exists from previously running cmdlets."
                    Write-Verbose "Receive-AzaOauthToken: ManagedIdentity: Running test to see if Oauth token expired."
                    $OauthExpiryTime = $UnixDateTime.AddSeconds($global:AzaManagedIdentity.expires_on)
                    if ($null -ne $global:AzaManagedIdentity.refresh_token) {
                        Write-Verbose "Receive-AzaOauthToken: Using the refresh token to get a new Oauth Token."
                        $Body = @{
                            refresh_token = $global:AzaManagedIdentity.refresh_token
                            grant_type    = 'refresh_token'
                        }
                        $global:AzaManagedIdentity = Invoke-RestMethod -Method Post -Uri $loginURI/$Tenant/oauth2/token?api-version=1.0 -Body $Body -UseBasicParsing
                        if ($null -eq $global:AzaManagedIdentity.access_token) {
                            Write-Warning 'We did not retrieve an Oauth access token from the refresh_token. Re-trying to log in with new token.'
                        }
                        else {
                            $global:AzaHeaderParameters = @{
                                Authorization = "$($global:AzaManagedIdentity.token_type) $($global:AzaManagedIdentity.access_token)"
                            }
                            $global:AzaLoginType = 'ManagedIdentity'
                        }
                    }
                    if ($OauthExpiryTime -le $UTCDate) {
                        $global:AzaManagedIdentity = $null
                        Receive-AzaOauthToken `
                            -ManagedIdentity `
                            -Resource $Resource
                    }
                    else {
                        Write-Verbose "Receive-AzaOauthToken: Basic UserCredentials: Oauth token from last run is still active."
                    }
                }
            }
            elseif ($PAT) {
                $global:AzaPAT = $PAT
                $global:AzaLoginType = 'PAT'
                $Base64PAT = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes(":$($PAT)"))
                $global:AzaHeaderParameters = @{Authorization = "Basic $($Base64PAT)" }
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

function Enable-AzaCustomHeader {
    [CmdletBinding()]
    param (
        $CustomHeader
    )
    
    begin {
        Write-Verbose 'Enable-AzaCustomHeader: begin: saving original header.'
        $global:AzaOriginalHeader = @{}
        foreach ($Header in $global:AzaHeaderParameters.GetEnumerator()) {
            $global:AzaOriginalHeader.Add($Header.Key, $Header.Value)
        }
    }
    process {
        Write-Verbose 'Enable-AzaCustomHeader: begin: Merging headers.'
        # $global:AzaHeaderParameters = $global:AzaOriginalHeader + $CustomHeader
        foreach ($Header in $CustomHeader.GetEnumerator()) {
            try {
                if ($null -ne $global:AzaHeaderParameters[$Header.Key]) {
                    $global:AzaHeaderParameters[$item.Key] = $Header.Value
                }
                else {
                    $global:AzaHeaderParameters.Add($Header.key, $Header.Value)
                }
            }
            catch {
                throw $_.Exception.Message
            }
        }   
    } 
    end {
        Write-Verbose 'Enable-AzaCustomHeader: end: CustomHeader created.'
    }
}

function Disable-AzaCustomHeader {
    [CmdletBinding()]
    param (
    )
    begin {
        Write-Verbose 'Disable-AzaCustomHeader: begin: Changing back to original header.'
    }
    process {
        try {
            if ($global:AzaHeaderParameters -ne $global:AzaOriginalHeader) {
                Write-Verbose 'Disable-AzaCustomHeader: process: Reverting header.'
                $global:AzaHeaderParameters = @{}
                $global:AzaHeaderParameters += $global:AzaOriginalHeader
                Remove-Variable -Name 'AzaOriginalHeader' -Scope Global
            }
            else {
                Write-Verbose "Disable-AzaCustomHeader: process: Header is already original header."
            }
        }
        catch {
            throw 'Something went wrong with reverting back to original header. Re-login with Connect-Aza to continue.'
        }
    } 
    end {
        Write-Verbose 'Disable-AzaCustomHeader: end: Header changed back to original header.'
    }
}
#endregion internal