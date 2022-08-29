# DECREPATED
Optimized.Aza is decrepated from today (August 29, 2022)  
For more: [Optimized.Aza: Decrepated](https://baswijdenes.com/optimized-aza-is-decrepated-from-today-august-29-2022/)

# Optimized.Aza
The default Rest API is the [Azure Management REST API](https://docs.microsoft.com/en-gb/rest/api/azure/). 
This API is fully tested and works. 

Other tested Azure REST APIs:
* Azure DevOps ([Connect-Aza](#Connect-Aza) with -PAT parameter)
* https://vault.azure.net/.default
* [Azure Storage API](https://docs.microsoft.com/en-us/rest/api/storageservices/).
* https://XXXXXXXXX.blob.core.windows.net/.default

The rest is untested but you can use them with [Connect-Aza](#Connect-Aza) and the -Resource parameter. You can set a CustomHeader by using -CustomHeader for each method. It will automatically refert back to the original header, so you'll have to use -CustomHeader per cmdlet.

Did you find issues that can easily be resolved? Then please leave some feedback on Github.

* If you want to know more about how to log in via a Client Secret (even with Delegated permissions), follow this **[link](https://bwit.blog/delegated-permissions-with-a-client-secret-by-adding-roles-to-a-service-principal/)**.
* If you want to know more about how to log in via MFA with a RedirectUri, follow this **[link](https://bwit.blog/how-to-start-with-microsoft-graph-in-powershell/#I_will_use_credentials)**.

The module handles the token and throttling for you. 

* [PowerShell Gallery](https://www.powershellgallery.com/packages/Optimized.Aza)
* [Submit an issue](https://github.com/baswijdenes/Optimized.Aza/issues)
* [My blog](https://bwit.blog/)

## UPDATES VERSIONS
* [0.0.0.3.md](./.Versions/0.0.0.3.md)
* [0.0.0.4.md](./.Versions/0.0.0.4.md)
* [0.0.0.5.md](./.Versions/0.0.0.5.md)
* [0.0.0.6.md](./.Versions/0.0.0.6.md)

# Optimized.Aza Cmdlets
* [Connect-Aza](#Connect-Aza)
* [Disconnect-Aza](#Disconnect-Aza)
* [Get-Aza](#Get-Aza)
* [Post-Aza](#Post-Aza)
* [Put-Aza](#put-aza)
* [Patch-Aza](#Patch-Aza)
* [Delete-Aza](#Delete-Aza)
  
---
## Connect-Aza
By selecting one of these parameters you log on with the following:
* **ClientSecret**: Will log you on with a ClientSecret.
* **Certificate**: Will log you on with a Certificate.
* **Thumbprint**: Will search for a Certificate under thumbprint on local device and log you on with a Certificate.
* **UserCredentials**: Will log you on with basic authentication.
* **RedirectUri**: Will log you on with MFA Authentication.
* **PAT**: Will log you on with a Personal Access token.
* **ManagedIdentity**: Will log a Managed Identity in Azure on.

The OauthToken is automatically renewed when you use cmdlets.

-Resource accepts other Azure REST APIs like the [Azure Storage API](https://docs.microsoft.com/en-us/rest/api/storageservices/): 'https://storage.azure.com/.default'.

Default is Azure REST API.

### Examples 
````PowerShell
Connect-Aza -ClientSecret '1yD3h~.KgROPO.K1sbRF~XXXXXXXXXXXXX' -ApplicationID 'XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXX' -Tenant 'XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXX' 

$Cert = get-ChildItem 'Cert:\LocalMachine\My\XXXXXXXXXXXXXXXXXXX'
Connect-Aza -Certificate $Cert -ApplicationID 'XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXX' -Tenant 'XXXXXXXX.onmicrosoft.com'

Connect-Aza -Thumbprint '3A7328F1059E9802FAXXXXXXXXXXXXXX' -ApplicationID 'XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXX' -Tenant 'XXXXXXXX.onmicrosoft.com' 

Connect-Aza -UserCredentials $Cred -Tenant 'XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXX' -ApplicationID 'XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXX'

Connect-Aza -redirectUri 'msalXXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXX://auth' -Tenant 'XXXXXXXX.onmicrosoft.com'  -ApplicationID 'XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXX'

Connect-Aza -ClientSecret '1yD3h~.KgROPO.K1sbRF~XXXXXXXXXXXXX' -ApplicationID 'XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXX' -Tenant 'XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXX' -Resource 'https://storage.azure.com/.default'

Connect-Aza -PAT 'XXXXXXXXXXXXXXXXXXXXXXXXXXXX'

Connect-Aza -ManagedIdentity -Resource 'https://management.azure.com'
````
---
## Disconnect-Aza
To update the OauthToken I fill the global scope with a number of properties. The properties are emptied by Disconnect-Aza.

### Examples 
````PowerShell
Disconnect-Aza
````
---
## Show-AzaAccessToken
With `Show-AzaAccessToken` you can request a decoded Token and see what is in their (normally you would paste it into (jwt.ms)[jwt.ms]).  
With the `-Roles` switch you can also only ask the roles you have assigned to the application registration.  

```PowerShell
Show-AzaAccessToken

Show-AzaAccessToken -Roles
```
---
## Get-Aza
Get-Aza speaks for itself. All you have to provide is the URL.

You can grab the URL via the browser developer tools, Fiddler, or from the [Azure REST API](https://docs.microsoft.com/en-gb/rest/api/azure/).
You can use all query parameters in the URL like some in the examples.

Use -CustomHeader to add extra headers, after the cmdlet ran it will convert back to original header.

It will automatically use the Next Link when there is one in the returned request. 

If you only want to retrieve data once, you can use the -Once parameter.
For example, I used this in the beta version to get the latest login. Nowadays this property is a property under the user: signInActivity.

### Examples 
````PowerShell
Get-Aza `
    -URL 'https://management.azure.com/subscriptions/81bdb7e0-2010-4c36-ba35-XXXXXXXX/resourceGroups/XXXXXXX/providers/Microsoft.Automation/automationAccounts/XXXXXX/runbooks/?api-version=2015-10-31'
````
---
## Post-Aza
Post-Aza can be seen as the 'new' Verb.
With this cmdlet you can create objects in Azure.

-InputObject will accept a PSObject or JSON. 

Use -KeepFormat when you want to keep the InputObject format (Default is converted to JSON).

Use -CustomHeader to add extra headers, after the cmdlet ran it will convert back to original header.

Use the -Put switch when the Method is Put instead.

The example below creates a new Azure Automation Runbook. 

### Examples 
````PowerShell
$InputObject = @{
    name = 'New-PUT-PSScript'
    properties = [PSCustomObject]@{
        runbookType = 'PowerShell'
        description = 'This is created from POST / PUT cmdlet'
        publishContentLink = [PSCustomObject]@{
            uri = 'https://raw.githubusercontent.com/baswijdenes/Bas.Wijdenes.IT.Blog/master/Get-AzureADUsers.ps1'
        }
    }
    Location = 'West Europe'
}

Post-Aza `
    -URL 'https://management.azure.com/subscriptions/81bdb7e0-2010-4c36-ba35-71c560e3b317/resourceGroups/RG-2019/providers/Microsoft.Automation/automationAccounts/AA-2019-01/runbooks/New-PUT-PSScript?api-version=2015-10-31' `
    -InputObject $InputObject `
    -Put
```` 
````PowerShell
$CustomHeader = @{
    'x-ms-blob-type' = 'BlockBlob'
    'content-type' = 'application/octet-stream'
}

$StorageAccount = 'baswijdenes'
$Container = 'testblob'
$Blob = 'certcert.cer'

#$Test = Get-Content  C:\Temp\10days.cer -Raw
$test = [System.IO.File]::OpenRead('C:\Temp\10days.cer')
$URL = 'https://{0}.blob.core.windows.net/{1}/{2}' -f $StorageAccount, $Container, $blob
Post-Aza -URL $URL -CustomHeader $CustomHeader -InputObject $test -KeepFormat -Put   
````
---
## Put-Aza
New cmdlet. It uses Post-Aza with Parameter -put switch.

-InputObject will accept a PSObject or JSON. 

Use -KeepFormat when you want to keep the InputObject format (Default is converted to JSON).

Use -CustomHeader to add extra headers, after the cmdlet ran it will convert back to original header.
````PowerShell
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
````
---
## Patch-Aza
Patch-Aza can be seen as the 'Update' Verb.

-InputObject will accept a PSObject or JSON. 

Use -KeepFormat when you want to keep the InputObject format (Default is converted to JSON).

Use -CustomHeader to add extra headers, after the cmdlet ran it will convert back to original header.

In the below example I change the description of a runbook in Azure Automation.

### Examples 
````PowerShell
$InputObject = [PSCustomObject]@{
    properties = [PSCustomObject]@{
        description = 'Update description with Patch-Aza'
    }
}

Patch-Aza `
    -URL 'https://management.azure.com/subscriptions/81bdb7e0-2010-4c36-ba35-71c560e3b317/resourceGroups/RG-2019/providers/Microsoft.Automation/automationAccounts/AA-2019-01/runbooks/New-PUT-PSScript?api-version=2015-10-31' `
    -InputObject $InputObject
````
---
## Delete-Aza
Delete speaks for itself. 
With this cmdlet you can remove objects from Azure. 

-URL is the URL for the item to delete.

-InputObject will accept a PSObject or JSON. 

Use -CustomHeader to add extra headers, after the cmdlet ran it will convert back to original header.

### Examples 
```PowerShell
Delete-Aza `
    -URL 'https://management.azure.com/subscriptions/81bdb7e0-2010-4c36-ba35-71c560e3b317/resourceGroups/RG-2019/providers/Microsoft.Automation/automationAccounts/AA-2019-01/runbooks/New-PUT-PSScript?api-version=2015-10-31'
```
