
# Optimized.Aza
This module is meant for the [Azure REST API](https://docs.microsoft.com/en-gb/rest/api/azure/).

* If you want to know more about how to log in via a Client Secret (even with Delegated permissions), follow this **[link](https://bwit.blog/delegated-permissions-with-a-client-secret-by-adding-roles-to-a-service-principal/)**.
* If you want to know more about how to log in via MFA with a RedirectUri, follow this **[link](https://bwit.blog/how-to-start-with-microsoft-graph-in-powershell/#I_will_use_credentials)**.

The module handles the token and throttling for you. 

* [PowerShell Gallery](https://www.powershellgallery.com/packages/Optimized.Aza)
* [Submit an issue](https://github.com/baswijdenes/Optimized.Aza/issues)
* [My blog](https://bwit.blog/)


# Optimized.Aza Cmdlets
* [Connect-Aza](#Connect-Aza)
* [Disconnect-Aza](#Disconnect-Aza)
* [Get-Aza](#Get-Aza)
* [Post-Aza](#Post-Aza)
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

The OauthToken is automatically renewed when you use cmdlets.

### Examples 
````PowerShell
Connect-Aza -ClientSecret '1yD3h~.KgROPO.K1sbRF~XXXXXXXXXXXXX' -ApplicationID 'XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXX' -Tenant 'XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXX' 

$Cert = get-ChildItem 'Cert:\LocalMachine\My\XXXXXXXXXXXXXXXXXXX'
Connect-Aza -Certificate $Cert -ApplicationID 'XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXX' -Tenant 'XXXXXXXX.onmicrosoft.com'

Connect-Aza -Thumbprint '3A7328F1059E9802FAXXXXXXXXXXXXXX' -ApplicationID 'XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXX' -Tenant 'XXXXXXXX.onmicrosoft.com' 

Connect-Aza -UserCredentials $Cred -Tenant 'XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXX' -ApplicationID 'XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXX'

Connect-Aza -redirectUri 'msalXXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXX://auth' -Tenant 'XXXXXXXX.onmicrosoft.com'  -ApplicationID 'XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXX'
````
---
## Disconnect-Aza
To update the OauthToken I fill the global scope with a number of properties. The properties are emptied by Disconnect-Aza.

### Examples 
````PowerShell
Disconnect-Aza
````
---
## Get-Aza
Get-Aza speaks for itself. All you have to provide is the URL.

You can grab the URL via the browser developer tools, Fiddler, or from the [Microsoft Graph docs](https://docs.microsoft.com/en-us/graph/overview).
You can use all query parameters in the URL like some in the examples.

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
---
## Patch-Aza
Patch-Aza can be seen as the 'Update' Verb.

-InputObject will accept a PSObject or JSON. 

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

### Examples 
```PowerShell
Delete-Aza `
    -URL 'https://management.azure.com/subscriptions/81bdb7e0-2010-4c36-ba35-71c560e3b317/resourceGroups/RG-2019/providers/Microsoft.Automation/automationAccounts/AA-2019-01/runbooks/New-PUT-PSScript?api-version=2015-10-31'
```
