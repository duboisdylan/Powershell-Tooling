# Invoke-Monkey365
```
$param = @{`
    Instance = 'Microsoft365';`
    Collect = 'ExchangeOnline','Microsoft365','MicrosoftTeams','Purview','SharePointOnline';`
    PromptBehavior = 'SelectAccount';`
    IncludeEntraID = $true;`
    TenantID = 'XXXX-XXXX-XXXX-XXXX-XXXX';`
    ExportTo = 'HTML';`
    Threads = 4;`
}
Invoke-Monkey365 @param 
```