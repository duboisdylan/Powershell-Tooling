param(
    [Alias("FilePath")]
    [parameter(Mandatory=$true)][string]$LoadFromFile
)


Begin {
    # Vérification du path.
    if (!(Test-Path $LoadFromFile)){Throw "Incorrect Source Path."}

    $Import = Import-CSv -Path $LoadFromFile -Delimiter ";"
    # Connect-ExchangeOnline -ShowBanner:$false
}

Process
{
    Foreach ($Email in $Import)
    {
        Set-Mailbox $Email.EmailAdress -EmailAddresses @{add="smtp:$($Email.ProxyAddress)"}
        Write-Host "Added $($Email.ProxyAddress) to $($Email.EmailAdress)" -ForegroundColor Green
    }
}