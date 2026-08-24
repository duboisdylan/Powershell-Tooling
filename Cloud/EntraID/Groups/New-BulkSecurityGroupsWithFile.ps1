param(
    [Alias("FilePath")]
    [parameter(Mandatory=$true)][string]$LoadFromFile
)

Begin {
        function Get-MgConnection {
        $context = Get-MgContext
        if (-not $context -or -not $context.Account) {
            Write-Host "Not connected to Microsoft Graph. Connecting..."
            Connect-MgGraph -Scopes "Group.ReadWrite.All", "Directory.ReadWrite.All" | Out-Null
            $context = Get-MgContext
            if (-not $context -or -not $context.Account) {
                Write-Host "❌ Failed to connect to Microsoft Graph." -ForegroundColor Red
                exit
            }
            else {
                Write-Host "Connected to Microsoft Graph as $($context.Account)."
            }
        }
        else {
            Write-Host "Already connected to Microsoft Graph as $($context.Account)."
        }
    }
    if (!(Test-Path $LoadFromFile)){Throw "Incorrect Source Path."}
    $GroupsList = Import-Csv -Path $LoadFromFile -Delimiter ";"

    Get-MgConnection
}

Process {
    Foreach ($Group in $GroupsList) {
        New-MgGroup -DisplayName $($Group.Name) -MailEnabled:$false -SecurityEnabled -MailNickname $($Group.Name) -Description $($Group.Description)
        Write-Host "$($Group.Name) - Created" -ForegroundColor Green
    }
}