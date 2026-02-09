param(
    [Alias("FilePath")]
    [parameter(Mandatory=$true)][string]$LoadFromFile
)

Begin {
    if (!(Test-Path $LoadFromFile)){Throw "Incorrect Source Path."}
    $UsersList=Get-Content -Path $LoadFromFile
}

Process {
    Foreach ($User in $UsersList) {
        Write-Host "Removing User: $User" -ForegroundColor Yellow
        try {
                Start-Sleep -Seconds 2
                Remove-ADUSer -Identity $User -Confirm:$false -ErrorAction Stop
        }
        catch {
            Write-Host "User $User not found or could not be removed." -ForegroundColor Red
        }
    }
}