param(
    [Alias("FilePath")]
    [parameter(Mandatory=$true)][string]$LoadFromFile
)

Begin {
    if (!(Test-Path $LoadFromFile)){Throw "Incorrect Source Path."}
    $GroupsList=Get-Content -Path $LoadFromFile
    # Connect-MgGraph
}

Process {
    Foreach ($Group in $GroupsList) {
        Write-Host "Removing Group: $Group" -ForegroundColor Yellow
        try {
                Start-Sleep -Seconds 2
                Remove-ADGroup -Identity $Group -Confirm:$false -ErrorAction Stop
                Write-Host
        }
        catch {
            Write-Host "Group $Group not found or could not be removed." -ForegroundColor Red
        }
    }
}