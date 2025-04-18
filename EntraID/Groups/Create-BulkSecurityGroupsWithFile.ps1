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
        New-MgGroup -DisplayName $Group -MailEnabled:$false -SecurityEnabled -MailNickname $Group
    }
}