param(
    [parameter(Mandatory=$true)][string]$Customer
)

Begin {
    $Computers  = $null
    $AllDomains = (Get-ADDomainController -Filter *).HostName
    $Date       = (Get-Date).AddMonths(-6)
}

Process {
    Foreach ($Domain in $AllDomains) {
        $Computers += Get-ADComputer -Filter * -Properties * -Server $Domain `
        | Select-Object Enabled, Name, Modified, OperatingSystem, whenCreated, whenChanged, `
        @{Name = 'LastLogondate'; Expression = { [DateTime]::FromFileTime($_.LastLogon) } }, @{Name = 'Controleur de domaine'; Expression = { [string]$Domain } } `
        | Where-Object { $_.LastLogondate -lt $Date }
    }
}

End {
    $Computers | Export-Excel -path "\\tsclient\C\Temp\$Customer-$(Get-Date -Format "yyyymmd")-Computers.xlsx" -Title "Inactives computers" -TitleBold
}