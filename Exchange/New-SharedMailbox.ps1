param(
    [parameter(Mandatory=$true)][string]$Name
)

New-Mailbox -Shared -Name $Name -DisplayName $Name -Alias $Name
