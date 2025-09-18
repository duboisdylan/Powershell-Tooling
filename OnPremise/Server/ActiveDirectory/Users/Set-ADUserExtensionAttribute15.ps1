param(
    [parameter(Mandatory=$true)][string]$Value,
    [parameter(Mandatory=$true)][string]$UserPrincipalName
)

Process {
    Set-ADUser -Identity $UserPrincipalName -Replace @{extensionAttribute15=$Value}
}