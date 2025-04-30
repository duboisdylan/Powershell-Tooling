param(
    [Alias("FilePath")]
    [parameter(Mandatory=$true)][string]$DnsName,
    [parameter(Mandatory=$true)][string]$Pass
)

Begin {
    $SecurePassword = ConvertTo-SecureString $Pass -AsPlainText -Force
}

Process {
    # Create certificate
    $mycert = New-SelfSignedCertificate -DnsName $DnsName -CertStoreLocation "cert:\CurrentUser\My" -NotAfter (Get-Date).AddYears(1) -KeySpec KeyExchange

    # Export certificate to .pfx file
    $mycert | Export-PfxCertificate -FilePath "..\..\Ressources\$($DnsName.Split(".")[0]).pfx" -Password $SecurePassword

    # Export certificate to .cer file
    $mycert | Export-Certificate -FilePath "..\..\Ressources\$($DnsName.Split(".")[0]).cer"
}
