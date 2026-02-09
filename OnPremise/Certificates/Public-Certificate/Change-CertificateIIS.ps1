# En cours de dev
Import-Module WebAdministration
$newThumb = "Thumbprint here" -replace '\s',''
$domainSuffix = "Domain here"
$AllSites = Get-ChildItem IIS:\Sites | Select-Object Name, @{Name='Bindings';Expression={$_.Bindings.Collection}}

$AllSites = $AllSites | ? {$_.Name -ne "Default Web Site"}

$AllSites
Function Update-CertCustom {
    param($siteName,
    $newThumb,
    $domainSuffix
    )
    Get-WebBinding -Name $siteName -Protocol "https" | ForEach-Object {

        # Ne jamais utiliser $host / $Host
        $bindingHost = $_.HostHeader
        if (-not $bindingHost) {
            # fallback: bindingInformation = ip:port:host
            $bindingHost = ($_.bindingInformation -split ":", 3)[2]
        }

        if ($bindingHost -and $bindingHost.ToLower().EndsWith($domainSuffix)) {
            $_.AddSslCertificate($newThumb, "MY")
            Write-Host "OK   $siteName -> $bindingHost"
        } else {
            Write-Host "SKIP $siteName -> Host='$bindingHost'"
        }
    }
}

Foreach ($Site in $AllSites)
{
    Update-CertCustom -newThumb $newThumb -domainSuffix $domainSuffix -siteName $($Site.name)
}
