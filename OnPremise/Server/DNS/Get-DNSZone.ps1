$resultOutput = [System.Collections.ArrayList]::new()

$AllDNS = Get-DnsServerZone | Where-Object {($_.ZoneType -eq "Primary") -and ($_.IsReverseLookupZone -eq $false)}

Foreach ($DOmain in $AllDNS)
{
    $AllRecords = Get-DnsServerResourceRecord -ZoneName $DOmain.ZoneName
    Foreach ($result in $AllRecords)
    {`
        $RecordsResult = [PSCustomObject] [ordered] @{
            "fieldType"     = $result.RecordType
            "id"            = ""
            "subDomain"     = $result.HostName
            "target"        = $result.RecordData.IPv4Address.IPAddressToString
            "ttl"           = $result.TimeToLive
            "zone"          = $DOmain.ZoneName
        }
        $resultOutput.Add($RecordsResult) | Out-Null
    }
}
$AllRecords

$resultOutput | Export-Csv -Path "C:\temp\DnsZonesDC-$(Get-Date -Format "yyyyMMdd-hhmmss").csv" -Delimiter ";" -NoTypeInformation