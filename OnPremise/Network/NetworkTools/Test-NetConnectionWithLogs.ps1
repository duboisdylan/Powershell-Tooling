param(
    [parameter(mandatory = $true)]$ComputerName
)

Process {
        Do {
            $ResultTest = Test-NetConnection -ComputerName $ComputerName
    
            $Records = [PSCustomObject] [ordered] @{
                "Time"           = $(Get-Date -Format "yyyyMMdd-hh:mm:ss")
                "Remote Address" = $ResultTest.RemoteAddress
                "PingSucceeded"  = $ResultTest.PingSucceeded
                "RTT"            = $ResultTest.PingReplyDetails.RoundtripTime
            }
    
            $Records | Export-CSV -Path "C:\temp\$ComputerName.csv" -Append
    
            Start-sleep -Seconds "30"
    
        } While ($true)
    }