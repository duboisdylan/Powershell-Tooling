$EventIDs = @(4720, 4722, 4725, 4726, 4738, 4767, 4771, 4776, 4624, 4625)

# Récupérer les événements un par un (évite le problème de liste)
$Events = foreach ($ID in $EventIDs) {`
    Get-WinEvent -LogName Security -FilterHashtable @{`
        LogName='Security'`
        ID=$ID`
        StartTime=$StartTime`
    } -ErrorAction SilentlyContinue`
}

# Filtrer pour ne garder que les événements liés à "CONTOSO\Administrateur"
$FilteredEvents = $Events | Where-Object { $_.Message -match "CONTOSO\\Administrateur" }
Get-EventLog -LogName Security
clear
$logs = get-eventlog -LogName Security -After (Get-Date).AddDays(-7);
$res = @(); 
ForEach ($log in $logs) {`
    if ($log.instanceid -eq 7001)`
    { $type = "Logon" } `
    Elseif ($log.instanceid -eq 7002)`
    { $type = "Logoff" } `
    Else { Continue } `
     `
    $res += New-Object PSObject -Property @{Time = $log.TimeWritten; "Event" = $type; User = (New-Object System.Security.Principal.SecurityIdentifier $Log.ReplacementStrings[1]).Translate([System.Security.Principal.NTAccount]) }`
}


$EventIDs = @(4720, 4722, 4725, 4726, 4738, 4767, 4771, 4776, 4624, 4625)
# Récupérer les événements un par un (évite le problème de liste)
$StartTime = (Get-Date).AddDays(-7)

$Events = foreach ($Event in $EventIDs) {`
    Get-WinEvent -LogName Security -FilterHashtable @{
        LogName = "Security" `
        id = $Event `
        StartTime = $StartTime `
    } -ErrorAction SilentlyContinue`
}



$logs = get-eventlog -LogName Security -After (Get-Date).AddDays(-7)
