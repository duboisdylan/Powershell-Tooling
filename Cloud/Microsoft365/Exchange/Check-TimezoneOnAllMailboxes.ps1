# Vérification du WorkingHoursTimeZone sur toutes les boîtes aux lettres Exchange Online
# Affiche uniquement celles qui ne sont pas en "Romance Standard Time"

$targetTimeZone = "Romance Standard Time"

Write-Host "Récupération des boîtes aux lettres..." -ForegroundColor Cyan

$mailboxes = Get-Mailbox -ResultSize Unlimited -RecipientTypeDetails UserMailbox

$results = @()
$total = $mailboxes.Count
$i = 0

foreach ($mbx in $mailboxes) {
    $i++
    Write-Progress -Activity "Vérification en cours" -Status "$($mbx.UserPrincipalName)" -PercentComplete (($i / $total) * 100)

    $calConfig = Get-MailboxCalendarConfiguration -Identity $mbx.UserPrincipalName |
        Select-Object Identity, WorkingHoursTimeZone

    if ($calConfig.WorkingHoursTimeZone -ne $targetTimeZone) {
        $results += [PSCustomObject]@{
            UPN           = $mbx.UserPrincipalName
            DisplayName   = $mbx.DisplayName
            TimeZone      = $calConfig.WorkingHoursTimeZone
        }
    }
}

Write-Progress -Activity "Vérification en cours" -Completed

if ($results.Count -eq 0) {
    Write-Host "`nToutes les boîtes aux lettres sont en '$targetTimeZone'." -ForegroundColor Green
} else {
    Write-Host "`n$($results.Count) boîte(s) avec un fuseau horaire différent de '$targetTimeZone' :" -ForegroundColor Yellow
    $results | Format-Table -AutoSize

    # Export CSV optionnel
    # $results | Export-Csv -Path ".\tz_non_conformes.csv" -NoTypeInformation -Encoding UTF8
}