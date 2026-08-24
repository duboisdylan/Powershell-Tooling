$AllSite = Get-SPOSite -Limit All | Select-Object Title, EnableAutoExpirationVersionTrim, ExpireVersionsAfterDays, MajorVersionLimit, Url

$LogPath = ".\SPO_VersionTrim_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$timestamp] [$Level] $Message"
    $line | Tee-Object -FilePath $LogPath -Append | Write-Host -ForegroundColor $(
        switch ($Level) {
            "INFO" { "Cyan" }
            "SUCCESS" { "Green" }
            "WARN" { "Yellow" }
            "ERROR" { "Red" }
            default { "White" }
        }
    )
}

try {
    $AllSites = Get-SPOSite -Limit All | Select-Object Title, Url,
    EnableAutoExpirationVersionTrim, ExpireVersionsAfterDays, MajorVersionLimit
    Write-Log "$($AllSites.Count) site(s) trouvé(s)." "SUCCESS"
}
catch {
    Write-Log "Erreur lors de Get-SPOSite : $_" "ERROR"
    exit 1
}

$stats = @{ Success = 0; Skipped = 0; Failed = 0 }

foreach ($site in $AllSites) {
    $url = $site.Url
    Write-Log "--- Traitement : $($site.Title) [$url]"

    # Ignorer sites déjà configurés
    if ($site.EnableAutoExpirationVersionTrim -eq $true) {
        Write-Log "AutoExpiration déjà activé – ignoré." "WARN"
        $stats.Skipped++
        continue
    }

    # Activer AutoExpirationVersionTrim
    try {
        Set-SPOSite -Identity $url -EnableAutoExpirationVersionTrim $true -ErrorAction Stop -Confirm:$false
        Write-Log "EnableAutoExpirationVersionTrim activé." "SUCCESS"
        try {
            New-SPOSiteFileVersionBatchDeleteJob -Identity $url -Automatic -ErrorAction Stop -Confirm:$false
            Write-Log "BatchDeleteJob lancé avec succès." "SUCCESS"
            $stats.Success++
        }
        catch {
            Write-Log "Échec New-SPOSiteFileVersionBatchDeleteJob sur '$url' : $_" "ERROR"
            $stats.Failed++
        }
    }
    catch {
        Write-Log "Échec Set-SPOSite sur '$url' : $_" "ERROR"
        $stats.Failed++
        continue
    }
}

Write-Log "============================================"
Write-Log "Résumé : $($stats.Success) traité(s) | $($stats.Skipped) ignoré(s) | $($stats.Failed) en erreur"
Write-Log "Log complet : $LogPath"
Write-Log "============================================"
