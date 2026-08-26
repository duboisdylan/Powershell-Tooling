<#
.SYNOPSIS
    Inventorie les navigateurs (Chrome / Firefox) detectes par Intune et croise
    avec l'utilisateur principal de chaque appareil.

.DESCRIPTION
    S'appuie sur l'inventaire natif "Discovered apps" d'Intune. Ne necessite pas
    que l'application soit deployee ou packagee via Intune.

    v2 - Gestion du throttling (HTTP 429) :
      * filtrage cote serveur pour eviter la pagination profonde
      * pages reduites (100 par defaut)
      * backoff exponentiel avec relances
      * pause configurable entre les appels

    Prerequis : module Microsoft.Graph.Authentication
                permission DeviceManagementManagedDevices.Read.All

.EXAMPLE
    .\Get-IntuneBrowserInventory.ps1

.EXAMPLE
    # Tenant tres volumineux : pages plus petites et pauses plus longues
    .\Get-IntuneBrowserInventory.ps1 -PageSize 50 -ThrottleDelayMs 500

.EXAMPLE
    .\Get-IntuneBrowserInventory.ps1 -FilterTerms 'Chrome','Firefox','Opera' -AppPatterns 'Chrome','Firefox','Opera'
#>

[CmdletBinding()]
param(
    # Termes utilises pour le filtre cote serveur (un seul mot, sans espace)
    [string[]]$FilterTerms = @('Chrome', 'Firefox'),

    # Motifs de validation cote client (peuvent contenir des espaces)
    [string[]]$AppPatterns = @('Chrome', 'Firefox'),

    [ValidateRange(10, 500)]
    [int]$PageSize = 100,

    # Pause entre chaque appel Graph, en millisecondes
    [int]$ThrottleDelayMs = 200,

    [int]$MaxRetries = 6,

    [string]$OutputPath = ".\Inventaire-Navigateurs-$(Get-Date -Format 'yyyyMMdd-HHmm').csv"
)

$ErrorActionPreference = 'Stop'
$graphBase = 'https://graph.microsoft.com/beta'

#region Fonctions -------------------------------------------------------------

function Invoke-GraphWithRetry {
    <#
        Appel Graph avec backoff exponentiel sur les erreurs 429 / 503.
        Le SDK ne relance que 3 fois et Intune ne renvoie pas toujours
        d'en-tete Retry-After : on gere donc notre propre temporisation.
    #>
    param(
        [Parameter(Mandatory)][string]$Uri,
        [int]$MaxAttempts = 6
    )

    $attempt = 0

    while ($true) {
        $attempt++

        try {
            return Invoke-MgGraphRequest -Method GET -Uri $Uri -ErrorAction Stop
        }
        catch {
            $message     = $_.Exception.Message
            $isThrottled = $message -match 'TooManyRequests|429|ServiceUnavailable|503|Too many retries'

            if (-not $isThrottled -or $attempt -ge $MaxAttempts) { throw }

            # 15s, 30s, 60s, 120s, 240s (plafonne a 300s)
            $wait = [math]::Min(300, 15 * [math]::Pow(2, $attempt - 1))

            Write-Warning ("Throttling detecte (tentative {0}/{1}) - pause de {2}s..." -f $attempt, $MaxAttempts, $wait)
            Start-Sleep -Seconds $wait
        }
    }
}

function Get-GraphAllPages {
    param(
        [Parameter(Mandatory)][string]$Uri,
        [int]$MaxAttempts = 6,
        [int]$DelayMs = 200,
        [string]$Label = 'elements'
    )

    $results = [System.Collections.Generic.List[object]]::new()
    $next    = $Uri
    $page    = 0

    while ($next) {
        $page++
        $response = Invoke-GraphWithRetry -Uri $next -MaxAttempts $MaxAttempts

        if ($response.value) { $results.AddRange([object[]]$response.value) }

        $next = $response.'@odata.nextLink'

        if ($page % 5 -eq 0) {
            Write-Host ("    page {0} - {1} {2}..." -f $page, $results.Count, $Label) -ForegroundColor DarkGray
        }

        if ($next -and $DelayMs -gt 0) { Start-Sleep -Milliseconds $DelayMs }
    }

    return $results
}

#endregion --------------------------------------------------------------------

# --- Connexion ---------------------------------------------------------------
Connect-MgGraph -Scopes 'DeviceManagementManagedDevices.Read.All' -NoWelcome

$context = Get-MgContext
Write-Host "Tenant : $($context.TenantId)" -ForegroundColor Cyan
Write-Host "Pages de $PageSize / pause $ThrottleDelayMs ms`n" -ForegroundColor DarkGray

# --- 1. Applications detectees (FILTRE COTE SERVEUR) -------------------------
# On ne recupere que les apps correspondantes : evite d'enumerer plusieurs
# milliers d'entrees et donc la pagination profonde qui declenche le 429.

Write-Host "Recherche des applications..." -ForegroundColor Yellow

$matchedApps = [System.Collections.Generic.List[object]]::new()
$serverFilterOk = $true

foreach ($term in $FilterTerms) {

    $filter = [uri]::EscapeDataString("contains(displayName,'$term')")
    $uri    = "$graphBase/deviceManagement/detectedApps?`$filter=$filter&`$top=$PageSize"

    Write-Host "  Filtre serveur : '$term'" -ForegroundColor Gray

    try {
        $found = Get-GraphAllPages -Uri $uri -MaxAttempts $MaxRetries -DelayMs $ThrottleDelayMs -Label 'apps'
        if ($found) { $matchedApps.AddRange([object[]]$found) }
        Write-Host "    -> $($found.Count) resultat(s)" -ForegroundColor DarkGray
    }
    catch {
        Write-Warning "Filtre serveur refuse pour '$term' : $($_.Exception.Message)"
        $serverFilterOk = $false
        break
    }
}

# --- Repli : enumeration complete si le filtre serveur n'est pas supporte -----
if (-not $serverFilterOk) {

    Write-Warning "Bascule en enumeration complete (plus lent, plus expose au throttling)."

    $uri    = "$graphBase/deviceManagement/detectedApps?`$top=$PageSize"
    $allApps = Get-GraphAllPages -Uri $uri -MaxAttempts $MaxRetries -DelayMs ([math]::Max(500, $ThrottleDelayMs)) -Label 'apps'

    Write-Host "  -> $($allApps.Count) applications au total." -ForegroundColor Gray

    $matchedApps = [System.Collections.Generic.List[object]]::new()
    foreach ($app in $allApps) {
        $name = $app.displayName
        if (($AppPatterns | Where-Object { $name -like "*$_*" }).Count -gt 0) {
            $matchedApps.Add($app)
        }
    }
}

# Deduplication (un terme peut matcher plusieurs fois) + validation cote client
$matchedApps = $matchedApps |
    Sort-Object -Property id -Unique |
    Where-Object {
        $name = $_.displayName
        ($AppPatterns | Where-Object { $name -like "*$_*" }).Count -gt 0
    }

Write-Host "`n$($matchedApps.Count) version(s) d'application retenue(s).`n" -ForegroundColor Green

if (-not $matchedApps) {
    Write-Warning "Aucune application ne correspond aux motifs : $($AppPatterns -join ', ')"
    return
}

# --- 2. Appareils concernes (uniquement ceux qui nous interessent) -----------
# On collecte d'abord les identifiants, puis on ne resout que ces appareils :
# inutile de telecharger tout le parc si 30 postes sont concernes.

Write-Host "Recuperation des appareils par application..." -ForegroundColor Yellow

$appToDevices = @{}
$deviceIds    = [System.Collections.Generic.HashSet[string]]::new()

foreach ($app in $matchedApps) {

    Write-Host ("  {0} {1} [{2} appareil(s)]" -f $app.displayName, $app.version, $app.deviceCount) -ForegroundColor DarkGray

    $uri     = "$graphBase/deviceManagement/detectedApps/$($app.id)/managedDevices?`$top=$PageSize"
    $devices = Get-GraphAllPages -Uri $uri -MaxAttempts $MaxRetries -DelayMs $ThrottleDelayMs -Label 'appareils'

    $appToDevices[$app.id] = $devices
    foreach ($d in $devices) { [void]$deviceIds.Add($d.id) }
}

Write-Host "`n$($deviceIds.Count) appareil(s) unique(s) a resoudre." -ForegroundColor Gray

# --- 3. Resolution des utilisateurs ------------------------------------------
# Strategie : au-dela de 200 appareils, un seul appel pagine coute moins cher
# que N appels unitaires. En dessous, on cible pour limiter le volume.

$deviceCache = @{}
$selectProps = 'id,deviceName,userPrincipalName,userDisplayName,operatingSystem,osVersion,lastSyncDateTime'

if ($deviceIds.Count -gt 200) {

    Write-Host "Recuperation groupee du parc..." -ForegroundColor Yellow

    $uri = "$graphBase/deviceManagement/managedDevices?`$select=$selectProps&`$top=$PageSize"
    foreach ($device in (Get-GraphAllPages -Uri $uri -MaxAttempts $MaxRetries -DelayMs $ThrottleDelayMs -Label 'appareils')) {
        $deviceCache[$device.id] = $device
    }
}
else {
    Write-Host "Resolution ciblee des appareils..." -ForegroundColor Yellow

    $i = 0
    foreach ($id in $deviceIds) {
        $i++
        try {
            $uri = "$graphBase/deviceManagement/managedDevices/$id" + "?`$select=$selectProps"
            $deviceCache[$id] = Invoke-GraphWithRetry -Uri $uri -MaxAttempts $MaxRetries
        }
        catch {
            Write-Warning "Appareil $id non resolu : $($_.Exception.Message)"
        }

        if ($i % 25 -eq 0) { Write-Host "    $i / $($deviceIds.Count)..." -ForegroundColor DarkGray }
        if ($ThrottleDelayMs -gt 0) { Start-Sleep -Milliseconds $ThrottleDelayMs }
    }
}

# --- 4. Construction du rapport ----------------------------------------------
$report = [System.Collections.Generic.List[object]]::new()

foreach ($app in $matchedApps) {

    foreach ($appDevice in $appToDevices[$app.id]) {

        $full = $deviceCache[$appDevice.id]

        $report.Add([pscustomobject]@{
            Application     = $app.displayName
            Version         = $app.version
            Editeur         = $app.publisher
            Plateforme      = $app.platform
            Appareil        = if ($full) { $full.deviceName }        else { $appDevice.deviceName }
            Utilisateur     = if ($full) { $full.userPrincipalName } else { 'N/A' }
            NomUtilisateur  = if ($full) { $full.userDisplayName }   else { 'N/A' }
            OS              = if ($full) { $full.operatingSystem }   else { 'N/A' }
            VersionOS       = if ($full) { $full.osVersion }         else { 'N/A' }
            DerniereSynchro = if ($full) { $full.lastSyncDateTime }  else { 'N/A' }
            DeviceId        = $appDevice.id
        })
    }
}

# --- 5. Export ----------------------------------------------------------------
$report | Sort-Object Application, Utilisateur |
    Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 -Delimiter ';'

Write-Host "`nExport : $OutputPath" -ForegroundColor Green
Write-Host "$($report.Count) ligne(s) generee(s).`n" -ForegroundColor Green

# --- 6. Synthese --------------------------------------------------------------
Write-Host "Synthese par application :" -ForegroundColor Cyan
$report | Group-Object Application |
    Select-Object @{n='Application';e={$_.Name}},
                  @{n='Appareils';e={$_.Count}},
                  @{n='Utilisateurs uniques';e={($_.Group.Utilisateur | Sort-Object -Unique).Count}} |
    Format-Table -AutoSize

Write-Host "Utilisateurs disposant de PLUSIEURS navigateurs :" -ForegroundColor Cyan
$report | Where-Object { $_.Utilisateur -ne 'N/A' } |
    Group-Object Utilisateur |
    ForEach-Object {
        $familles = $_.Group.Application |
            ForEach-Object { foreach ($p in $AppPatterns) { if ($_ -like "*$p*") { $p } } } |
            Sort-Object -Unique

        if ($familles.Count -gt 1) {
            [pscustomobject]@{
                Utilisateur = $_.Name
                Navigateurs = $familles -join ', '
                Appareils   = ($_.Group.Appareil | Sort-Object -Unique) -join ', '
            }
        }
    } | Format-Table -AutoSize