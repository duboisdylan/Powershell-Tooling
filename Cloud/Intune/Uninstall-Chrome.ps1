<#
.SYNOPSIS
    Détecte et désinstalle silencieusement Google Chrome (toutes variantes) sur un poste Windows.

.DESCRIPTION
    Le script recherche Chrome dans :
      - HKLM\...\Uninstall (64 bits et WOW6432Node)  -> installations machine
      - HKCU\...\Uninstall et HKU\<SID>\...\Uninstall -> installations par utilisateur (option)
    Il gère les deux modes de déploiement :
      - Omaha / setup.exe  : "setup.exe --uninstall --force-uninstall [--system-level]"
      - MSI (Chrome Enterprise) : msiexec /x {GUID} /qn

    ATTENTION AUX CODES RETOUR : setup.exe renvoie 19 (UNINSTALL_SUCCESSFUL) en cas
    de succès, et non 0. Un script qui ne teste que 0 remonte de faux échecs.
    Le script vérifie donc l'absence réelle en registre, seule source fiable.

.PARAMETER DetectOnly
    Mode détection uniquement : aucune modification. Code retour 0 si Chrome est
    présent, 1 s'il est absent (convention de détection Intune / Freshservice).

.PARAMETER IncludeUserInstalls
    Inclut les installations par utilisateur (HKCU + ruches HKEY_USERS chargées).
    Chrome s'installe dans %LOCALAPPDATA% sans droits admin : ce cas est fréquent.

.PARAMETER RemoveGoogleUpdate
    Supprime aussi Google Update / Google Updater et ses tâches planifiées.
    À MANIER AVEC PRÉCAUTION : ce composant est partagé avec les autres produits
    Google (Drive, Earth, Chrome Remote Desktop). Le script refuse l'opération
    s'il détecte un autre produit Google, sauf si -Force est présent.

.PARAMETER RemoveUserData
    DESTRUCTIF : supprime les profils Chrome (%LOCALAPPDATA%\Google\Chrome\User Data)
    de tous les utilisateurs — favoris, mots de passe enregistrés, extensions.

.PARAMETER Force
    Termine les processus Chrome en cours et lève le garde-fou de -RemoveGoogleUpdate.

.PARAMETER TimeoutSeconds
    Délai maximal d'attente par désinstallation (défaut 300 s).

.PARAMETER LogPath
    Fichier journal. Défaut : C:\ProgramData\Logs\Uninstall-Chrome.log

.EXAMPLE
    .\Uninstall-Chrome.ps1 -DetectOnly

.EXAMPLE
    .\Uninstall-Chrome.ps1 -WhatIf

.EXAMPLE
    .\Uninstall-Chrome.ps1 -Force -IncludeUserInstalls

.NOTES
    Exécution requise en tant qu'administrateur (ou SYSTEM) pour les installations machine.
    Codes retour : 0 = succès / rien à faire | 1 = échec (ou absent en -DetectOnly)
                   3010 = redémarrage requis
#>

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [switch]$DetectOnly,
    [switch]$IncludeUserInstalls,
    [switch]$RemoveGoogleUpdate,
    [switch]$RemoveUserData,
    [switch]$Force,
    [int]$TimeoutSeconds = 300,
    [string]$LogPath = "$env:ProgramData\Logs\Uninstall-Chrome.log"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Variantes Chrome ciblées (le tri place Chrome avant les composants annexes)
$script:ChromePattern      = '^Google Chrome( Beta| Dev| Canary| SxS)?$'
$script:ComponentPattern   = '^(Google Update Helper|Google Updater)$'

#region ---------- Utilitaires ----------

function Write-Log {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('INFO', 'WARN', 'ERROR', 'OK')][string]$Level = 'INFO'
    )
    $line = '{0} [{1,-5}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    switch ($Level) {
        'ERROR' { Write-Host $line -ForegroundColor Red }
        'WARN'  { Write-Host $line -ForegroundColor Yellow }
        'OK'    { Write-Host $line -ForegroundColor Green }
        default { Write-Host $line }
    }
    try {
        $dir = Split-Path -Path $LogPath -Parent
        if ($dir -and -not (Test-Path -LiteralPath $dir)) {
            New-Item -Path $dir -ItemType Directory -Force | Out-Null
        }
        Add-Content -LiteralPath $LogPath -Value $line -Encoding UTF8
    }
    catch {
        # Le journal ne doit jamais faire échouer le script
    }
}

function Get-Prop {
    <# Lecture tolérante d'une propriété (compatible Set-StrictMode) #>
    param($InputObject, [Parameter(Mandatory)][string]$Name)
    if ($null -eq $InputObject) { return $null }
    $prop = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $prop) { return $null }
    $prop.Value
}

function Test-Elevated {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Split-CommandLine {
    <# Sépare "C:\...\setup.exe" --uninstall en exécutable + arguments #>
    param([Parameter(Mandatory)][string]$CommandLine)

    $cmd = $CommandLine.Trim()
    if ($cmd.StartsWith('"')) {
        $end = $cmd.IndexOf('"', 1)
        if ($end -gt 0) {
            return [pscustomobject]@{
                FilePath  = $cmd.Substring(1, $end - 1)
                Arguments = $cmd.Substring($end + 1).Trim()
            }
        }
    }
    $m = [regex]::Match($cmd, '^(?<f>.+?\.exe)\s*(?<a>.*)$', 'IgnoreCase')
    if ($m.Success) {
        return [pscustomobject]@{ FilePath = $m.Groups['f'].Value; Arguments = $m.Groups['a'].Value }
    }
    [pscustomobject]@{ FilePath = $cmd; Arguments = '' }
}

function Get-ChromeExitCodeLabel {
    <# Codes InstallStatus de l'installeur Chromium (installer/util/util_constants.h) #>
    param([int]$Code)
    switch ($Code) {
        0  { 'Succès' }
        15 { 'CHROME_NOT_INSTALLED — produit déjà absent' }
        16 { 'CHROME_RUNNING — Chrome est encore en cours d''exécution' }
        17 { 'UNINSTALL_CANCELLED — annulé (souvent : --force-uninstall manquant)' }
        18 { 'UNINSTALL_DELETE_PROFILE' }
        19 { 'UNINSTALL_SUCCESSFUL' }
        20 { 'UNINSTALL_FAILED' }
        21 { 'UNINSTALL_REQUIRES_REBOOT' }
        default { "Code non répertorié ($Code)" }
    }
}

#endregion

#region ---------- Détection ----------

function Get-ChromeInstallation {
    param([switch]$IncludeUserScope, [switch]$IncludeComponents)

    $roots = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
    )

    if ($IncludeUserScope) {
        $roots += 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
        if (-not (Get-PSDrive -Name 'HKU' -ErrorAction SilentlyContinue)) {
            New-PSDrive -Name 'HKU' -PSProvider Registry -Root 'HKEY_USERS' -Scope Script | Out-Null
        }
        # Uniquement les ruches déjà chargées (sessions ouvertes / profils actifs)
        Get-ChildItem -Path 'HKU:\' -ErrorAction SilentlyContinue |
            Where-Object { $_.PSChildName -match '^S-1-5-21-[\d\-]+$' } |
            ForEach-Object {
                $roots += "HKU:\$($_.PSChildName)\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
            }
    }

    $pattern = if ($IncludeComponents) {
        "$script:ChromePattern|$script:ComponentPattern"
    } else {
        $script:ChromePattern
    }

    $found = foreach ($root in $roots) {
        if (-not (Test-Path -LiteralPath $root)) { continue }
        Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue | ForEach-Object {
            $p = Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue
            if (-not $p) { return }
            $name = Get-Prop -InputObject $p -Name 'DisplayName'
            if ([string]::IsNullOrWhiteSpace($name)) { return }
            if ($name -notmatch $pattern) { return }

            $uninstall = Get-Prop -InputObject $p -Name 'UninstallString'
            [pscustomobject]@{
                DisplayName     = $name
                DisplayVersion  = Get-Prop -InputObject $p -Name 'DisplayVersion'
                UninstallString = $uninstall
                InstallLocation = Get-Prop -InputObject $p -Name 'InstallLocation'
                RegistryPath    = $_.PSPath
                Scope           = if ($root -like 'HKLM*') { 'Machine' } else { 'Utilisateur' }
                Type            = if ($uninstall -match '(?i)msiexec') { 'MSI' } else { 'Omaha' }
                ProductCode     = $_.PSChildName
                IsComponent     = [bool]($name -match $script:ComponentPattern)
            }
        }
    }

    # Chrome d'abord, composants Google Update ensuite
    $found | Sort-Object -Property @{ Expression = { $_.IsComponent } }, DisplayName
}

function Get-OtherGoogleProduct {
    <# Détecte les produits Google qui dépendent de Google Update #>
    $roots = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
    )
    foreach ($root in $roots) {
        if (-not (Test-Path -LiteralPath $root)) { continue }
        Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue | ForEach-Object {
            $n = Get-Prop -InputObject (Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue) -Name 'DisplayName'
            if ($n -and $n -match '(?i)^Google ' -and
                $n -notmatch $script:ChromePattern -and
                $n -notmatch $script:ComponentPattern) { $n }
        }
    }
}

#endregion

#region ---------- Actions ----------

function Stop-ChromeProcess {
    # chrome.exe survit à la fermeture des fenêtres si "Continuer l'exécution des
    # applications en arrière-plan" est actif : l'arrêt explicite est indispensable.
    $names = @(
        'chrome', 'chrome_pwa_launcher', 'crashpad_handler',
        'GoogleCrashHandler', 'GoogleCrashHandler64',
        'GoogleUpdate', 'GoogleUpdater', 'GoogleUpdateOnDemand', 'elevation_service'
    )
    $procs = Get-Process -Name $names -ErrorAction SilentlyContinue
    if (-not $procs) { return $true }

    if (-not $Force) {
        Write-Log "Chrome est en cours d'exécution ($($procs.Count) processus). Relancez avec -Force pour le fermer." 'ERROR'
        return $false
    }

    Write-Log "Arrêt de $($procs.Count) processus Chrome / Google Update..." 'WARN'
    if ($PSCmdlet.ShouldProcess('Processus Chrome', 'Arrêter')) {
        $procs | Stop-Process -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 3
    }
    -not (Get-Process -Name $names -ErrorAction SilentlyContinue)
}

function Invoke-Uninstall {
    param([Parameter(Mandatory)][psobject]$Installation)

    $label = '{0} {1} ({2}/{3})' -f $Installation.DisplayName, $Installation.DisplayVersion,
                                     $Installation.Scope, $Installation.Type

    if (-not $PSCmdlet.ShouldProcess($label, 'Désinstaller')) { return $true }

    Write-Log "Désinstallation de $label"

    if ($Installation.Type -eq 'MSI') {
        # Chrome Enterprise déployé par MSI : passer par msiexec, sinon l'entrée
        # ARP reste orpheline et la GPO peut redéployer le paquet.
        $code = $null
        $file = "$env:SystemRoot\System32\msiexec.exe"
        if ($Installation.ProductCode -match '^\{[0-9A-Fa-f\-]{36}\}$') {
            $argList = "/x $($Installation.ProductCode) /qn /norestart REBOOT=ReallySuppress"
        }
        else {
            $parsed  = Split-CommandLine -CommandLine $Installation.UninstallString
            $argList = ($parsed.Arguments + ' /qn /norestart').Trim()
        }
    }
    else {
        if ([string]::IsNullOrWhiteSpace($Installation.UninstallString)) {
            Write-Log "Aucune commande de désinstallation pour $label." 'ERROR'
            return $false
        }
        $parsed  = Split-CommandLine -CommandLine $Installation.UninstallString
        $file    = $parsed.FilePath
        $argList = $parsed.Arguments

        # --force-uninstall : sans lui, setup.exe affiche une boîte de confirmation
        # et le script reste bloqué indéfiniment (retour 17 UNINSTALL_CANCELLED).
        if ($argList -notmatch '(?i)--force-uninstall') { $argList = "$argList --force-uninstall".Trim() }
        # --system-level : présent dans l'UninstallString pour les installations machine.
        if ($Installation.Scope -eq 'Machine' -and $argList -notmatch '(?i)--system-level') {
            $argList = "$argList --system-level".Trim()
        }
        # --multi-install / --chrome sont obsolètes sur les versions modernes : on les retire.
        $argList = ($argList -replace '(?i)\s--multi-install', '' -replace '(?i)\s--chrome(?!-)', '').Trim()

        if (-not (Test-Path -LiteralPath $file)) {
            Write-Log "Désinstalleur introuvable : $file (entrée de registre orpheline)" 'WARN'
            Remove-Item -LiteralPath $Installation.RegistryPath -Recurse -Force -ErrorAction SilentlyContinue
            return $true
        }
    }

    Write-Log "Commande : `"$file`" $argList"

    try {
        $splat = @{ FilePath = $file; Wait = $true; PassThru = $true; WindowStyle = 'Hidden' }
        if ($argList) { $splat.ArgumentList = $argList }
        $proc = Start-Process @splat
        $code = $proc.ExitCode
    }
    catch {
        Write-Log "Échec du lancement du désinstalleur : $($_.Exception.Message)" 'ERROR'
        return $false
    }

    if ($Installation.Type -eq 'Omaha') {
        Write-Log "Code retour setup.exe : $code — $(Get-ChromeExitCodeLabel -Code $code)"
        # setup.exe se recopie dans %TEMP% et peut rendre la main avant la fin réelle :
        # on attend la disparition de la clé de registre plutôt que de se fier au code.
        $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
        while ((Test-Path -LiteralPath $Installation.RegistryPath) -and (Get-Date) -lt $deadline) {
            Start-Sleep -Seconds 3
        }
        Get-Process -Name 'setup' -ErrorAction SilentlyContinue |
            Wait-Process -Timeout 60 -ErrorAction SilentlyContinue

        if ($code -eq 21) { $script:RebootRequired = $true }
    }
    else {
        switch ($code) {
            0     { }
            1605  { Write-Log 'Produit déjà absent (1605).' 'WARN' }
            3010  { Write-Log 'Désinstallation OK : redémarrage requis (3010).' 'WARN'; $script:RebootRequired = $true }
            1641  { Write-Log 'Désinstallation OK : redémarrage engagé (1641).' 'WARN'; $script:RebootRequired = $true }
            default { Write-Log "msiexec a renvoyé $code." 'WARN' }
        }
    }

    # Verdict : l'absence en registre, et rien d'autre.
    if (Test-Path -LiteralPath $Installation.RegistryPath) {
        Write-Log "$label toujours référencé après $TimeoutSeconds s (code $code)." 'ERROR'
        return $false
    }

    Write-Log "$label désinstallé." 'OK'
    return $true
}

function Remove-GoogleUpdateComponent {
    # Tâches planifiées Omaha 3 (GoogleUpdateTask*) et Omaha 4 (GoogleUpdater*)
    $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue |
                Where-Object { $_.TaskName -match '(?i)^Google(Update|Updater)' }
    foreach ($t in $tasks) {
        if ($PSCmdlet.ShouldProcess($t.TaskName, 'Supprimer la tâche planifiée')) {
            try {
                Unregister-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath -Confirm:$false -ErrorAction Stop
                Write-Log "Tâche planifiée supprimée : $($t.TaskName)" 'OK'
            }
            catch { Write-Log "Échec suppression tâche $($t.TaskName) : $($_.Exception.Message)" 'WARN' }
        }
    }

    # Services Omaha 3 (gupdate / gupdatem) et Omaha 4 (GoogleUpdater*Service)
    $services = Get-Service -ErrorAction SilentlyContinue |
                    Where-Object { $_.Name -match '(?i)^(gupdate|gupdatem|GoogleUpdater)' }
    foreach ($s in $services) {
        if ($PSCmdlet.ShouldProcess($s.Name, 'Arrêter et supprimer le service')) {
            try {
                Stop-Service -Name $s.Name -Force -ErrorAction SilentlyContinue
                & "$env:SystemRoot\System32\sc.exe" delete $s.Name | Out-Null
                Write-Log "Service supprimé : $($s.Name)" 'OK'
            }
            catch { Write-Log "Échec suppression service $($s.Name) : $($_.Exception.Message)" 'WARN' }
        }
    }
}

function Remove-ChromeResidue {
    param([switch]$IncludeProfiles, [switch]$IncludeGoogleUpdate)

    $paths = @(
        "$env:ProgramFiles\Google\Chrome"
        "${env:ProgramFiles(x86)}\Google\Chrome"
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Google Chrome.lnk"
        "$env:Public\Desktop\Google Chrome.lnk"
    )
    if ($IncludeGoogleUpdate) {
        $paths += "$env:ProgramFiles\Google\Update"
        $paths += "${env:ProgramFiles(x86)}\Google\Update"
        $paths += "$env:ProgramFiles\Google\GoogleUpdater"
        $paths += "${env:ProgramFiles(x86)}\Google\GoogleUpdater"
    }

    if ($IncludeProfiles) {
        Get-ChildItem -LiteralPath "$env:SystemDrive\Users" -Directory -ErrorAction SilentlyContinue |
            ForEach-Object {
                $paths += "$($_.FullName)\AppData\Local\Google\Chrome"
                $paths += "$($_.FullName)\AppData\Roaming\Google\Chrome"
            }
    }

    foreach ($p in $paths | Where-Object { $_ -and (Test-Path -LiteralPath $_) }) {
        if ($PSCmdlet.ShouldProcess($p, 'Supprimer')) {
            try {
                Remove-Item -LiteralPath $p -Recurse -Force -ErrorAction Stop
                Write-Log "Supprimé : $p" 'OK'
            }
            catch { Write-Log "Impossible de supprimer $p : $($_.Exception.Message)" 'WARN' }
        }
    }
}

#endregion

#region ---------- Programme principal ----------

$script:RebootRequired = $false

Write-Log '=== Uninstall-Chrome : démarrage ==='
Write-Log "Poste : $env:COMPUTERNAME | Contexte : $env:USERNAME | Élévation : $(Test-Elevated)"

if (-not (Test-Elevated)) {
    Write-Log 'Script non élevé : les installations machine ne pourront pas être désinstallées.' 'WARN'
}

$installs = @(Get-ChromeInstallation -IncludeUserScope:$IncludeUserInstalls `
                                     -IncludeComponents:$RemoveGoogleUpdate)

$chromeOnly = @($installs | Where-Object { -not $_.IsComponent })

if (-not $chromeOnly) {
    Write-Log 'Google Chrome n''est pas installé sur ce poste.' 'OK'
    if ($DetectOnly) { exit 1 } else { exit 0 }
}

foreach ($i in $installs) {
    Write-Log "Détecté : $($i.DisplayName) $($i.DisplayVersion) [$($i.Scope) / $($i.Type)]"
}

if ($DetectOnly) {
    Write-Log 'Mode détection : aucune modification effectuée.'
    exit 0
}

# Garde-fou Google Update : composant mutualisé entre produits Google
if ($RemoveGoogleUpdate) {
    $others = @(Get-OtherGoogleProduct)
    if ($others -and -not $Force) {
        Write-Log "Autres produits Google détectés : $($others -join ', ')" 'WARN'
        Write-Log 'Google Update sera conservé (utilisez -Force pour le supprimer malgré tout).' 'WARN'
        $RemoveGoogleUpdate = $false
        $installs = @($installs | Where-Object { -not $_.IsComponent })
    }
}

if (-not (Stop-ChromeProcess)) {
    Write-Log 'Abandon : Chrome est toujours en cours d''exécution.' 'ERROR'
    exit 1
}

$success = $true
foreach ($i in $installs) {
    if (-not (Invoke-Uninstall -Installation $i)) { $success = $false }
}

if ($RemoveGoogleUpdate) { Remove-GoogleUpdateComponent }

Remove-ChromeResidue -IncludeProfiles:$RemoveUserData -IncludeGoogleUpdate:$RemoveGoogleUpdate

# Vérification finale
$remaining = @(Get-ChromeInstallation -IncludeUserScope:$IncludeUserInstalls |
                Where-Object { -not $_.IsComponent })

if ($remaining) {
    Write-Log "Chrome encore présent : $($remaining.Count) entrée(s)." 'ERROR'
    foreach ($r in $remaining) { Write-Log "  -> $($r.DisplayName) [$($r.Scope)]" 'ERROR' }
    $success = $false
}
else {
    Write-Log 'Vérification finale : Google Chrome est absent du poste.' 'OK'
}

Write-Log '=== Uninstall-Chrome : fin ==='

if (-not $success)          { exit 1 }
if ($script:RebootRequired) { exit 3010 }
exit 0

#endregion