<#
.SYNOPSIS
    Détecte et désinstalle silencieusement Mozilla Firefox (toutes variantes) sur un poste Windows.

.DESCRIPTION
    Le script recherche Firefox dans :
      - HKLM\...\Uninstall (64 bits et WOW6432Node)  -> installations machine
      - HKCU\...\Uninstall et HKU\<SID>\...\Uninstall -> installations par utilisateur (option)
      - Les paquets Appx/MSIX (Mozilla.Firefox)       -> version Microsoft Store
    Il gère les deux types de programmes d'installation :
      - NSIS (uninstall\helper.exe /S) : cas standard
      - MSI  (msiexec /x {GUID} /qn)   : déploiements d'entreprise
    Le "Mozilla Maintenance Service" est également supprimé pour ne pas laisser
    de composant orphelin.

.PARAMETER DetectOnly
    Mode détection uniquement : aucune modification. Code retour 0 si Firefox est
    présent, 1 s'il est absent (convention de détection Intune / Freshservice).

.PARAMETER IncludeUserInstalls
    Inclut les installations par utilisateur (HKCU + ruches HKEY_USERS chargées).

.PARAMETER RemoveUserData
    DESTRUCTIF : supprime les profils Firefox (%APPDATA%\Mozilla et
    %LOCALAPPDATA%\Mozilla) de tous les utilisateurs après désinstallation.

.PARAMETER Force
    Termine les processus Firefox en cours au lieu d'abandonner.

.PARAMETER TimeoutSeconds
    Délai maximal d'attente par désinstallation (défaut 300 s).

.PARAMETER LogPath
    Fichier journal. Défaut : C:\ProgramData\Logs\Uninstall-Firefox.log

.EXAMPLE
    .\Uninstall-Firefox.ps1 -DetectOnly

.EXAMPLE
    .\Uninstall-Firefox.ps1 -Force -IncludeUserInstalls

.EXAMPLE
    .\Uninstall-Firefox.ps1 -WhatIf

.NOTES
    Exécution requise en tant qu'administrateur (ou SYSTEM) pour les installations machine.
    Codes retour : 0 = succès / rien à faire | 1 = échec (ou absent en -DetectOnly)
                   3010 = redémarrage requis
#>

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [switch]$DetectOnly,
    [switch]$IncludeUserInstalls,
    [switch]$RemoveUserData,
    [switch]$Force,
    [int]$TimeoutSeconds = 300,
    [string]$LogPath = "$env:ProgramData\Logs\Uninstall-Firefox.log"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

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
    <# Sépare "C:\...\helper.exe" /S en exécutable + arguments #>
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

#endregion

#region ---------- Détection ----------

function Get-FirefoxInstallation {
    param([switch]$IncludeUserScope)

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

    $found = foreach ($root in $roots) {
        if (-not (Test-Path -LiteralPath $root)) { continue }
        Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue | ForEach-Object {
            $p = Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue
            if (-not $p) { return }
            $name = Get-Prop -InputObject $p -Name 'DisplayName'
            if ([string]::IsNullOrWhiteSpace($name)) { return }
            if ($name -notmatch 'Firefox|Mozilla Maintenance Service') { return }

            [pscustomobject]@{
                DisplayName      = $name
                DisplayVersion   = Get-Prop -InputObject $p -Name 'DisplayVersion'
                UninstallString  = Get-Prop -InputObject $p -Name 'UninstallString'
                QuietUninstall   = Get-Prop -InputObject $p -Name 'QuietUninstallString'
                InstallLocation  = Get-Prop -InputObject $p -Name 'InstallLocation'
                RegistryPath     = $_.PSPath
                Scope            = if ($root -like 'HKLM*') { 'Machine' } else { 'Utilisateur' }
                Type             = if ($_.PSChildName -match '^\{[0-9A-Fa-f\-]{36}\}$') { 'MSI' } else { 'NSIS' }
                ProductCode      = $_.PSChildName
            }
        }
    }

    # Ordre : Firefox d'abord, service de maintenance ensuite
    $found | Sort-Object -Property @{ Expression = { $_.DisplayName -match 'Maintenance' } }
}

function Get-FirefoxAppxPackage {
    if (-not (Get-Command -Name Get-AppxPackage -ErrorAction SilentlyContinue)) { return @() }
    try { @(Get-AppxPackage -Name 'Mozilla.Firefox*' -AllUsers -ErrorAction Stop) }
    catch { @(Get-AppxPackage -Name 'Mozilla.Firefox*' -ErrorAction SilentlyContinue) }
}

#endregion

#region ---------- Actions ----------

function Stop-FirefoxProcess {
    $names = @('firefox', 'pingsender', 'crashreporter', 'default-browser-agent', 'maintenanceservice')
    $procs = Get-Process -Name $names -ErrorAction SilentlyContinue
    if (-not $procs) { return $true }

    if (-not $Force) {
        Write-Log "Firefox est en cours d'exécution ($($procs.Count) processus). Relancez avec -Force pour le fermer." 'ERROR'
        return $false
    }

    Write-Log "Arrêt de $($procs.Count) processus Firefox..." 'WARN'
    if ($PSCmdlet.ShouldProcess('Processus Firefox', 'Arrêter')) {
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
        $file = "$env:SystemRoot\System32\msiexec.exe"
        $argList = "/x $($Installation.ProductCode) /qn /norestart REBOOT=ReallySuppress"
    }
    else {
        $source = if ($Installation.QuietUninstall) { $Installation.QuietUninstall } else { $Installation.UninstallString }
        if ([string]::IsNullOrWhiteSpace($source)) {
            Write-Log "Aucune commande de désinstallation pour $label." 'ERROR'
            return $false
        }
        $parsed  = Split-CommandLine -CommandLine $source
        $file    = $parsed.FilePath
        $argList = $parsed.Arguments
        # helper.exe (NSIS) : /S = silencieux, indispensable
        if ($argList -notmatch '(?i)(^|\s)/S(\s|$)') { $argList = ("$argList /S").Trim() }

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

    # helper.exe se recopie dans %TEMP% et rend la main avant la fin réelle du travail :
    # on attend la disparition de la clé de registre plutôt que de se fier au code retour.
    if ($Installation.Type -eq 'NSIS') {
        $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
        while ((Test-Path -LiteralPath $Installation.RegistryPath) -and (Get-Date) -lt $deadline) {
            Start-Sleep -Seconds 3
        }
        Get-Process -Name 'helper', 'uninstall' -ErrorAction SilentlyContinue |
            Wait-Process -Timeout 60 -ErrorAction SilentlyContinue
    }

    $stillThere = Test-Path -LiteralPath $Installation.RegistryPath

    switch ($code) {
        0     { }
        3010  { Write-Log 'Désinstallation OK : redémarrage requis (3010).' 'WARN'; $script:RebootRequired = $true }
        1605  { Write-Log 'Produit déjà absent (1605).' 'WARN' }
        1641  { Write-Log 'Désinstallation OK : redémarrage engagé (1641).' 'WARN'; $script:RebootRequired = $true }
        default {
            if ($stillThere) {
                Write-Log "Code retour inattendu : $code — $label toujours présent." 'ERROR'
                return $false
            }
            Write-Log "Code retour $code mais produit absent : considéré comme désinstallé." 'WARN'
        }
    }

    if ($stillThere) {
        Write-Log "$label toujours référencé après $TimeoutSeconds s." 'ERROR'
        return $false
    }

    Write-Log "$label désinstallé." 'OK'
    return $true
}

function Remove-FirefoxAppx {
    $packages = Get-FirefoxAppxPackage
    if (-not $packages) { return $true }
    $ok = $true
    foreach ($pkg in $packages) {
        if (-not $PSCmdlet.ShouldProcess($pkg.PackageFullName, 'Supprimer le paquet Appx')) { continue }
        try {
            Remove-AppxPackage -Package $pkg.PackageFullName -AllUsers -ErrorAction Stop
            Write-Log "Paquet MSIX supprimé : $($pkg.PackageFullName)" 'OK'
        }
        catch {
            Write-Log "Échec suppression MSIX $($pkg.PackageFullName) : $($_.Exception.Message)" 'ERROR'
            $ok = $false
        }
    }
    # Provisionnement (nouveaux profils utilisateurs)
    try {
        Get-AppxProvisionedPackage -Online -ErrorAction Stop |
            Where-Object { $_.DisplayName -like 'Mozilla.Firefox*' } |
            ForEach-Object {
                if ($PSCmdlet.ShouldProcess($_.DisplayName, 'Déprovisionner')) {
                    Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName -ErrorAction Stop | Out-Null
                    Write-Log "Paquet déprovisionné : $($_.DisplayName)" 'OK'
                }
            }
    }
    catch {
        Write-Log "Déprovisionnement ignoré : $($_.Exception.Message)" 'WARN'
    }
    $ok
}

function Remove-FirefoxResidue {
    param([switch]$IncludeProfiles)

    $paths = @(
        "$env:ProgramFiles\Mozilla Firefox"
        "${env:ProgramFiles(x86)}\Mozilla Firefox"
        "$env:ProgramFiles\Mozilla Maintenance Service"
        "${env:ProgramFiles(x86)}\Mozilla Maintenance Service"
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Firefox.lnk"
        "$env:Public\Desktop\Firefox.lnk"
    )

    if ($IncludeProfiles) {
        Get-ChildItem -LiteralPath "$env:SystemDrive\Users" -Directory -ErrorAction SilentlyContinue |
            ForEach-Object {
                $paths += "$($_.FullName)\AppData\Roaming\Mozilla"
                $paths += "$($_.FullName)\AppData\Local\Mozilla"
            }
    }

    foreach ($p in $paths | Where-Object { $_ -and (Test-Path -LiteralPath $_) }) {
        if ($PSCmdlet.ShouldProcess($p, 'Supprimer')) {
            try {
                Remove-Item -LiteralPath $p -Recurse -Force -ErrorAction Stop
                Write-Log "Supprimé : $p" 'OK'
            }
            catch {
                Write-Log "Impossible de supprimer $p : $($_.Exception.Message)" 'WARN'
            }
        }
    }
}

#endregion

#region ---------- Programme principal ----------

$script:RebootRequired = $false

Write-Log '=== Uninstall-Firefox : démarrage ==='
Write-Log "Poste : $env:COMPUTERNAME | Contexte : $env:USERNAME | Élévation : $(Test-Elevated)"

if (-not (Test-Elevated)) {
    Write-Log 'Script non élevé : les installations machine ne pourront pas être désinstallées.' 'WARN'
}

$installs = @(Get-FirefoxInstallation -IncludeUserScope:$IncludeUserInstalls)
$appx     = @(Get-FirefoxAppxPackage)

if (-not $installs -and -not $appx) {
    Write-Log 'Firefox n''est pas installé sur ce poste.' 'OK'
    if ($DetectOnly) { exit 1 } else { exit 0 }
}

foreach ($i in $installs) {
    Write-Log "Détecté : $($i.DisplayName) $($i.DisplayVersion) [$($i.Scope) / $($i.Type)]"
}
foreach ($a in $appx) {
    Write-Log "Détecté (MSIX) : $($a.PackageFullName)"
}

if ($DetectOnly) {
    Write-Log 'Mode détection : aucune modification effectuée.'
    exit 0
}

if (-not (Stop-FirefoxProcess)) {
    Write-Log 'Abandon : Firefox est toujours en cours d''exécution.' 'ERROR'
    exit 1
}

$success = $true
foreach ($i in $installs) {
    if (-not (Invoke-Uninstall -Installation $i)) { $success = $false }
}
if ($appx) {
    if (-not (Remove-FirefoxAppx)) { $success = $false }
}

Remove-FirefoxResidue -IncludeProfiles:$RemoveUserData

# Vérification finale
$remaining = @(Get-FirefoxInstallation -IncludeUserScope:$IncludeUserInstalls) +
             @(Get-FirefoxAppxPackage)

if ($remaining) {
    Write-Log "Éléments encore présents : $($remaining.Count)" 'ERROR'
    $success = $false
}
else {
    Write-Log 'Vérification finale : Firefox est totalement absent du poste.' 'OK'
}

Write-Log '=== Uninstall-Firefox : fin ==='

if (-not $success)          { exit 1 }
if ($script:RebootRequired) { exit 3010 }
exit 0

#endregion