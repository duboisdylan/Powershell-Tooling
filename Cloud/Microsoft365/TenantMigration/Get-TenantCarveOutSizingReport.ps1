#Requires -Version 5.1
<#
.SYNOPSIS
    Calcule les indicateurs de comptage et de volumétrie nécessaires au dimensionnement des licences
    AvePoint pour un carve-out / carve-in de tenant Microsoft 365.

.DESCRIPTION
    Se connecte à Microsoft Graph avec un compte disposant du rôle Global Admin (ou au minimum des
    rôles permettant Reports.Read.All et Group.Read.All) et calcule :
      - Le nombre d'adresses e-mail (boîtes actives) et leur volumétrie totale
      - Le nombre de groupes Microsoft 365 (Unified Groups) et le sous-ensemble équipé Teams
      - Le nombre de sites SharePoint Online et leur volumétrie totale (OneDrive exclu par défaut,
        car il fait l'objet d'un rapport Graph distinct)

    En complément du résumé affiché à l'écran, le script exporte un classeur Excel unique (.xlsx) avec
    une feuille par périmètre (Résumé, Boîtes, Groupes, SharePoint) pour affiner le dimensionnement
    AvePoint (répartition par taille, identification des plus gros objets, etc.).

.PARAMETER Period
    Période couverte par les rapports d'usage Graph : D7, D30, D90 ou D180 (défaut : D30).
    Un objet inactif au-delà de cette période n'apparaît pas dans le rapport ; utiliser D180 pour
    capter un maximum d'objets si le tenant a peu d'activité récente.

.PARAMETER IncludeOneDrive
    Ajoute au résumé le nombre de comptes OneDrive et leur volumétrie (rapport Graph séparé :
    getOneDriveUsageAccountDetail). Non inclus par défaut car non demandé dans le périmètre SharePoint.

.PARAMETER OutputFolder
    Dossier de destination du classeur Excel généré (défaut : dossier courant).

.EXAMPLE
    .\Get-TenantCarveOutSizingReport.ps1

.EXAMPLE
    .\Get-TenantCarveOutSizingReport.ps1 -Period D90 -IncludeOneDrive -OutputFolder C:\Sizing

.NOTES
    Pré-requis : modules Microsoft.Graph (Authentication, Reports, Groups) et ImportExcel.
    Scopes délégués utilisés : Reports.Read.All, Group.Read.All.

    Important : par défaut, Microsoft 365 anonymise les identifiants (UPN, URL de site) dans les
    rapports d'usage tant que l'option "Afficher les noms concrets dans tous les rapports" n'est pas
    activée dans le centre d'administration M365 (Paramètres > Paramètres de l'organisation >
    Rapports des services). Cela n'affecte ni les compteurs ni les volumétries de ce script, seulement
    la lisibilité des identifiants dans les feuilles détaillées.
#>

[CmdletBinding()]
param(
    [ValidateSet("D7", "D30", "D90", "D180")]
    [string]$Period = "D30",

    [switch]$IncludeOneDrive,

    [string]$OutputFolder = (Get-Location).Path
)

function ConvertTo-GB {
    param([double]$Bytes)
    [math]::Round($Bytes / 1GB, 2)
}

function Get-SafeDouble {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return 0 }
    return [double]$Value
}

function Invoke-MgReportDownload {
    # Le SDK Microsoft.Graph.Reports lève parfois une erreur non bloquante sur les gros rapports
    # ("Cannot set percent because PercentComplete cannot be greater than 100") : bug connu du calcul
    # de progression du téléchargement (https://github.com/microsoftgraph/msgraph-sdk-powershell/issues/3488),
    # sans rapport avec le contenu réellement téléchargé. On l'ignore spécifiquement et on vérifie le
    # fichier obtenu plutôt que de se fier au flux d'erreur.
    param(
        [Parameter(Mandatory)][string]$CmdletName,
        [Parameter(Mandatory)][hashtable]$CmdletParams,
        [Parameter(Mandatory)][string]$OutFile
    )
    & $CmdletName @CmdletParams -ErrorAction SilentlyContinue -ErrorVariable ReportErrors | Out-Null

    $UnexpectedErrors = $ReportErrors | Where-Object { $_.Exception.Message -notmatch 'PercentComplete cannot be greater than 100' }
    if ($UnexpectedErrors) { throw $UnexpectedErrors[0] }

    if (-not (Test-Path $OutFile) -or (Get-Item $OutFile).Length -eq 0) {
        throw "Échec du téléchargement du rapport $CmdletName : fichier absent ou vide ($OutFile)."
    }
}

# ─── VÉRIFICATION / INSTALLATION DES MODULES REQUIS ──────────────────────────
$RequiredModules = "Microsoft.Graph.Authentication", "Microsoft.Graph.Reports", "Microsoft.Graph.Groups", "ImportExcel"
foreach ($ModuleName in $RequiredModules) {
    if (-not (Get-Module -Name $ModuleName -ListAvailable)) {
        Write-Host "Le module $ModuleName est requis mais absent." -ForegroundColor Yellow
        $Confirm = Read-Host "Installer $ModuleName maintenant ? [O] Oui [N] Non"
        if ($Confirm -match "^[oOyY]") {
            Install-Module $ModuleName -Scope CurrentUser -AllowClobber -Force
        }
        else {
            Write-Host "Le module $ModuleName est indispensable à l'exécution du script." -ForegroundColor Red
            exit 1
        }
    }
}

Write-Host "`nConnexion à Microsoft Graph (compte Global Admin requis)..." -ForegroundColor Cyan
Connect-MgGraph -Scopes "Reports.Read.All", "Group.Read.All" -NoWelcome

if (-not (Test-Path $OutputFolder)) {
    New-Item -Path $OutputFolder -ItemType Directory -Force | Out-Null
}
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$ExcelPath = Join-Path $OutputFolder "TenantCarveOutSizing_$Timestamp.xlsx"
$ExcelStyle = @{ AutoSize = $true; FreezeTopRow = $true; BoldTopRow = $true; TableStyle = 'Medium2' }

# ─── 1. BOÎTES AUX LETTRES (nombre d'adresses e-mail + volumétrie) ───────────
Write-Host "Récupération du rapport d'utilisation des boîtes aux lettres..." -ForegroundColor Cyan
$MailboxRawPath = Join-Path $OutputFolder "MailboxUsage_Raw_$Timestamp.csv"
Invoke-MgReportDownload -CmdletName 'Get-MgReportMailboxUsageDetail' -OutFile $MailboxRawPath `
    -CmdletParams @{ Period = $Period; OutFile = $MailboxRawPath }

$ActiveMailboxes = Import-Csv -Path $MailboxRawPath | Where-Object { $_.'Is Deleted' -eq 'False' }

$MailboxDetail = $ActiveMailboxes | Select-Object `
    'User Principal Name',
    'Display Name',
@{Name = 'StorageUsedGo'; Expression = { ConvertTo-GB (Get-SafeDouble $_.'Storage Used (Byte)') } },
    'Item Count',
    'Has Archive',
    'Last Activity Date'

$NbAdressesEmail = $ActiveMailboxes.Count
$VolumetrieMailGo = ConvertTo-GB (($ActiveMailboxes | ForEach-Object { Get-SafeDouble $_.'Storage Used (Byte)' } | Measure-Object -Sum).Sum)

$MailboxDetail | Export-Excel -Path $ExcelPath -WorksheetName "Boites" @ExcelStyle
Remove-Item $MailboxRawPath -ErrorAction SilentlyContinue

# ─── 2. GROUPES MICROSOFT 365 & ÉQUIPES TEAMS ────────────────────────────────
Write-Host "Récupération des groupes Microsoft 365 et équipes Teams..." -ForegroundColor Cyan
$M365Groups = Get-MgGroup -All -ConsistencyLevel eventual -CountVariable GroupCount `
    -Filter "groupTypes/any(c:c eq 'Unified')" `
    -Property "Id,DisplayName,Mail,ResourceProvisioningOptions,CreatedDateTime"

$GroupDetail = $M365Groups | Select-Object `
    DisplayName, Mail, CreatedDateTime,
@{Name = 'EquipeTeams'; Expression = { $_.ResourceProvisioningOptions -contains 'Team' } }

$NbGroupesM365 = $M365Groups.Count
$NbEquipesTeams = ($M365Groups | Where-Object { $_.ResourceProvisioningOptions -contains 'Team' }).Count

$GroupDetail | Export-Excel -Path $ExcelPath -WorksheetName "Groupes" @ExcelStyle

# ─── 3. SITES SHAREPOINT ONLINE (nombre + volumétrie) ────────────────────────
Write-Host "Récupération du rapport d'utilisation des sites SharePoint..." -ForegroundColor Cyan
$SPORawPath = Join-Path $OutputFolder "SharePointUsage_Raw_$Timestamp.csv"
Invoke-MgReportDownload -CmdletName 'Get-MgReportSharePointSiteUsageDetail' -OutFile $SPORawPath `
    -CmdletParams @{ Period = $Period; OutFile = $SPORawPath }

$SPOActive = Import-Csv -Path $SPORawPath | Where-Object { $_.'Is Deleted' -eq 'False' }

$SPODetail = $SPOActive | Select-Object `
    'Site URL',
    'Owner Display Name',
    'Root Web Template',
@{Name = 'StorageUsedGo'; Expression = { ConvertTo-GB (Get-SafeDouble $_.'Storage Used (Byte)') } },
    'File Count',
    'Last Activity Date'

$NbSitesSharePoint = $SPOActive.Count
$VolumetrieSPOGo = ConvertTo-GB (($SPOActive | ForEach-Object { Get-SafeDouble $_.'Storage Used (Byte)' } | Measure-Object -Sum).Sum)

$SPODetail | Export-Excel -Path $ExcelPath -WorksheetName "SharePoint" @ExcelStyle
Remove-Item $SPORawPath -ErrorAction SilentlyContinue

# ─── 4. ONEDRIVE (optionnel, rapport Graph distinct) ─────────────────────────
$NbComptesOneDrive = $null
$VolumetrieOneDriveGo = $null
if ($IncludeOneDrive) {
    Write-Host "Récupération du rapport d'utilisation OneDrive..." -ForegroundColor Cyan
    $OneDriveRawPath = Join-Path $OutputFolder "OneDriveUsage_Raw_$Timestamp.csv"
    Invoke-MgReportDownload -CmdletName 'Get-MgReportOneDriveUsageAccountDetail' -OutFile $OneDriveRawPath `
        -CmdletParams @{ Period = $Period; OutFile = $OneDriveRawPath }

    $OneDriveActive = Import-Csv -Path $OneDriveRawPath | Where-Object { $_.'Is Deleted' -eq 'False' }
    $NbComptesOneDrive = $OneDriveActive.Count
    $VolumetrieOneDriveGo = ConvertTo-GB (($OneDriveActive | ForEach-Object { Get-SafeDouble $_.'Storage Used (Byte)' } | Measure-Object -Sum).Sum)

    $OneDriveDetail = $OneDriveActive | Select-Object `
        'Site URL',
        'Owner Display Name',
    @{Name = 'StorageUsedGo'; Expression = { ConvertTo-GB (Get-SafeDouble $_.'Storage Used (Byte)') } },
        'File Count',
        'Last Activity Date'
    $OneDriveDetail | Export-Excel -Path $ExcelPath -WorksheetName "OneDrive" @ExcelStyle

    Remove-Item $OneDriveRawPath -ErrorAction SilentlyContinue
}

# ─── RÉSUMÉ ───────────────────────────────────────────────────────────────────
$VolumetrieOneDriveGoOuZero = if ($IncludeOneDrive) { $VolumetrieOneDriveGo } else { 0 }
$VolumetrieTotaleGo = [math]::Round($VolumetrieMailGo + $VolumetrieSPOGo + $VolumetrieOneDriveGoOuZero, 2)

$Summary = [ordered]@{
    'Nombre adresses e-mail (boîtes actives)' = $NbAdressesEmail
    'Volumétrie messagerie (Go)'              = $VolumetrieMailGo
    'Nombre groupes Microsoft 365'            = $NbGroupesM365
    'Nombre équipes Teams'                    = $NbEquipesTeams
    'Nombre sites SharePoint'                 = $NbSitesSharePoint
    'Volumétrie SharePoint (Go)'              = $VolumetrieSPOGo
}
if ($IncludeOneDrive) {
    $Summary['Nombre comptes OneDrive'] = $NbComptesOneDrive
    $Summary['Volumétrie OneDrive (Go)'] = $VolumetrieOneDriveGo
}
$Summary['Volumétrie totale (Go)'] = $VolumetrieTotaleGo

$SummaryObject = [PSCustomObject]$Summary

Write-Host "`n──────────────────────────────────────────────" -ForegroundColor Green
Write-Host " RÉSUMÉ DIMENSIONNEMENT AVEPOINT (période $Period)" -ForegroundColor Green
Write-Host "──────────────────────────────────────────────" -ForegroundColor Green
$SummaryObject | Format-List

# Calculée en dernier (elle agrège les autres feuilles) mais repositionnée en premier onglet.
$SummaryRows = $Summary.GetEnumerator() | ForEach-Object {
    [PSCustomObject]@{ Indicateur = $_.Key; Valeur = $_.Value }
}
$SummaryRows | Export-Excel -Path $ExcelPath -WorksheetName "Resume" -MoveToStart @ExcelStyle

Write-Host "`nClasseur généré : $ExcelPath" -ForegroundColor Cyan
Write-Host "  Feuilles : Resume, Boites, Groupes, SharePoint$(if ($IncludeOneDrive) { ', OneDrive' })"

Disconnect-MgGraph | Out-Null
