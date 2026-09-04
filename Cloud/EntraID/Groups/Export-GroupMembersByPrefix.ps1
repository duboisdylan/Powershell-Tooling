<#
.SYNOPSIS
    Exporte au format Excel les membres de tous les groupes Entra ID dont le nom commence par un préfixe donné.

.DESCRIPTION
    Se connecte à Microsoft Graph (module Microsoft.Graph), recherche tous les groupes dont le
    displayName commence par -Prefix, puis récupère l'ensemble des membres de chaque groupe
    (utilisateurs, groupes imbriqués, principaux de service...). Le résultat est exporté dans un
    classeur Excel (.xlsx) contenant un onglet de synthèse des groupes et un onglet détaillé des
    membres, généré par défaut dans le dossier _Output à la racine du dépôt.

.PARAMETER Prefix
    Préfixe utilisé pour filtrer les groupes (ex: "SG-", "TEAM-").

.PARAMETER OutputPath
    Chemin du fichier Excel (.xlsx) de sortie. Par défaut, un fichier horodaté est créé dans
    le dossier _Output à la racine du dépôt (chemin relatif au script).

.EXAMPLE
    .\Export-GroupMembersByPrefix.ps1 -Prefix "SG-"

.EXAMPLE
    .\Export-GroupMembersByPrefix.ps1 -Prefix "TEAM-" -OutputPath "C:\Export\Groupes.xlsx"
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$Prefix,

    [string]$OutputPath = (Join-Path $PSScriptRoot "..\..\..\_Output\GroupMembersByPrefix_$(Get-Date -Format 'yyyyMMdd_HHmmss').xlsx")
)

Import-Module ImportExcel -ErrorAction Stop
Import-Module Microsoft.Graph.Groups -ErrorAction Stop

# -------------------- Connexion --------------------
if (-not (Get-MgContext)) {
    Write-Host "Connexion à Microsoft Graph..." -ForegroundColor Cyan
    Connect-MgGraph -Scopes "Group.Read.All", "GroupMember.Read.All" | Out-Null
}

# -------------------- Recherche des groupes --------------------
Write-Host "Recherche des groupes commençant par '$Prefix'..." -ForegroundColor Cyan

$escapedPrefix = $Prefix.Replace("'", "''")
$groups = Get-MgGroup -Filter "startsWith(displayName,'$escapedPrefix')" -ConsistencyLevel eventual -CountVariable groupCount -All `
    -Property Id, DisplayName, Mail, Description, SecurityEnabled, GroupTypes, Visibility

if (-not $groups -or $groups.Count -eq 0) {
    Write-Warning "Aucun groupe trouvé avec le préfixe '$Prefix'."
}

# -------------------- Collecte des membres --------------------
$groupSummary = New-Object System.Collections.Generic.List[object]
$memberDetails = New-Object System.Collections.Generic.List[object]

foreach ($group in $groups) {

    Write-Host "  - $($group.DisplayName)" -ForegroundColor DarkGray

    $members = @()
    try {
        $members = Get-MgGroupMember -GroupId $group.Id -All -ErrorAction Stop
    }
    catch {
        Write-Warning "Impossible de récupérer les membres du groupe '$($group.DisplayName)' : $($_.Exception.Message)"
    }

    foreach ($member in $members) {
        $odataType = $member.AdditionalProperties["@odata.type"]
        $memberType = if ($odataType) { $odataType -replace '^#microsoft\.graph\.', '' } else { "unknown" }

        $memberDetails.Add([pscustomobject]@{
            GroupDisplayName  = $group.DisplayName
            GroupId           = $group.Id
            GroupMail         = $group.Mail
            MemberType        = $memberType
            MemberDisplayName = $member.AdditionalProperties["displayName"]
            MemberUPN         = $member.AdditionalProperties["userPrincipalName"]
            MemberMail        = $member.AdditionalProperties["mail"]
            MemberId          = $member.Id
        })
    }

    $groupSummary.Add([pscustomobject]@{
        DisplayName     = $group.DisplayName
        Id              = $group.Id
        Mail            = $group.Mail
        SecurityEnabled = $group.SecurityEnabled
        GroupTypes      = ($group.GroupTypes -join "; ")
        Visibility      = $group.Visibility
        Description     = $group.Description
        MemberCount     = $members.Count
    })
}

# -------------------- Export Excel --------------------
$outputDir = Split-Path -Path $OutputPath -Parent
if ($outputDir -and -not (Test-Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
}
if (Test-Path $OutputPath) { Remove-Item $OutputPath -Force }

$dataGroups = $groupSummary
if ($dataGroups.Count -eq 0) {
    $dataGroups = [pscustomobject]@{ Info = "Aucun groupe trouvé avec le préfixe '$Prefix'." }
}
$dataGroups | Export-Excel -Path $OutputPath -WorksheetName "Groups" -TableName "Groups" `
    -AutoSize -FreezeTopRow -BoldTopRow -AutoFilter

$dataMembers = $memberDetails
if ($dataMembers.Count -eq 0) {
    $dataMembers = [pscustomobject]@{ Info = "Aucun membre trouvé pour les groupes correspondant au préfixe '$Prefix'." }
}
$dataMembers | Export-Excel -Path $OutputPath -WorksheetName "Members" -TableName "Members" `
    -AutoSize -FreezeTopRow -BoldTopRow -AutoFilter

Write-Host "Export terminé : $OutputPath" -ForegroundColor Green
Write-Host "Groupes trouvés : $($groups.Count) | Membres totaux : $($memberDetails.Count)" -ForegroundColor Yellow
