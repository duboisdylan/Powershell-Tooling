#Requires -Modules Az.Accounts, Az.Resources, ImportExcel

<#
.SYNOPSIS
    Exporte toutes les attributions de rôles (RBAC) d'une souscription Azure
    dans un fichier Excel (.xlsx).

.DESCRIPTION
    Ce script :
    1. Se connecte à Azure (si besoin)
    2. Récupère toutes les attributions de rôles de la souscription
    3. Résout les noms des principaux (utilisateurs, groupes, SP, identités managées)
    4. Génère un rapport XLSX avec mise en forme automatique

.NOTES
    Prérequis :
      Install-Module Az             -Scope CurrentUser -Force
      Install-Module ImportExcel    -Scope CurrentUser -Force
#>

# ── Paramètres ────────────────────────────────────────────────
param(
    [string]$SubscriptionId,          # Laisser vide = souscription courante
    [string]$OutputPath = ".\Azure_RBAC_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').xlsx"
)

# ── Connexion ─────────────────────────────────────────────────
Write-Host "🔐 Vérification de la connexion Azure..." -ForegroundColor Cyan
$context = Get-AzContext -ErrorAction SilentlyContinue
if (-not $context) {
    Write-Host "   Aucune session active → lancement de Connect-AzAccount" -ForegroundColor Yellow
    Connect-AzAccount
    $context = Get-AzContext
}

if ($SubscriptionId) {
    Set-AzContext -SubscriptionId $SubscriptionId | Out-Null
    $context = Get-AzContext
}

$subName = $context.Subscription.Name
$subId   = $context.Subscription.Id
Write-Host "✅ Souscription : $subName ($subId)" -ForegroundColor Green

# ── Récupération des attributions de rôles ────────────────────
Write-Host "`n📋 Récupération des attributions de rôles..." -ForegroundColor Cyan
$roleAssignments = Get-AzRoleAssignment -Scope "/subscriptions/$subId"
Write-Host "   $($roleAssignments.Count) attribution(s) trouvée(s)" -ForegroundColor Green

# ── Construction du rapport ───────────────────────────────────
Write-Host "`n🔍 Résolution des identités et construction du rapport..." -ForegroundColor Cyan

$report = foreach ($ra in $roleAssignments) {

    # Déterminer le type de principal
    $principalType = switch ($ra.ObjectType) {
        "User"             { "Utilisateur" }
        "Group"            { "Groupe" }
        "ServicePrincipal" { "Principal de service" }
        "ManagedIdentity"  { "Identité managée" }
        default            { $ra.ObjectType }
    }

    # Déterminer la portée lisible
    $scopeDisplay = $ra.Scope
    if ($ra.Scope -eq "/subscriptions/$subId") {
        $scopeDisplay = "Souscription"
    }
    elseif ($ra.Scope -match "/resourceGroups/([^/]+)$") {
        $scopeDisplay = "RG: $($Matches[1])"
    }
    elseif ($ra.Scope -match "/resourceGroups/([^/]+)/providers/(.+)") {
        $scopeDisplay = "Ressource: $($Matches[2]) (RG: $($Matches[1]))"
    }

    # Catégoriser le niveau de risque du rôle
    $risque = switch -Wildcard ($ra.RoleDefinitionName) {
        "Owner"                      { "🔴 Critique" }
        "Contributor"                { "🟠 Élevé" }
        "User Access Administrator"  { "🔴 Critique" }
        "*Admin*"                    { "🟠 Élevé" }
        "Reader"                     { "🟢 Faible" }
        default                      { "🟡 Moyen" }
    }

    [PSCustomObject]@{
        "Nom affiché"       = $ra.DisplayName
        "Identifiant (UPN)" = $ra.SignInName
        "Type de principal"  = $principalType
        "Rôle"              = $ra.RoleDefinitionName
        "Niveau de risque"  = $risque
        "Portée"            = $scopeDisplay
        "Portée complète"   = $ra.Scope
        "Hérité"            = if ($ra.Scope -ne "/subscriptions/$subId") { "Oui" } else { "Non" }
        "Peut déléguer"     = $ra.CanDelegate
        "ObjectId"          = $ra.ObjectId
        "RoleAssignmentId"  = $ra.RoleAssignmentId
        "Date d'export"     = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    }
}

# ── Export Excel avec mise en forme ───────────────────────────
Write-Host "`n📊 Génération du fichier Excel..." -ForegroundColor Cyan

# Feuille principale : détail des attributions
$excelParams = @{
    Path          = $OutputPath
    WorksheetName = "Attributions RBAC"
    AutoSize      = $true
    AutoFilter    = $true
    FreezeTopRow  = $true
    BoldTopRow    = $true
    TableStyle    = "Medium6"
    Title         = "Rapport RBAC — $subName"
    TitleBold     = $true
    TitleSize     = 14
}
$report | Export-Excel @excelParams

# Feuille résumé : nombre d'attributions par rôle
$summary = $report |
    Group-Object "Rôle" |
    Select-Object @{N="Rôle";E={$_.Name}}, @{N="Nombre";E={$_.Count}} |
    Sort-Object Nombre -Descending

$summaryParams = @{
    Path          = $OutputPath
    WorksheetName = "Résumé par rôle"
    AutoSize      = $true
    BoldTopRow    = $true
    TableStyle    = "Medium4"
    Append        = $true
}
$summary | Export-Excel @summaryParams

# Feuille résumé par type de principal
$summaryType = $report |
    Group-Object "Type de principal" |
    Select-Object @{N="Type";E={$_.Name}}, @{N="Nombre";E={$_.Count}} |
    Sort-Object Nombre -Descending

$summaryTypeParams = @{
    Path          = $OutputPath
    WorksheetName = "Résumé par type"
    AutoSize      = $true
    BoldTopRow    = $true
    TableStyle    = "Medium4"
    Append        = $true
}
$summaryType | Export-Excel @summaryTypeParams

# ── Résultat ──────────────────────────────────────────────────
Write-Host "`n✅ Rapport généré avec succès !" -ForegroundColor Green
Write-Host "   📁 Fichier : $OutputPath" -ForegroundColor White
Write-Host "   📄 Feuilles :" -ForegroundColor White
Write-Host "      • Attributions RBAC (détail complet)"
Write-Host "      • Résumé par rôle"
Write-Host "      • Résumé par type de principal"
Write-Host "`n   Total : $($report.Count) attribution(s) exportée(s)" -ForegroundColor Cyan

# Ouvrir le fichier automatiquement (Windows)
if ($IsWindows -or $env:OS -match "Windows") {
    Invoke-Item $OutputPath
}