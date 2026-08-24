#Requires -Modules Microsoft.Graph.Authentication

<#
.SYNOPSIS
    Liste les UPN et les rôles Entra ID (permanents, PIM actifs, PIM éligibles)
    via connexion interactive avec un compte Global Reader.

.PARAMETER OutputCsv
    Chemin du fichier CSV de sortie. Si omis, affichage console uniquement.

.EXAMPLE
    .\Get-EntraIDRolesWithPIM.ps1

.EXAMPLE
    .\Get-EntraIDRolesWithPIM.ps1 -OutputCsv "C:\Temp\roles.csv"

.NOTES
    Permissions requises sur le compte connecté :
      - Global Reader (couvre RoleManagement.Read.Directory + PrivilegedAccess.Read.AzureAD + Directory.Read.All)
#>

[CmdletBinding()]
param (
    [string]$OutputCsv
)

# ─────────────────────────────────────────────
#  CONNEXION INTERACTIVE
# ─────────────────────────────────────────────

Write-Host "`n=== Connexion à Microsoft Graph ===" -ForegroundColor Cyan

Connect-MgGraph -Scopes `
    "RoleManagement.Read.Directory",
    "PrivilegedAccess.Read.AzureAD",
    "Directory.Read.All" `
    -NoWelcome

Write-Host "Connecté en tant que : $((Get-MgContext).Account)" -ForegroundColor Green

# ─────────────────────────────────────────────
#  FONCTIONS UTILITAIRES
# ─────────────────────────────────────────────

$script:roleCache = @{}
$script:userCache = @{}

function Invoke-GraphPagedRequest {
    param ([Parameter(Mandatory)][string]$Uri)

    $allResults = @()
    $nextUri    = $Uri

    do {
        try {
            $response    = Invoke-MgGraphRequest -Uri $nextUri -Method GET -OutputType PSObject
            $allResults += $response.value
            $nextUri     = $response.'@odata.nextLink'
        }
        catch {
            Write-Warning "Erreur Graph [$nextUri] : $_"
            break
        }
    } while ($nextUri)

    return $allResults
}

function Get-RoleName {
    param ([string]$RoleDefinitionId)
    if ($script:roleCache.ContainsKey($RoleDefinitionId)) {
        return $script:roleCache[$RoleDefinitionId]
    }
    try {
        $role = Invoke-MgGraphRequest `
            -Uri    "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions/$RoleDefinitionId" `
            -Method GET -OutputType PSObject
        $script:roleCache[$RoleDefinitionId] = $role.displayName
        return $role.displayName
    }
    catch { return $RoleDefinitionId }
}

function Get-PrincipalUPN {
    param ([string]$PrincipalId)
    if ($script:userCache.ContainsKey($PrincipalId)) {
        return $script:userCache[$PrincipalId]
    }
    try {
        $obj = Invoke-MgGraphRequest `
            -Uri    "https://graph.microsoft.com/v1.0/directoryObjects/$PrincipalId" `
            -Method GET -OutputType PSObject
        $upn = if ($obj.userPrincipalName)  { $obj.userPrincipalName }
               elseif ($obj.displayName)    { "$($obj.displayName) [$($obj.'@odata.type' -replace '#microsoft.graph.','')]" }
               else                         { $PrincipalId }
    }
    catch { $upn = $PrincipalId }

    $script:userCache[$PrincipalId] = $upn
    return $upn
}

# ─────────────────────────────────────────────
#  COLLECTE DES DONNÉES
# ─────────────────────────────────────────────

$results = [System.Collections.Generic.List[PSCustomObject]]::new()

# --- 1. Rôles permanents (hors PIM) ---

Write-Host "`n[1/3] Rôles permanents (directs, hors PIM)..." -ForegroundColor Yellow

$permanent = Invoke-GraphPagedRequest `
    -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?`$expand=roleDefinition&`$top=999"

foreach ($a in $permanent) {
    $roleName = if ($a.roleDefinition.displayName) { $a.roleDefinition.displayName }
                else { Get-RoleName $a.roleDefinitionId }

    $results.Add([PSCustomObject]@{
        UPN             = Get-PrincipalUPN $a.principalId
        Role            = $roleName
        TypeAffectation = "Permanent (hors PIM)"
        StatutPIM       = "Non soumis a PIM"
        DebutActivation = ""
        FinActivation   = ""
    })
}

Write-Host "  -> $($permanent.Count) affectation(s) permanente(s)" -ForegroundColor DarkGray

# --- 2. Rôles PIM actifs ---

Write-Host "[2/3] Rôles PIM actifs (activés en ce moment)..." -ForegroundColor Yellow

$pimActifs = Invoke-GraphPagedRequest `
    -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleInstances?`$expand=roleDefinition&`$top=999"

foreach ($a in $pimActifs) {
    # Ignorer les lignes qui correspondent à des affectations permanentes déjà remontées
    # (memberType = "Direct" sans expiration = doublons avec /roleAssignments)
    if ($a.memberType -eq "Direct" -and -not $a.endDateTime) { continue }

    $roleName = if ($a.roleDefinition.displayName) { $a.roleDefinition.displayName }
                else { Get-RoleName $a.roleDefinitionId }

    $results.Add([PSCustomObject]@{
        UPN             = Get-PrincipalUPN $a.principalId
        Role            = $roleName
        TypeAffectation = "PIM Actif"
        StatutPIM       = "PIM -- Role actif (active)"
        DebutActivation = $a.startDateTime
        FinActivation   = if ($a.endDateTime) { $a.endDateTime } else { "Sans expiration" }
    })
}

Write-Host "  -> $($pimActifs.Count) instance(s) PIM active(s)" -ForegroundColor DarkGray

# --- 3. Rôles PIM éligibles (non activés) ---

Write-Host "[3/3] Rôles PIM éligibles (non activés)..." -ForegroundColor Yellow

$pimEligibles = Invoke-GraphPagedRequest `
    -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleInstances?`$expand=roleDefinition&`$top=999"

foreach ($a in $pimEligibles) {
    $roleName = if ($a.roleDefinition.displayName) { $a.roleDefinition.displayName }
                else { Get-RoleName $a.roleDefinitionId }

    $results.Add([PSCustomObject]@{
        UPN             = Get-PrincipalUPN $a.principalId
        Role            = $roleName
        TypeAffectation = "PIM Eligible"
        StatutPIM       = "PIM -- Role eligible (non active)"
        DebutActivation = $a.startDateTime
        FinActivation   = if ($a.endDateTime) { $a.endDateTime } else { "Sans expiration" }
    })
}

Write-Host "  -> $($pimEligibles.Count) instance(s) PIM eligible(s)" -ForegroundColor DarkGray

# ─────────────────────────────────────────────
#  AFFICHAGE CONSOLE
# ─────────────────────────────────────────────

Write-Host "`n=== Resultats ($($results.Count) entrees au total) ===" -ForegroundColor Cyan

$results |
    Sort-Object UPN, Role, TypeAffectation |
    Format-Table UPN, Role, TypeAffectation, StatutPIM, DebutActivation, FinActivation -AutoSize

# ─────────────────────────────────────────────
#  EXPORT CSV
# ─────────────────────────────────────────────

if ($OutputCsv) {
    try {
        $results |
            Sort-Object UPN, Role, TypeAffectation |
            Export-Excel -Path $OutputCsv
        Write-Host "Export CSV : $OutputCsv" -ForegroundColor Green
    }
    catch {
        Write-Warning "Impossible d'ecrire le CSV : $_"
    }
}

# ─────────────────────────────────────────────
#  RÉSUMÉ
# ─────────────────────────────────────────────

Write-Host "`n=== Resume ===" -ForegroundColor Cyan
$results | Group-Object TypeAffectation | ForEach-Object {
    Write-Host ("  {0,-30} : {1} entree(s)" -f $_.Name, $_.Count)
}

Write-Host "`nTermine.`n" -ForegroundColor Green