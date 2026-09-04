<#
.SYNOPSIS
    Analyse l'affectation des numéros de téléphone aux utilisateurs Teams en Direct Routing.

.DESCRIPTION
    Ce script se connecte au module MicrosoftTeams, récupère les numéros de type "DirectRouting"
    via Get-CsPhoneNumberAssignment, puis croise ces numéros avec les informations utilisateurs
    (Get-CsOnlineUser) : Enterprise Voice, politique de routage vocal, dial plan, politique
    d'appel, informations RH (société, département, poste), etc. Il met également en évidence
    les incohérences courantes (numéro affecté mais Enterprise Voice désactivé, politique de
    routage vocal manquante, etc.).

.PARAMETER OutputPath
    Chemin du fichier Excel (.xlsx) de sortie. Par défaut, un fichier horodaté est créé dans
    le dossier _Output à la racine du dépôt (chemin relatif au script).

.PARAMETER IncludeUnassignedEVUsers
    Ajoute un onglet listant les utilisateurs Enterprise Voice activés qui n'ont aucun numéro
    Direct Routing affecté (utile pour détecter les oublis).

.EXAMPLE
    .\Get-TeamsDirectRoutingUserAssignment.ps1

.EXAMPLE
    .\Get-TeamsDirectRoutingUserAssignment.ps1 -IncludeUnassignedEVUsers
#>

param(
    [string]$OutputPath = (Join-Path $PSScriptRoot "..\..\..\_Output\TeamsDirectRouting_UserAssignment_$(Get-Date -Format 'yyyyMMdd_HHmmss').xlsx"),
    [switch]$IncludeUnassignedEVUsers
)

Import-Module ImportExcel -ErrorAction Stop

# -------------------- Connexion --------------------
if (-not (Get-Module -Name MicrosoftTeams -ListAvailable)) {
    Throw "Le module MicrosoftTeams n'est pas installé. Installez-le via 'Install-Module MicrosoftTeams'."
}

try {
    Get-CsTenant -ErrorAction Stop | Out-Null
}
catch {
    Write-Host "Connexion à Microsoft Teams..." -ForegroundColor Cyan
    Connect-MicrosoftTeams | Out-Null
}

# -------------------- Collecte des numéros Direct Routing --------------------
Write-Host "Récupération des numéros Direct Routing..." -ForegroundColor Cyan
$drNumbers = @()
try {
    $drNumbers = Get-CsPhoneNumberAssignment -NumberType DirectRouting -ErrorAction Stop
}
catch {
    Throw "Impossible de récupérer les numéros Direct Routing : $($_.Exception.Message)"
}

if (-not $drNumbers -or $drNumbers.Count -eq 0) {
    Write-Warning "Aucun numéro de type DirectRouting trouvé dans le tenant."
}

# -------------------- Collecte des utilisateurs Teams --------------------
Write-Host "Récupération des utilisateurs Teams (Get-CsOnlineUser)..." -ForegroundColor Cyan
$csUsers = Get-CsOnlineUser

$userIndex = @{}
foreach ($u in $csUsers) {
    if ($u.Identity) { $userIndex[$u.Identity] = $u }
    if ($u.ObjectId) { $userIndex[$u.ObjectId] = $u }
}

# -------------------- Croisement Numéros DR <-> Utilisateurs --------------------
$assignedResults = New-Object System.Collections.Generic.List[object]
$assignedTargetIds = New-Object System.Collections.Generic.HashSet[string]

foreach ($num in $drNumbers) {

    $targetId = $num.AssignedPstnTargetId
    if ($targetId) { [void]$assignedTargetIds.Add($targetId) }

    $user = $null
    if ($targetId -and $userIndex.ContainsKey($targetId)) {
        $user = $userIndex[$targetId]
    }

    $anomalies = New-Object System.Collections.Generic.List[string]

    if (-not $targetId) {
        $anomalies.Add("Numéro DirectRouting non affecté")
    }
    elseif (-not $user) {
        $anomalies.Add("Cible affectée introuvable via Get-CsOnlineUser (peut-être un compte de ressource ou un objet supprimé)")
    }
    else {
        if (-not $user.EnterpriseVoiceEnabled) {
            $anomalies.Add("Numéro affecté mais EnterpriseVoiceEnabled = False")
        }
        if (-not $user.OnlineVoiceRoutingPolicy) {
            $anomalies.Add("Aucune OnlineVoiceRoutingPolicy affectée")
        }
        if (-not $user.UsageLocation) {
            $anomalies.Add("UsageLocation manquant")
        }
        if ($user.Enabled -eq $false) {
            $anomalies.Add("Compte désactivé (Enabled = False)")
        }
    }

    $assignedResults.Add([pscustomobject]@{
        TelephoneNumber           = $num.TelephoneNumber
        NumberType                = $num.NumberType
        ActivationState           = $num.ActivationState
        IsoCountryCode             = $num.IsoCountryCode
        City                       = $num.City
        AssignedPstnTargetType    = $num.AssignedPstnTargetType
        AssignedPstnTargetId      = $targetId
        DisplayName                = $user.DisplayName
        UserPrincipalName         = $user.UserPrincipalName
        CompanyName                = $user.Company
        Department                 = $user.Department
        JobTitle                   = $user.Title
        SipAddress                 = $user.SipAddress
        Enabled                    = $user.Enabled
        AccountType                = $user.InterpretedUserType
        UsageLocation              = $user.UsageLocation
        EnterpriseVoiceEnabled    = $user.EnterpriseVoiceEnabled
        HostedVoiceMail            = $user.HostedVoiceMail
        OnlineVoiceRoutingPolicy  = $user.OnlineVoiceRoutingPolicy
        OnlineDialPlan             = $user.OnlineDialPlan
        TenantDialPlan             = $user.TenantDialPlan
        TeamsCallingPolicy         = $user.TeamsCallingPolicy
        Anomalies                  = ($anomalies -join " | ")
    })
}

# -------------------- Utilisateurs Enterprise Voice sans numéro DR --------------------
$unassignedResults = New-Object System.Collections.Generic.List[object]

if ($IncludeUnassignedEVUsers) {
    Write-Host "Recherche des utilisateurs Enterprise Voice sans numéro Direct Routing affecté..." -ForegroundColor Cyan

    $evUsersWithoutNumber = $csUsers | Where-Object {
        $_.EnterpriseVoiceEnabled -eq $true -and
        (-not $assignedTargetIds.Contains($_.Identity)) -and
        (-not $assignedTargetIds.Contains($_.ObjectId))
    }

    foreach ($user in $evUsersWithoutNumber) {
        $unassignedResults.Add([pscustomobject]@{
            DisplayName                = $user.DisplayName
            UserPrincipalName         = $user.UserPrincipalName
            CompanyName                = $user.Company
            Department                 = $user.Department
            JobTitle                   = $user.Title
            SipAddress                 = $user.SipAddress
            Enabled                    = $user.Enabled
            AccountType                = $user.InterpretedUserType
            UsageLocation              = $user.UsageLocation
            EnterpriseVoiceEnabled    = $user.EnterpriseVoiceEnabled
            HostedVoiceMail            = $user.HostedVoiceMail
            OnlineVoiceRoutingPolicy  = $user.OnlineVoiceRoutingPolicy
            OnlineDialPlan             = $user.OnlineDialPlan
            TenantDialPlan             = $user.TenantDialPlan
            TeamsCallingPolicy         = $user.TeamsCallingPolicy
            Anomalies                  = "EnterpriseVoiceEnabled = True mais aucun numéro DirectRouting affecté"
        })
    }
}

# -------------------- Export Excel --------------------
$outputDir = Split-Path -Path $OutputPath -Parent
if ($outputDir -and -not (Test-Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
}
if (Test-Path $OutputPath) { Remove-Item $OutputPath -Force }

$assignedResults | Export-Excel -Path $OutputPath -WorksheetName "DirectRouting_Assigned" -TableName "DirectRoutingAssigned" `
    -AutoSize -FreezeTopRow -BoldTopRow -AutoFilter

if ($IncludeUnassignedEVUsers) {
    $dataUnassigned = $unassignedResults
    if ($dataUnassigned.Count -eq 0) {
        $dataUnassigned = [pscustomobject]@{ Info = "Aucun utilisateur Enterprise Voice sans numéro DirectRouting." }
    }
    $dataUnassigned | Export-Excel -Path $OutputPath -WorksheetName "Unassigned_EV_Users" -TableName "UnassignedEVUsers" `
        -AutoSize -FreezeTopRow -BoldTopRow -AutoFilter
}

$anomalyCount = ($assignedResults | Where-Object { $_.Anomalies }).Count
Write-Host "Export terminé : $OutputPath" -ForegroundColor Green
Write-Host "Numéros DirectRouting : $($drNumbers.Count) | Lignes avec anomalie : $anomalyCount | Utilisateurs EV sans numéro : $($unassignedResults.Count)" -ForegroundColor Yellow
