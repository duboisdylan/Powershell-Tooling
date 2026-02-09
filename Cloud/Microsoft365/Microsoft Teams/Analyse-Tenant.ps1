param(
    [string]$OutputPath = ".\TeamsPhone_Export_$(Get-Date -Format 'yyyyMMdd_HHmmss').xlsx"
)

# --- Helpers ---
function Export-Sheet {
    param(
        [Parameter(Mandatory)]$Data,
        [Parameter(Mandatory)][string]$Worksheet,
        [string]$TableName
    )

    if (-not $TableName) { $TableName = ($Worksheet -replace '\W', '') }
    if ($null -eq $Data -or ($Data | Measure-Object).Count -eq 0) {
        # Crée quand même l’onglet avec une ligne “vide” informative
        [pscustomobject]@{ Info = "Aucune donnée retournée pour $Worksheet (ou cmdlet non disponible/permissions)." } |
        Export-Excel -Path $OutputPath -WorksheetName $Worksheet -TableName $TableName -AutoSize -FreezeTopRow -BoldTopRow
    }
    else {
        $Data | Export-Excel -Path $OutputPath -WorksheetName $Worksheet -TableName $TableName -AutoSize -FreezeTopRow -BoldTopRow
    }
}

# --- Collecte ---
Write-Host "Collecte Call Queues / Auto Attendants / Voice / Users / Policies / SBC..." -ForegroundColor Cyan

# Call Queues
$cq = @()
try {
    $cq = Get-CsCallQueue | Select-Object `
        Name, Identity, LanguageId, AgentAlertTime, RoutingMethod, DistributionLists, AllowOptOut, PresenceBasedRouting, ConferenceMode, WelcomeMusicAudioFileId, MusicOnHoldAudioFileId
}
catch {}

# Auto Attendants
$aa = @()
try {
    $aa = Get-CsAutoAttendant | Select-Object `
        Name, Identity, LanguageId, TimeZone, DefaultCallFlow, CallFlows, Schedules, Operator
}
catch {}

# Resource Accounts (Application Instances)
$ra = @()
try {
    $ra = Get-CsOnlineApplicationInstance | Select-Object `
        DisplayName, UserPrincipalName, ObjectId, ApplicationId, PhoneNumber, OnlineVoiceRoutingPolicy, OnlineDialPlan
}
catch {}

# SBC / Direct Routing Gateways
$sbc = @()
try {
    $sbc = Get-CsOnlinePSTNGateway | Select-Object `
        Identity, Fqdn, SipSignalingPort, Enabled, MediaBypass, MaxConcurrentSessions, ForwardCallHistory, FailoverResponseCodes, GatewaySiteId
}
catch {}

# Voice: routes / usages / policies / dial plans / normalization
$voiceRoutes = @()
try { $voiceRoutes = Get-CsOnlineVoiceRoute | Select-Object Identity, Name, NumberPattern, OnlinePstnGatewayList, OnlinePstnUsages, Priority, Description } catch {}

$pstnUsage = @()
try { $pstnUsage = Get-CsOnlinePstnUsage | Select-Object Identity, Usage } catch {}

$vrp = @()
try { $vrp = Get-CsOnlineVoiceRoutingPolicy | Select-Object Identity, Description, OnlinePstnUsages } catch {}

$voicePolicy = @()
try { $voicePolicy = Get-CsOnlineVoicePolicy | Select-Object Identity, Description, PstnUsages, AllowCallForwardingToPhone, AllowPSTNCalling, PreventTollBypass } catch {}

$dialPlans = @()
try { $dialPlans = Get-CsOnlineDialPlan | Select-Object Identity, SimpleName, Description, ExternalAccessPrefix, NormalizeNumberFromE164, DialPlanRules } catch {}

$normRules = @()
try { $normRules = Get-CsVoiceNormalizationRule | Select-Object Identity, Name, Pattern, Translation, Description, IsInternalExtension } catch {}

# Stratégies “call/voice” côté Teams
$callingPolicy = @()
try { $callingPolicy = Get-CsTeamsCallingPolicy | Select-Object Identity, Description, AllowPrivateCalling, AllowCallForwardingToUser, AllowCallForwardingToPhone, AllowCallGroups } catch {}

$callerIdPolicy = @()
try { $callerIdPolicy = Get-CsCallingLineIdentity | Select-Object Identity, Description, CallingIDSubstitute, EnableUserOverride, ServiceNumber, BlockIncomingPstnCallerID } catch {}

$emergencyPolicy = @()
try { $emergencyPolicy = Get-CsTeamsEmergencyCallingPolicy | Select-Object Identity, Description, NotificationGroup, NotifySecuriyDesk, EmergencyNumbers } catch {}

# Utilisateurs (Voice enabled + numéros + policies principales)
$users = @()
try {
    # Attention: gros tenant => peut être long
    $users = Get-CsOnlineUser | Select-Object DisplayName, UserPrincipalName, Enabled, EnterpriseVoiceEnabled, HostedVoiceMail, LineURI, OnPremLineURI, PhoneNumber, OnlineVoiceRoutingPolicy, OnlineDialPlan, TenantDialPlan, TeamsCallingPolicy, CallingLineIdentity, TeamsEmergencyCallingPolicy, UsageLocation
}
catch {}

# Assignments de numéros (si disponible dans ton module/tenant)
$phoneAssignments = @()
try {
    $phoneAssignments = Get-CsPhoneNumberAssignment | Select-Object `
        TelephoneNumber, NumberType, ActivationState, AssignedPstnTargetId, AssignedPstnTargetType, City, CountryOrRegion
}
catch {}

# --- Exports XLSX ---
# Nettoyage fichier existant si besoin
if (Test-Path $OutputPath) { Remove-Item $OutputPath -Force }

Export-Sheet -Data $cq              -Worksheet "CallQueues"              -TableName "CallQueues"
Export-Sheet -Data $aa              -Worksheet "AutoAttendants"          -TableName "AutoAttendants"
Export-Sheet -Data $ra              -Worksheet "ResourceAccounts"        -TableName "ResourceAccounts"
Export-Sheet -Data $sbc             -Worksheet "SBC_PSTNGateways"        -TableName "SBCPSTNGateways"

Export-Sheet -Data $voiceRoutes     -Worksheet "VoiceRoutes"             -TableName "VoiceRoutes"
Export-Sheet -Data $pstnUsage       -Worksheet "PSTNUsages"              -TableName "PSTNUsages"
Export-Sheet -Data $vrp             -Worksheet "VoiceRoutingPolicies"    -TableName "VoiceRoutingPolicies"
Export-Sheet -Data $voicePolicy     -Worksheet "VoicePolicies"           -TableName "VoicePolicies"
Export-Sheet -Data $dialPlans       -Worksheet "DialPlans"               -TableName "DialPlans"
Export-Sheet -Data $normRules       -Worksheet "NormalizationRules"      -TableName "NormalizationRules"

Export-Sheet -Data $callingPolicy   -Worksheet "TeamsCallingPolicies"    -TableName "TeamsCallingPolicies"
Export-Sheet -Data $callerIdPolicy  -Worksheet "CallerIDPolicies"        -TableName "CallerIDPolicies"
Export-Sheet -Data $emergencyPolicy -Worksheet "EmergencyCallingPolicy"  -TableName "EmergencyCallingPolicy"

Export-Sheet -Data $users           -Worksheet "Users_TeamsPhone"        -TableName "UsersTeamsPhone"
Export-Sheet -Data $phoneAssignments-Worksheet "PhoneNumberAssignments"  -TableName "PhoneNumberAssignments"

Write-Host "Export terminé : $OutputPath" -ForegroundColor Green
