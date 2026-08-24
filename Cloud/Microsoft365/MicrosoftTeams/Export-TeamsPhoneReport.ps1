param(
    [string]$OutputPath = ".\TeamsPhone_Export_$(Get-Date -Format 'yyyyMMdd_HHmmss').xlsx",
    [string]$Delimiter  = "; ",
    [switch]$ResolveDistributionLists,   # essaie de résoudre les GUID des DL en noms
    [switch]$IncludeJson                # ajoute des colonnes JSON pour objets complexes
)

Import-Module ImportExcel -ErrorAction Stop

# -------------------- Helpers --------------------
function Join-MultiValue {
    param(
        [Parameter(Mandatory)]$Value,
        [string]$Delimiter = "; "
    )
    if ($null -eq $Value) { return $null }
    if ($Value -is [string]) { return $Value }
    if ($Value -is [guid])   { return $Value.Guid }

    # IEnumerable (Array, ArrayList, List<T>, Guid[], etc.) => join
    if ($Value -is [System.Collections.IEnumerable]) {
        $items = foreach ($v in $Value) {
            if ($null -eq $v) { continue }
            if ($v -is [guid]) { $v.Guid } else { $v.ToString() }
        }
        return ($items | Where-Object { $_ -and $_.Trim() -ne "" }) -join $Delimiter
    }

    return $Value.ToString()
}

function To-JsonSafe {
    param([Parameter(Mandatory)]$Obj, [int]$Depth = 30)
    if ($null -eq $Obj) { return $null }
    try { return ($Obj | ConvertTo-Json -Depth $Depth) } catch { return $Obj.ToString() }
}

function Export-Sheet {
    param(
        [Parameter(Mandatory)]$Data,
        [Parameter(Mandatory)][string]$Worksheet,
        [string]$TableName,
        [bool]$WrapText = $false
    )

    if (-not $TableName) { $TableName = ($Worksheet -replace '\W', '') }

    # Si aucune donnée, on met une ligne info pour créer l'onglet
    if ($null -eq $Data -or ($Data | Measure-Object).Count -eq 0) {
        $Data = [pscustomobject]@{
            Info = "Aucune donnée retournée pour $Worksheet (cmdlet indispo / permissions / vide)."
        }
    }

    # Export classique (sans -WrapText pour compat)
    $Data | Export-Excel -Path $OutputPath -WorksheetName $Worksheet -TableName $TableName `
        -AutoSize -FreezeTopRow -BoldTopRow -AutoFilter

    # WrapText appliqué ensuite sur la zone utilisée (dimension)
    if ($WrapText) {
        $pkg = Open-ExcelPackage -Path $OutputPath
        $ws  = $pkg.Workbook.Worksheets[$Worksheet]
        if ($ws -and $ws.Dimension) {
            Set-ExcelRange -Worksheet $ws -Range $ws.Dimension.Address -WrapText
        }
        Close-ExcelPackage $pkg
    }
}


# --- Résolution de GUID de groupes (DistributionLists) ---
$GroupCache = @{}
function Resolve-GroupGuid {
    param([Parameter(Mandatory)][guid]$Id)

    $key = $Id.Guid
    if ($GroupCache.ContainsKey($key)) { return $GroupCache[$key] }

    $resolved = $key
    try {
        if (Get-Command Get-MgGroup -ErrorAction SilentlyContinue) {
            # nécessite Connect-MgGraph (ex: Group.Read.All)
            $g = Get-MgGroup -GroupId $key -Property Id,DisplayName,Mail -ErrorAction Stop
            if ($g) {
                $resolved = if ($g.Mail) { "$($g.DisplayName) <$($g.Mail)>" } else { $g.DisplayName }
            }
        }
        elseif (Get-Command Get-AzureADGroup -ErrorAction SilentlyContinue) {
            $g = Get-AzureADGroup -ObjectId $key -ErrorAction Stop
            if ($g) {
                $resolved = if ($g.Mail) { "$($g.DisplayName) <$($g.Mail)>" } else { $g.DisplayName }
            }
        }
        elseif (Get-Command Get-UnifiedGroup -ErrorAction SilentlyContinue) {
            # nécessite EXO (Connect-ExchangeOnline)
            $g = Get-UnifiedGroup -Identity $key -ErrorAction Stop
            if ($g) {
                $resolved = if ($g.PrimarySmtpAddress) { "$($g.DisplayName) <$($g.PrimarySmtpAddress)>" } else { $g.DisplayName }
            }
        }
    } catch { }

    $GroupCache[$key] = $resolved
    return $resolved
}

function Resolve-GuidListToNames {
    param($GuidArray, [string]$Delimiter="; ")
    if ($null -eq $GuidArray) { return $null }

    $out = foreach ($v in $GuidArray) {
        if ($null -eq $v) { continue }
        $tmp = [guid]::Empty
        if ($v -is [guid]) {
            Resolve-GroupGuid -Id $v
        }
        elseif ([guid]::TryParse($v.ToString(), [ref]$tmp)) {
            Resolve-GroupGuid -Id $tmp
        }
        else {
            $v.ToString()
        }
    }
    return ($out | Where-Object { $_ }) -join $Delimiter
}

# -------------------- Collecte --------------------
Write-Host "Collecte Teams Phone (CQ/AA/Voice/Users/Policies/SBC/Unassigned)..." -ForegroundColor Cyan

# Info sheet
$info = [pscustomobject]@{
    ExportDateTime = (Get-Date).ToString("s")
    MicrosoftTeamsModule = (Get-Module MicrosoftTeams -ListAvailable | Sort-Object Version -Descending | Select-Object -First 1).Version.ToString()
    ImportExcelModule    = (Get-Module ImportExcel    -ListAvailable | Sort-Object Version -Descending | Select-Object -First 1).Version.ToString()
}

# Call Queues
$cq = @()
try {
    $cqRaw = Get-CsCallQueue
    $cq = $cqRaw | Select-Object `
        Name, Identity, LanguageId, AgentAlertTime, RoutingMethod, AllowOptOut, PresenceBasedRouting, ConferenceMode, `
        @{N='DistributionLists_Raw'; E={ Join-MultiValue $_.DistributionLists $Delimiter }}, `
        @{N='DistributionLists_Friendly'; E={
            if ($ResolveDistributionLists) { Resolve-GuidListToNames $_.DistributionLists $Delimiter }
            else { $null }
        }}, `
        WelcomeMusicAudioFileId, MusicOnHoldAudioFileId
}
catch {}

# Auto Attendants (Summary + JSON + CallFlows/MenuOptions)
$aaSummary   = @()
$aaCallFlows = @()
$aaMenu      = @()

try {
    $aaRaw = Get-CsAutoAttendant
    $aaSummary = $aaRaw | Select-Object `
        Name, Identity, LanguageId, TimeZone, `
        @{N='Operator'; E={ Join-MultiValue $_.Operator $Delimiter }}, `
        @{N='DefaultCallFlowName'; E={ $_.DefaultCallFlow.Name }}, `
        @{N='CallFlows_Names';     E={ Join-MultiValue ($_.CallFlows | ForEach-Object {$_.Name}) $Delimiter }}, `
        @{N='Schedules_Names';     E={ Join-MultiValue ($_.Schedules | ForEach-Object {$_.Name}) $Delimiter }}, `
        @{N='DefaultCallFlow_JSON';E={ if($IncludeJson){ To-JsonSafe $_.DefaultCallFlow } else { $null } }}, `
        @{N='CallFlows_JSON';      E={ if($IncludeJson){ To-JsonSafe $_.CallFlows } else { $null } }}, `
        @{N='Schedules_JSON';      E={ if($IncludeJson){ To-JsonSafe $_.Schedules } else { $null } }}

    foreach ($aa in $aaRaw) {
        $allFlows = @()
        if ($aa.DefaultCallFlow) { $allFlows += [pscustomobject]@{ Flow=$aa.DefaultCallFlow; IsDefault=$true } }
        if ($aa.CallFlows) {
            foreach ($cf in $aa.CallFlows) { $allFlows += [pscustomobject]@{ Flow=$cf; IsDefault=$false } }
        }

        foreach ($x in $allFlows) {
            $cf = $x.Flow
            $aaCallFlows += [pscustomobject]@{
                AutoAttendantName = $aa.Name
                AutoAttendantId   = $aa.Identity
                CallFlowName      = $cf.Name
                IsDefault         = $x.IsDefault
                CallFlow_JSON     = To-JsonSafe $cf
            }

            # Menu options (si présents) => table exploitable
            $menuOptions = $null
            try { $menuOptions = $cf.Menu.MenuOptions } catch { $menuOptions = $null }

            if ($menuOptions) {
                foreach ($opt in $menuOptions) {
                    $aaMenu += [pscustomobject]@{
                        AutoAttendantName = $aa.Name
                        AutoAttendantId   = $aa.Identity
                        CallFlowName      = $cf.Name
                        IsDefault         = $x.IsDefault
                        DtmfResponse      = $opt.DtmfResponse
                        VoiceResponse     = $opt.VoiceResponse
                        Action            = $opt.Action
                        # cible: on garde du “best effort” + JSON pour ne rien perdre
                        Target            = (try { $opt.CallTarget.Id } catch { $null })
                        TargetType        = (try { $opt.CallTarget.Type } catch { $null })
                        Option_JSON       = To-JsonSafe $opt
                    }
                }
            }
        }
    }
}
catch {}

# Resource Accounts
$ra = @()
try {
    $ra = Get-CsOnlineApplicationInstance | Select-Object `
        DisplayName, UserPrincipalName, ObjectId, ApplicationId, PhoneNumber, OnlineVoiceRoutingPolicy, OnlineDialPlan
}
catch {}

# SBC / Gateways
$sbc = @()
try {
    $sbc = Get-CsOnlinePSTNGateway | Select-Object `
        Identity, Fqdn, SipSignalingPort, Enabled, MediaBypass, MaxConcurrentSessions, ForwardCallHistory, `
        @{N='FailoverResponseCodes';E={ Join-MultiValue $_.FailoverResponseCodes $Delimiter }}, `
        GatewaySiteId
}
catch {}

# Voice routes / usages / policies
$voiceRoutes = @()
try {
    $voiceRoutes = Get-CsOnlineVoiceRoute | Select-Object `
        Identity, Name, NumberPattern, Priority, Description, `
        @{N='OnlinePstnGatewayList';E={ Join-MultiValue $_.OnlinePstnGatewayList $Delimiter }}, `
        @{N='OnlinePstnUsages';     E={ Join-MultiValue $_.OnlinePstnUsages $Delimiter }}
}
catch {}

$pstnUsage = @()
try {
    # Get-CsOnlinePstnUsage renvoie souvent un objet avec une liste dans .Usage
    $pstnUsage = foreach ($u in (Get-CsOnlinePstnUsage)) {
        foreach ($usage in $u.Usage) {
            [pscustomobject]@{ Identity = $u.Identity; Usage = $usage }
        }
    }
}
catch {}

$vrp = @()
try {
    $vrp = Get-CsOnlineVoiceRoutingPolicy | Select-Object `
        Identity, Description, @{N='OnlinePstnUsages';E={ Join-MultiValue $_.OnlinePstnUsages $Delimiter }}
}
catch {}

$voicePolicy = @()
try {
    $voicePolicy = Get-CsOnlineVoicePolicy | Select-Object `
        Identity, Description, AllowCallForwardingToPhone, AllowPSTNCalling, PreventTollBypass, `
        @{N='PstnUsages';E={ Join-MultiValue $_.PstnUsages $Delimiter }}
}
catch {}

$dialPlans = @()
try {
    $dialPlans = Get-CsOnlineDialPlan | Select-Object `
        Identity, SimpleName, Description, ExternalAccessPrefix, NormalizeNumberFromE164, `
        @{N='DialPlanRules';E={ if($IncludeJson){ To-JsonSafe $_.DialPlanRules } else { Join-MultiValue $_.DialPlanRules $Delimiter } }}
}
catch {}

$normRules = @()
try { $normRules = Get-CsVoiceNormalizationRule | Select-Object Identity, Name, Pattern, Translation, Description, IsInternalExtension } catch {}

# Policies Teams (custom calling policy)
$callingPolicy = @()
try {
    $callingPolicy = Get-CsTeamsCallingPolicy |
        Where-Object { $_.Identity -ne "Global" } |
        Select-Object Identity, Description, AllowPrivateCalling, AllowCallForwardingToUser, AllowCallForwardingToPhone, AllowCallGroups
}
catch {}

$callerIdPolicy = @()
try { $callerIdPolicy = Get-CsCallingLineIdentity | Select-Object Identity, Description, CallingIDSubstitute, EnableUserOverride, ServiceNumber, BlockIncomingPstnCallerID } catch {}

$emergencyPolicy = @()
try {
    $emergencyPolicy = Get-CsTeamsEmergencyCallingPolicy | Select-Object `
        Identity, Description, NotifySecuriyDesk, `
        @{N='NotificationGroup';E={ Join-MultiValue $_.NotificationGroup $Delimiter }}, `
        @{N='EmergencyNumbers'; E={ Join-MultiValue $_.EmergencyNumbers $Delimiter }}
}
catch {}

# Unassigned numbers routing rules (Treatments)
$unassigned = @()
try {
    # cmdlet Teams dédiée
    $unassigned = Get-CsTeamsUnassignedNumberTreatment | Select-Object `
        Identity, Description, Pattern, `
        @{N='Target';E={ try { $_.Target } catch { $null } }}, `
        @{N='TargetType';E={ try { $_.TargetType } catch { $null } }}, `
        @{N='TreatmentPriority';E={ try { $_.TreatmentPriority } catch { $null } }}, `
        @{N='Raw_JSON';E={ if($IncludeJson){ To-JsonSafe $_ } else { $null } }}
}
catch {}

# Utilisateurs (Voice enabled + numéros + policies)
$users = @()
try {
    $users = Get-CsOnlineUser | Select-Object `
        DisplayName, UserPrincipalName, Enabled, EnterpriseVoiceEnabled, HostedVoiceMail, `
        LineURI, OnPremLineURI, PhoneNumber, UsageLocation, `
        OnlineVoiceRoutingPolicy, OnlineDialPlan, TenantDialPlan, TeamsCallingPolicy, CallingLineIdentity, TeamsEmergencyCallingPolicy
}
catch {}

# Assignments de numéros
$phoneAssignments = @()
try {
    $phoneAssignments = Get-CsPhoneNumberAssignment | Select-Object `
        TelephoneNumber, NumberType, ActivationState, AssignedPstnTargetId, AssignedPstnTargetType, City, CountryOrRegion
}
catch {}

# -------------------- Export XLSX --------------------
if (Test-Path $OutputPath) { Remove-Item $OutputPath -Force }

Export-Sheet -Data $info            -Worksheet "INFO"                   -TableName "INFO"

Export-Sheet -Data $cq              -Worksheet "CallQueues"              -TableName "CallQueues"
Export-Sheet -Data $aaSummary       -Worksheet "AutoAttendants"          -TableName "AutoAttendants"
Export-Sheet -Data $aaCallFlows     -Worksheet "AA_CallFlows"            -TableName "AACallFlows"
Export-Sheet -Data $aaMenu          -Worksheet "AA_MenuOptions"          -TableName "AAMenuOptions"

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

Export-Sheet -Data $unassigned      -Worksheet "UnassignedNumberRules"   -TableName "UnassignedNumberRules"

Export-Sheet -Data $users           -Worksheet "Users_TeamsPhone"        -TableName "UsersTeamsPhone"
Export-Sheet -Data $phoneAssignments-Worksheet "PhoneNumberAssignments"  -TableName "PhoneNumberAssignments"

Write-Host "Export terminé : $OutputPath" -ForegroundColor Green
