# Report-UserPasswordChanges
# A script to show how to report details of user password settings including dates for last password changes and
# information about account MFA enablement and uses the sign in information for user accounts to figure out if
# an account is active.
# V1.0 5-Jan-2024
# V1.1 17-Mar-2024
# V1.2 12-June-2024 Add check for per-user MFA state
# V1.3 20-June-2024 Add better output for authentication methods registered for a user
# V1.4 18-Sep-2025  Updated with SDK cmdlets
# V1.5 30-Oct-2025  Added last used date for authentication methods
# V1.6 01-Jun-2026  Fixed guest accounts missing auth methods; removed duplicated code block
# V1.7 01-Jun-2026  Removed MFA last used; added Security Group membership column
# V1.8 01-Jun-2026  Fixed group lookup (transitive members); added Employee Type column

# https://github.com/12Knocksinna/Office365itpros/blob/master/Report-UserPasswordChanges.PS1

Param (
    [Parameter(Mandatory = $false)]
    [switch]$PrivacyFlag  # If set, outputs minimal MFA data (methods list only). Default shows full method details.
)

function Get-AuthMethods {
    # Function to return details of the authentication methods registered for a user
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [string]$UserId
    )
    [array]$AllMethods = @()
    Try {
        [array]$AuthMethods = Get-MgBetaUserAuthenticationMethod -UserId $UserId -ErrorAction Stop
    } Catch {
        Write-Host ("Failed to retrieve authentication methods for user ID {0}: {1}" -f $UserId, $_.Exception.Message) -ForegroundColor Red
        Return $null
    }
    ForEach ($AuthMethod in $AuthMethods) {
       $P1 = $null; $P2 = $null; $LastUsed = $null; $CreatedDate = $null; $DisplayMethod = $null; $MethodSummary = $null
       $Method = $AuthMethod.AdditionalProperties['@odata.type']
       If ($AuthMethod.LastUsedDateTime) {
           $LastUsed = Get-Date($AuthMethod.LastUsedDateTime) -format "dd-MMM-yyyy HH:mm"
       }
       If ($AuthMethod.CreatedDateTime) {
           $CreatedDate = Get-Date($AuthMethod.CreatedDateTime) -format "dd-MMM-yyyy HH:mm"
       }
       Switch ($Method) {
           "#microsoft.graph.passwordAuthenticationMethod" {
               $DisplayMethod = "Password"
               If ($LastUsed) {
                   $P1 = "Traditional password - Last used: " + $LastUsed
               } Else {
                   $P1 = "Traditional password - No date for last use"
               }
               $MethodSummary = $P1
           }
           "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod" {
               $DisplayMethod = "Authenticator app"
               $P1 = $AuthMethod.AdditionalProperties['displayName']
               $P2 = $AuthMethod.AdditionalProperties['deviceTag'] + " " + $AuthMethod.AdditionalProperties['phoneAppVersion']
               If ($LastUsed) {
                   $P2 = $P2 + " (Last used: " + $LastUsed + ")"
               }
               $MethodSummary = ("{0} on {1} ({2})" -f $DisplayMethod, $P1, $P2)
           }
           "#microsoft.graph.fido2AuthenticationMethod" {
               If ($AuthMethod.AdditionalProperties['aaGuid'] -eq "90a3ccdf-635c-4729-a248-9b709135078f") {
                   $DisplayMethod = ("Passkey: {0}" -f $AuthMethod.AdditionalProperties['model'])
               } Else {
                   $DisplayMethod = "Fido 2 Key"
               }
               $P1 = $AuthMethod.AdditionalProperties['displayName']
               If ($LastUsed) {
                   $P2 = "Last used: " + $LastUsed
               } Else {
                   $P2 = "No date for last use"
               }
               $MethodSummary = ("Passkey on {0} - {1}" -f $AuthMethod.AdditionalProperties['model'], $P2)
           }
           "#microsoft.graph.phoneAuthenticationMethod" {
                $DisplayMethod = "SMS"
                If ($LastUsed) {
                   $P1 = ("Last used: {0}" -f $LastUsed)
                } Else {
                   $P1 = $null
                }
                $MethodSummary = ("{0} to {1} ({2}) {3}" -f $DisplayMethod, $AuthMethod.AdditionalProperties['phoneNumber'], $AuthMethod.AdditionalProperties['phoneType'], $P1)
           }
           "#microsoft.graph.emailAuthenticationMethod" {
                $DisplayMethod = "Email (SSPR)"
                If ($LastUsed) {
                    $P1 = ("Address {0} Last used: {1}" -f $AuthMethod.AdditionalProperties['emailAddress'], $LastUsed)
                } Else {
                    $P1 = "Address: " + $AuthMethod.AdditionalProperties['emailAddress']
                }
                $MethodSummary = ("{0} to {1}" -f $DisplayMethod, $P1)
           }
           "#microsoft.graph.passwordlessMicrosoftAuthenticatorAuthenticationMethod" {
               $DisplayMethod = "Passwordless"
               $P1 = $AuthMethod.AdditionalProperties['displayName']
               If ($LastUsed) {
                   $P2 = "Last used: " + $LastUsed
               } Else {
                   $P2 = "No date for last use"
               }
               If ($CreatedDate) {
                   $P2 = "Enabled on: " + $CreatedDate
               } Else {
                   $P2 = "Unknown date"
               }
               $MethodSummary = ("{0} {1} - {2}" -f $DisplayMethod, $P1, $P2)
           }
           "#microsoft.graph.windowsHelloForBusinessAuthenticationMethod" {
               $DisplayMethod = "Windows Hello for Business"
               If ($LastUsed) {
                   $P1 = "Last used: " + $LastUsed
               } Else {
                   $P1 = "No date for last use"
               }
               If ($CreatedDate) {
                    $P2 = $CreatedDate
               } Else {
                    $P2 = "Unknown date"
               }
               $MethodSummary = ("{0} ({1}) enabled for {2} on {3}" -f $DisplayMethod, $P1, $AuthMethod.AdditionalProperties['displayName'], $P2)
           }
           Default {
               $DisplayMethod = "Unknown authentication method"
               $MethodSummary = ("Unknown method: {0}" -f $AuthMethod.AdditionalProperties['@odata.type'])
           }
        }
    $MethodSummary = $MethodSummary.Trim()
    $AllMethods += $MethodSummary
    }
    $AllMethods = $AllMethods -join ", "
    Return $AllMethods
}

Connect-MgGraph -NoWelcome -Scopes AuditLog.Read.All, Directory.Read.All, UserAuthenticationMethod.Read.All, Policy.ReadWrite.AuthenticationMethod

[string]$RunDate = Get-Date -format "dd-MMM-yyyy HH:mm:ss"
$Version = "1.8"
$CSVOutputFile = ((New-Object -ComObject Shell.Application).Namespace('shell:Downloads').Self.Path) + "\UserAuthenticationReport.CSV"
$ReportFile = ((New-Object -ComObject Shell.Application).Namespace('shell:Downloads').Self.Path) + "\UserAuthenticationReport.html"


Write-Host "Retrieving user details"
[array]$Users = Get-MgUser -ConsistencyLevel eventual `
    -CountVariable UsersFound -Property id, displayName, userprincipalname, usertype, employeeType, signInActivity, SignInSessionsValidFromDateTime, LastPasswordChangeDateTime, passwordPolicies `
    -All -PageSize 500 -Sort displayName

Write-Host ("All available user accounts fetched ({0}) - now processing report" -f $Users.count) -ForegroundColor Yellow

# Get MFA registration data — keep ALL user types (Member + Guest) so guests appear in the report
[array]$MFAData = Get-MgReportAuthenticationMethodUserRegistrationDetail -All -PageSize 500

# Pre-load security group memberships (one Graph call per group, no per-user queries)
Write-Host "Retrieving security group memberships..."
$SecurityGroupIds = @{
    '3b3019dd-e437-4e48-a88a-5d9def38fcb7' = $null   # SG-MFA-NoRequired (contient des groupes imbriqués)
}
$GroupMemberIndex = @{}   # key = userId, value = [string[]] group display names

foreach ($GroupId in @($SecurityGroupIds.Keys)) {
    Try {
        $GroupName = (Get-MgGroup -GroupId $GroupId -Property DisplayName -ErrorAction Stop).DisplayName
        $SecurityGroupIds[$GroupId] = $GroupName
        Write-Host ("  Group '{0}' ({1}) — loading members..." -f $GroupName, $GroupId)
        # Use TransitiveMember to also catch users added via nested groups
        $Members = Get-MgGroupTransitiveMember -GroupId $GroupId -All -ErrorAction Stop
        foreach ($Member in $Members) {
            $MemberId = $Member.Id.ToString()
            if (-not $GroupMemberIndex.ContainsKey($MemberId)) {
                $GroupMemberIndex[$MemberId] = [System.Collections.Generic.List[string]]::new()
            }
            $GroupMemberIndex[$MemberId].Add($GroupName)
        }
        Write-Host ("    {0} members loaded." -f $Members.Count)
    } Catch {
        Write-Host ("  Failed to retrieve group {0}: {1}" -f $GroupId, $_.Exception.Message) -ForegroundColor Red
    }
}

# Report what we've found
$Report = [System.Collections.Generic.List[Object]]::new()
[int]$i = 0
ForEach ($User in $Users) {
    $i++
    Write-Host ("Processing {0} ({1}/{2})..." -f $User.displayname, $i, $Users.count)
    $DaysSincePasswordChange = $null; $PasswordPoliciesOutput = $null
    $LastSignIn = $null; $LastSuccessfulSignIn = $null; $LastPasswordChange = $null
    $LastSignInOutput = $null; $LastSuccessfulSignInOutput = $null
    $LastPasswordChangeOutput = $null; $SessionTokensValidFromOutput = $null
    $DaysSinceLastSignIn = "N/A"; $DaysSinceLastSuccessfulSignIn = "N/A"

    If (!([string]::IsNullOrWhiteSpace($User.signInActivity.lastSuccessfulSignInDateTime))) {
        $LastSuccessfulSignIn = [datetime]$User.signInActivity.lastSuccessfulSignInDateTime
        $DaysSinceLastSuccessfulSignIn = (New-TimeSpan $LastSuccessfulSignIn).Days
    }
    If (!([string]::IsNullOrWhiteSpace($User.signInActivity.lastSignInDateTime))) {
        $LastSignIn = [datetime]$User.signInActivity.lastSignInDateTime
        $DaysSinceLastSignIn = (New-TimeSpan $LastSignIn).Days
    }
    If (!([string]::IsNullOrWhiteSpace($User.LastPasswordChangeDateTime))) {
        $LastPasswordChange = $User.LastPasswordChangeDateTime
        $DaysSincePasswordChange = (New-TimeSpan $LastPasswordChange).Days
    }

    $SessionTokensValidFrom = $User.SignInSessionsValidFromDateTime
    $LastPasswordChange = $User.LastPasswordChangeDateTime
    [array]$PasswordPolicies = $User.passwordPolicies

    If ($PasswordPolicies) {
        $PasswordPoliciesOutput = $PasswordPolicies -join ", "
    }

    # Get MFA status for the user.
    # PrivacyFlag = simple list of registered method names.
    # Default    = full detail per method via Get-AuthMethods.
    # Note: Get-MgBetaUserAuthenticationMethod works for guests too (external users may have fewer methods).
    $UserMFAStatus = $MFAData | Where-Object { $_.Id -eq $User.Id }
    If ($PrivacyFlag -eq $true) {
        $AuthenticationTypesOutput = $UserMFAStatus.MethodsRegistered -join ", "
    } Else {
        $AuthenticationTypesOutput = Get-AuthMethods -UserId $User.Id
    }

    # Get per-user MFA state — guests may not support this endpoint, error is caught gracefully
    $Data = $null
    Try {
        $Data = Get-MgBetaUserAuthenticationRequirement -UserId $User.Id -ErrorAction Stop
    } Catch {
        Write-Host ("Failed to retrieve MFA requirements for user {0}: {1}" -f $User.displayName, $_.Exception.Message) -ForegroundColor DarkYellow
    }

    # Make sure dates are all in a common format
    If ($LastSignIn) {
        $LastSignInOutput = (Get-Date $LastSignIn -format 'dd-MMM-yyyy HH:mm')
    }
    If ($LastPasswordChange) {
        $LastPasswordChangeOutput = (Get-Date $LastPasswordChange -format 'dd-MMM-yyyy HH:mm')
    }
    If ($LastSuccessfulSignIn) {
        $LastSuccessfulSignInOutput = (Get-Date $LastSuccessfulSignIn -format 'dd-MMM-yyyy HH:mm')
    }
    If ($SessionTokensValidFrom) {
        $SessionTokensValidFromOutput = (Get-Date $SessionTokensValidFrom -format 'dd-MMM-yyyy HH:mm')
    }

    Switch ($UserMFAStatus.UserPreferredMethodForSecondaryAuthentication) {
        "sms"                    { $PreferredMethod = "SMS" }
        "voice"                  { $PreferredMethod = "Voice call" }
        "mobileAppNotification"  { $PreferredMethod = "Authenticator app notification" }
        "mobileAppCode"          { $PreferredMethod = "Authenticator app code" }
        "email"                  { $PreferredMethod = "Email" }
        "push"                   { $PreferredMethod = "Push notification to device" }
        Default                  { $PreferredMethod = $UserMFAStatus.UserPreferredMethodForSecondaryAuthentication }
    }

    # Security group membership — O(1) lookup from pre-loaded index
    $UserGroups = $GroupMemberIndex[$User.Id.ToString()]
    $SecurityGroupOutput = if ($UserGroups -and $UserGroups.Count -gt 0) { $UserGroups -join ", " } else { $null }

    $DataLine = [PSCustomObject][Ordered]@{
        User                            = $User.displayName
        UserId                          = $User.Id
        UPN                             = $User.userPrincipalName
        UserType                        = $User.userType
        'Employee Type'                 = $User.employeeType
        'Last password change'          = $LastPasswordChangeOutput
        'Days since password change'    = $DaysSincePasswordChange
        'Last successful sign in'       = $LastSuccessfulSignInOutput
        'Last sign in'                  = $LastSignInOutput
        'Days since successful sign in' = $DaysSinceLastSuccessfulSignIn
        'Days since sign in'            = $DaysSinceLastSignIn
        'Session tokens valid from'     = $SessionTokensValidFromOutput
        'Password policies applied'     = $PasswordPoliciesOutput
        'Authentication methods'        = $AuthenticationTypesOutput
        'Admin flag'                    = $UserMFAStatus.isAdmin
        'MFA capable'                   = $UserMFAStatus.IsMfaCapable
        'MFA registered'                = $UserMFAStatus.IsMfaRegistered
        'Preferred MFA method'          = $PreferredMethod
        'Per user MFA state'            = $Data.perUserMfaState
        'Security Group'                = $SecurityGroupOutput
    }
    $Report.Add($DataLine)
}

# Now to generate a HTML report
Write-Host "Generating HTML report..."
[array]$PerUserMFAStates = "enabled", "enforced"
$OrgName = (Get-MgOrganization).DisplayName

$HTMLHead = "<html>
       <style>
       BODY{font-family: Arial; font-size: 8pt;}
       H1{font-size: 22px; font-family: 'Segoe UI Light','Segoe UI','Lucida Grande',Verdana,Arial,Helvetica,sans-serif;}
       H2{font-size: 18px; font-family: 'Segoe UI Light','Segoe UI','Lucida Grande',Verdana,Arial,Helvetica,sans-serif;}
       H3{font-size: 16px; font-family: 'Segoe UI Light','Segoe UI','Lucida Grande',Verdana,Arial,Helvetica,sans-serif;}
       TABLE{border: 1px solid black; border-collapse: collapse; font-size: 8pt;}
       TH{border: 1px solid #969595; background: #dddddd; padding: 5px; color: #000000;}
       TD{border: 1px solid #969595; padding: 5px; }
       td.admin{background: #B7EB83;}
       td.mfacapable{background: #E3242B;}
       td.mfaperuserenabled{background: #FFFF00;}
       td.mfaregistered{background: #FF474C;}
       td.ingroup{background: #7EC8E3;}
       </style>
       <body>
           <div align=center>
           <p><h1>User Password and Authentication Report</h1></p>
           <p><h2><b>For the " + $OrgName + " tenant</b></h2></p>
           <p><h3>Generated: " + $RunDate + "</h3></p></div>"

# Column layout (0-based indices used for conditional formatting below):
#  0 User | 1 UPN | 2 UserType | 3 Employee Type | 4 Last pwd change | 5 Days since pwd change
#  6 Last successful sign in | 7 Days since sign in | 8 Password policies
#  9 Authentication methods | 10 Admin flag | 11 MFA capable | 12 MFA registered
#  13 Preferred MFA method | 14 Per user MFA state | 15 Security Group
$HTMLTable = $Report | Select-Object User, UPN, UserType, 'Employee Type', 'Last password change', 'Days since password change', 'Last successful sign in', 'Days since sign in', 'Password policies applied', `
    'Authentication methods', 'Admin flag', 'MFA capable', 'MFA registered', 'Preferred MFA method', 'Per user MFA state', 'Security Group' | ConvertTo-Html -Fragment
[xml]$XML = $HTMLTable

$TableClass = $XML.CreateAttribute("class")
$TableClass.Value = "State"
$XML.table.Attributes.Append($TableClass) | Out-Null

ForEach ($TableRow in $XML.table.SelectNodes("tr")) {
    $TableRow.SetAttribute("class", "tablerow")
    # Admin flag (col 10)
    If (($TableRow.td) -and ([string]$TableRow.td[10] -eq 'True')) {
        $TableRow.SelectNodes("td")[10].SetAttribute("class", "admin")
    }
    # MFA capable (col 11)
    If (($TableRow.td) -and ([string]$TableRow.td[11] -eq 'True')) {
        $TableRow.SelectNodes("td")[11].SetAttribute("class", "mfacapable")
    }
    # MFA registered (col 12)
    If (($TableRow.td) -and ([string]$TableRow.td[12] -eq 'True')) {
        $TableRow.SelectNodes("td")[12].SetAttribute("class", "mfaregistered")
    }
    # Per-user MFA state (col 14)
    If (($TableRow.td) -and ([string]$TableRow.td[14] -in $PerUserMFAStates)) {
        $TableRow.SelectNodes("td")[14].SetAttribute("class", "mfaperuserenabled")
    }
    # Security Group membership (col 15)
    If (($TableRow.td) -and (-not [string]::IsNullOrWhiteSpace([string]$TableRow.td[15]))) {
        $TableRow.SelectNodes("td")[15].SetAttribute("class", "ingroup")
    }
}
$HTMLBody = [string]::Format('<div class="tablediv">{0}</div>', $XML.OuterXml)

[array]$MFAUsers      = $Report | Where-Object { $_.'MFA Registered' -eq $true }
[array]$AdminUsers    = $Report | Where-Object { $_.'Admin Flag' -eq $true }
[array]$AdminNoMFA    = $AdminUsers | Where-Object { $_.'MFA Registered' -eq $false }
[string]$AdminNoMFANames = $AdminNoMFA.User -Join ", "
[int]$NumberAdminNoMFA   = $AdminNoMFA.Count
[int]$NumberUsersNoMFA   = $Users.Count - $MFAUsers.Count
$PercentMFAUsers = ($NumberUsersNoMFA / $Users.Count).ToString("P")

If ($AdminUsers.Count -eq 0) {
    $PercentMFAAdmins = "N/A"
} Else {
    $PercentMFAAdmins = ($NumberAdminNoMFA / $AdminUsers.Count).ToString("P")
}

[array]$PerUserMFAEnabled  = $Report | Where-Object { $_.'Per user MFA state' -eq 'enabled' }
[array]$PerUserMFAEnforced = $Report | Where-Object { $_.'Per user MFA state' -eq 'enforced' }

# Guest breakdown
[array]$GuestUsers   = $Report | Where-Object { $_.UserType -eq 'Guest' }
[array]$GuestWithMFA = $GuestUsers | Where-Object { $_.'MFA Registered' -eq $true }

# Security group breakdown
[array]$UsersInGroup = $Report | Where-Object { -not [string]::IsNullOrWhiteSpace($_.'Security Group') }
$GroupStats = foreach ($GroupId in $SecurityGroupIds.Keys) {
    $Name = $SecurityGroupIds[$GroupId]
    if ($Name) {
        $Count = ($Report | Where-Object { $_.'Security Group' -like "*$Name*" }).Count
        "  $Name : $Count member(s)"
    }
}

$HTMLTail = "<p>Report created for the " + $OrgName + " tenant on " + $RunDate + "</p>" +
"<p>-----------------------------------------------------------------------------------------------------------------------------</p>" +
"<p>Number of user accounts analyzed:        " + $Users.Count + "</p>" +
"<p>Number of admin accounts found:          " + $AdminUsers.Count + "</p>" +
"<p>Number of accounts registered for MFA:   " + $MFAUsers.Count + "</p>" +
"<p>Number of guest accounts:                " + $GuestUsers.Count + "</p>" +
"<p>Number of guests registered for MFA:     " + $GuestWithMFA.Count + "</p>" +
"<p>Users found in monitored security groups: " + $UsersInGroup.Count + "</p>" +
"<p>" + ($GroupStats -join "<br/>") + "</p>"

If ($PerUserMFAEnabled.Count -gt 0 -or $PerUserMFAEnforced.Count -gt 0) {
    $HTMLTail = $HTMLTail +
    "<p>Number of accounts with per-user MFA enabled:   " + $PerUserMFAEnabled.Count + "</p>" +
    "<p>Names: " + ($PerUserMFAEnabled.User -join ", ") + "</p>" +
    "<p>Number of accounts with per-user MFA enforced:  " + $PerUserMFAEnforced.Count + "</p>" +
    "<p>Names: " + ($PerUserMFAEnforced.User -join ", ") + "</p>"
}

$HTMLTail = $HTMLTail +
"<p>User accounts not registered for MFA:    " + $NumberUsersNoMFA + " (" + $PercentMFAUsers + ")</p>" +
"<p>Admin accounts not registered for MFA:   " + $NumberAdminNoMFA + " (" + $PercentMFAAdmins + ")</p>" +
"<p>Names of admin accounts not registered:  " + $AdminNoMFANames + "</p>" +
"<p>-----------------------------------------------------------------------------------------------------------------------------</p>" +
"<p>Entra ID User Passwords and Authentication Report <b>" + $Version + "</b></p>"

$HTMLReport = $HTMLHead + $HTMLBody + $HTMLTail
$HTMLReport | Out-File $ReportFile -Encoding UTF8

$Report | Export-Csv -NoTypeInformation $CSVOutputFile -Encoding utf8
Write-Host ("HTML format report is available in {0} and CSV file in {1}" -f $ReportFile, $CSVOutputFile)
