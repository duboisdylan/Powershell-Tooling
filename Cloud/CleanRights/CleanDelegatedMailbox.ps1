<#
.SYNOPSIS
    Vérifie et purge les droits Exchange délégués d'un compte sur l'ensemble du tenant.

.DESCRIPTION
    Ce script recherche toutes les délégations Exchange (FullAccess, SendAs, SendOnBehalf)
    associées à un compte ou une adresse email cible sur l'ensemble des boîtes aux lettres du tenant.
    Pour chaque délégation trouvée, un prompt interactif permet de supprimer ou conserver le droit.

.PARAMETER TargetEmail
    Adresse email ou UPN du compte à auditer.

.PARAMETER PurgeAll
    Si spécifié, supprime toutes les délégations trouvées sans prompt interactif.

.EXAMPLE
    .\CleanDelegatedMailbox.ps1 -TargetEmail "admin@contoso.com"

.EXAMPLE
    .\CleanDelegatedMailbox.ps1 -TargetEmail "admin@contoso.com" -PurgeAll
#>

[CmdletBinding(SupportsShouldProcess)]
param (
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$TargetEmail,

    [switch]$PurgeAll
)

#region Helpers

function Write-Section {
    param([string]$Title)
    Write-Host "`n$('=' * 70)" -ForegroundColor Cyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host "$('=' * 70)" -ForegroundColor Cyan
}

function Write-Found {
    param([string]$Message)
    Write-Host "[TROUVE] $Message" -ForegroundColor Yellow
}

function Write-Removed {
    param([string]$Message)
    Write-Host "[SUPPRIME] $Message" -ForegroundColor Red
}

function Write-Kept {
    param([string]$Message)
    Write-Host "[CONSERVE] $Message" -ForegroundColor Green
}

function Confirm-Removal {
    param([string]$Description)

    if ($PurgeAll) { return $true }

    Write-Host ""
    $answer = Read-Host "  Supprimer '$Description' ? [O/N] (O=Oui, N=Non, T=Tout supprimer)"
    switch ($answer.ToUpper()) {
        'O' { return $true }
        'T' {
            $script:PurgeAll = $true
            return $true
        }
        default { return $false }
    }
}

#endregion

#region Connection check

Write-Section "Vérification de la connexion Exchange Online"

try {
    $null = Get-OrganizationConfig -ErrorAction Stop
    Write-Host "[OK] Connexion Exchange Online active." -ForegroundColor Green
}
catch {
    Write-Host "[INFO] Connexion Exchange Online absente. Tentative de connexion..." -ForegroundColor Yellow
    try {
        Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
        Write-Host "[OK] Connexion Exchange Online établie." -ForegroundColor Green
    }
    catch {
        Write-Error "Impossible de se connecter à Exchange Online : $_"
        exit 1
    }
}

#endregion

#region Resolve target

Write-Section "Résolution du compte cible : $TargetEmail"

try {
    $targetRecipient = Get-Recipient -Identity $TargetEmail -ErrorAction Stop
    Write-Host "[OK] Compte trouvé : $($targetRecipient.DisplayName) <$($targetRecipient.PrimarySmtpAddress)>" -ForegroundColor Green
    $targetIdentity = $targetRecipient.PrimarySmtpAddress.ToString()
}
catch {
    Write-Error "Le compte '$TargetEmail' est introuvable dans le tenant."
    exit 1
}

#endregion

#region Collect all mailboxes

Write-Section "Récupération de toutes les boîtes aux lettres du tenant"
Write-Host "Cette opération peut prendre plusieurs minutes selon la taille du tenant..." -ForegroundColor Gray

$allMailboxes = Get-Mailbox -ResultSize Unlimited -RecipientTypeDetails UserMailbox, SharedMailbox, RoomMailbox, EquipmentMailbox |
    Where-Object { $_.PrimarySmtpAddress -ne $targetIdentity }

Write-Host "[OK] $($allMailboxes.Count) boîtes aux lettres récupérées." -ForegroundColor Green

#endregion

#region Audit counters

$stats = @{
    FullAccess    = @{ Found = 0; Removed = 0 }
    SendAs        = @{ Found = 0; Removed = 0 }
    SendOnBehalf  = @{ Found = 0; Removed = 0 }
}

#endregion

#region FullAccess audit

Write-Section "Audit FullAccess"

foreach ($mbx in $allMailboxes) {
    $permissions = Get-MailboxPermission -Identity $mbx.Identity -User $targetIdentity -ErrorAction SilentlyContinue |
        Where-Object { $_.AccessRights -contains 'FullAccess' -and -not $_.Deny }

    foreach ($perm in $permissions) {
        $stats.FullAccess.Found++
        $desc = "FullAccess | $($mbx.PrimarySmtpAddress)"
        Write-Found $desc

        if (Confirm-Removal -Description $desc) {
            if ($PSCmdlet.ShouldProcess($mbx.Identity, "Remove-MailboxPermission FullAccess pour $targetIdentity")) {
                Remove-MailboxPermission -Identity $mbx.Identity -User $targetIdentity -AccessRights FullAccess -Confirm:$false -ErrorAction SilentlyContinue
                $stats.FullAccess.Removed++
                Write-Removed $desc
            }
        }
        else {
            Write-Kept $desc
        }
    }
}

if ($stats.FullAccess.Found -eq 0) {
    Write-Host "[OK] Aucune délégation FullAccess trouvée." -ForegroundColor Green
}

#endregion

#region SendAs audit

Write-Section "Audit SendAs"

foreach ($mbx in $allMailboxes) {
    $permissions = Get-RecipientPermission -Identity $mbx.Identity -Trustee $targetIdentity -AccessRights SendAs -ErrorAction SilentlyContinue

    foreach ($perm in $permissions) {
        $stats.SendAs.Found++
        $desc = "SendAs | $($mbx.PrimarySmtpAddress)"
        Write-Found $desc

        if (Confirm-Removal -Description $desc) {
            if ($PSCmdlet.ShouldProcess($mbx.Identity, "Remove-RecipientPermission SendAs pour $targetIdentity")) {
                Remove-RecipientPermission -Identity $mbx.Identity -Trustee $targetIdentity -AccessRights SendAs -Confirm:$false -ErrorAction SilentlyContinue
                $stats.SendAs.Removed++
                Write-Removed $desc
            }
        }
        else {
            Write-Kept $desc
        }
    }
}

if ($stats.SendAs.Found -eq 0) {
    Write-Host "[OK] Aucune délégation SendAs trouvée." -ForegroundColor Green
}

#endregion

#region SendOnBehalf audit

Write-Section "Audit SendOnBehalf"

foreach ($mbx in $allMailboxes) {
    $grantedList = $mbx.GrantSendOnBehalfTo

    if ($grantedList -and $grantedList.Count -gt 0) {
        $match = $grantedList | Where-Object {
            (Get-Recipient $_ -ErrorAction SilentlyContinue).PrimarySmtpAddress -eq $targetIdentity
        }

        foreach ($entry in $match) {
            $stats.SendOnBehalf.Found++
            $desc = "SendOnBehalf | $($mbx.PrimarySmtpAddress)"
            Write-Found $desc

            if (Confirm-Removal -Description $desc) {
                if ($PSCmdlet.ShouldProcess($mbx.Identity, "Remove SendOnBehalf pour $targetIdentity")) {
                    $newList = $grantedList | Where-Object { $_ -ne $entry }
                    Set-Mailbox -Identity $mbx.Identity -GrantSendOnBehalfTo $newList -ErrorAction SilentlyContinue
                    $stats.SendOnBehalf.Removed++
                    Write-Removed $desc
                }
            }
            else {
                Write-Kept $desc
            }
        }
    }
}

if ($stats.SendOnBehalf.Found -eq 0) {
    Write-Host "[OK] Aucune délégation SendOnBehalf trouvée." -ForegroundColor Green
}

#endregion

#region Summary

Write-Section "Résumé de l'audit pour $targetIdentity"

$table = @(
    [PSCustomObject]@{ Type = 'FullAccess';   Trouvées = $stats.FullAccess.Found;   Supprimées = $stats.FullAccess.Removed;   Conservées = $stats.FullAccess.Found - $stats.FullAccess.Removed }
    [PSCustomObject]@{ Type = 'SendAs';       Trouvées = $stats.SendAs.Found;       Supprimées = $stats.SendAs.Removed;       Conservées = $stats.SendAs.Found - $stats.SendAs.Removed }
    [PSCustomObject]@{ Type = 'SendOnBehalf'; Trouvées = $stats.SendOnBehalf.Found; Supprimées = $stats.SendOnBehalf.Removed; Conservées = $stats.SendOnBehalf.Found - $stats.SendOnBehalf.Removed }
)

$table | Format-Table -AutoSize

$totalFound   = $stats.FullAccess.Found   + $stats.SendAs.Found   + $stats.SendOnBehalf.Found
$totalRemoved = $stats.FullAccess.Removed + $stats.SendAs.Removed + $stats.SendOnBehalf.Removed

Write-Host "Total délégations trouvées  : $totalFound" -ForegroundColor Cyan
Write-Host "Total délégations supprimées: $totalRemoved" -ForegroundColor Red
Write-Host "Total délégations conservées: $($totalFound - $totalRemoved)" -ForegroundColor Green

#endregion
