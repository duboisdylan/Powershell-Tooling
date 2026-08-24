#Requires -Version 5.1

# ============================================================
#  Script : Send-TestMail.ps1
#  Description : Envoie un e-mail de test via un serveur SMTP
# ============================================================

# --- Paramètres à adapter ---
$SmtpServer   = ""
$SmtpPort     = "2525"                        # 25 (non chiffré), 465 (SSL implicite), 587 (STARTTLS)
$UseSsl       = $true
$From         = ""
$To           = ""
$Subject      = "Mail de test PowerShell"
$Body         = "Ceci est un e-mail de test envoyé depuis un script PowerShell."
$IsBodyHtml   = $false                     # $true si le body est en HTML

# --- Authentification (laisser vide si le serveur n'en requiert pas) ---
$Username     = ""
$Password     = 
$SecurePassword = ConvertTo-SecureString $Password -AsPlainText -Force
$Credential    = New-Object System.Management.Automation.PSCredential($Username, $SecurePassword)

# --- Construction et envoi du message ---
$MailParams = @{
    From       = $From
    To         = $To
    Subject    = $Subject
    Body       = $Body
    SmtpServer = $SmtpServer
    Port       = $SmtpPort
    Credential = $Credential
    UseSsl     = $UseSsl
    BodyAsHtml = $IsBodyHtml
    Encoding   = [System.Text.Encoding]::UTF8
}

# Ajouter des destinataires CC / BCC si nécessaire :
# $MailParams.Cc  = "copie@example.com"
# $MailParams.Bcc = "copie-cachee@example.com"

# Ajouter une pièce jointe si nécessaire :
# $MailParams.Attachments = "C:\chemin\vers\fichier.pdf"

try {
    Send-MailMessage @MailParams -ErrorAction Stop
    Write-Host "✅ E-mail envoyé avec succès à $To" -ForegroundColor Green
}
catch {
    Write-Host "❌ Échec de l'envoi : $_" -ForegroundColor Red
}