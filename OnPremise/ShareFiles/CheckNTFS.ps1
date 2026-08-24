<#
.SYNOPSIS
    Audit NTFS récursif avec vérification des ownership
    Détecte tous les droits écriture (hérités + explicites) et les owners inhabituels
.NOTES
    À exécuter en tant qu'administrateur local sur le serveur de fichiers
#>

# ─── PARAMETRES ───────────────────────────────────────────────────────────────
$RootPath  = "D:\FS\Toto"
$MaxDepth  = 10
$OutputCsv = "C:\Logs\audit_ntfs_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"

# Droits considérés comme "écriture"
$WriteRights = @(
    "FullControl", "Modify", "Write", "WriteData", "AppendData",
    "CreateFiles", "CreateDirectories", "WriteAttributes", "WriteExtendedAttributes"
)

# Identités système à exclure des ACL
$ExcludedIdentities = @(
    "NT AUTHORITY\SYSTEM",
    "NT AUTHORITY\Authenticated Users",
    "BUILTIN\Administrators",
    "CREATOR OWNER"
)

# Owners considérés comme normaux
$ExpectedOwners = @(
    "BUILTIN\Administrators",
    "NT AUTHORITY\SYSTEM"
)

# ─── FONCTIONS ────────────────────────────────────────────────────────────────
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$timestamp] [$Level] $Message"
    Write-Host $line -ForegroundColor $(switch ($Level) {
        "OK"    { "Green"  }
        "WARN"  { "Yellow" }
        "ERR"   { "Red"    }
        default { "Cyan"   }
    })
}

function Get-FolderDepth {
    param([string]$Path, [string]$Root)
    $relative = $Path.Replace($Root, "").TrimStart("\")
    return ($relative -split "\\").Count
}

function Audit-NTFSFolder {
    param([string]$Path, [int]$Depth)

    $entries = @()
    try {
        $acl   = Get-Acl -Path $Path -ErrorAction Stop
        $owner = $acl.Owner

        # Vérification de l'owner
        $ownerFlag = if ($ExpectedOwners | Where-Object { $owner -match [regex]::Escape($_) }) {
            "OK"
        } else {
            Write-Log "  ⚠ Owner inhabituel : $owner  →  $Path" "WARN"
            "Owner inhabituel"
        }

        foreach ($ace in $acl.Access) {
            # Filtrer les Deny et identités système
            if ($ace.AccessControlType -eq "Deny") { continue }
            $identity = $ace.IdentityReference.ToString()
            if ($ExcludedIdentities | Where-Object { $identity -match [regex]::Escape($_) }) { continue }

            $rights   = $ace.FileSystemRights.ToString() -split ", "
            $hasWrite = $rights | Where-Object { $WriteRights -contains $_ }
            $statut   = if ($hasWrite) { "Ecriture détectée" } else { "Lecture seule" }
            $heritage = if ($ace.IsInherited) { "Hérité" } else { "Explicite" }

            if ($hasWrite) {
                Write-Log "  ⚠ [$heritage] $identity → $($ace.FileSystemRights)" "WARN"
            }

            $entries += [PSCustomObject]@{
                Profondeur   = $Depth
                Dossier      = $Path
                Owner        = $owner
                StatutOwner  = $ownerFlag
                Identite     = $identity
                Droits       = $ace.FileSystemRights.ToString()
                Heritage     = $heritage
                TypeControle = $ace.AccessControlType.ToString()
                Statut       = $statut
            }
        }

        # Si aucune ACE après filtrage, on remonte quand même l'owner
        if ($entries.Count -eq 0) {
            $entries += [PSCustomObject]@{
                Profondeur   = $Depth
                Dossier      = $Path
                Owner        = $owner
                StatutOwner  = $ownerFlag
                Identite     = "Aucun (filtré)"
                Droits       = "N/A"
                Heritage     = "N/A"
                TypeControle = "N/A"
                Statut       = "Lecture seule"
            }
        }

    } catch {
        Write-Log "Impossible de lire les ACL : $Path → $_" "ERR"
        $entries += [PSCustomObject]@{
            Profondeur   = $Depth
            Dossier      = $Path
            Owner        = "ERREUR"
            StatutOwner  = "Erreur"
            Identite     = "ERREUR"
            Droits       = "Accès refusé"
            Heritage     = "N/A"
            TypeControle = "N/A"
            Statut       = "Erreur lecture ACL"
        }
    }
    return $entries
}

# ─── VÉRIFICATION DU CHEMIN RACINE ────────────────────────────────────────────
if (-not (Test-Path $RootPath)) {
    Write-Log "Chemin introuvable : $RootPath" "ERR"
    exit 1
}

# ─── COLLECTE DES DOSSIERS ────────────────────────────────────────────────────
Write-Log "Scan de : $RootPath (profondeur max : $MaxDepth niveaux)"

$foldersToScan = @($RootPath)
$subFolders = Get-ChildItem -Path $RootPath -Recurse -Directory -ErrorAction SilentlyContinue |
    Where-Object {
        $depth = Get-FolderDepth -Path $_.FullName -Root $RootPath
        $depth -le $MaxDepth
    }

$foldersToScan += $subFolders.FullName
Write-Log "$($foldersToScan.Count) dossier(s) à analyser." "OK"

# ─── AUDIT ────────────────────────────────────────────────────────────────────
$results = @()

foreach ($folder in $foldersToScan) {
    $depth  = if ($folder -eq $RootPath) { 0 } else { Get-FolderDepth -Path $folder -Root $RootPath }
    $indent = "  " * $depth
    Write-Log "${indent}Analyse [Niveau $depth] : $folder"
    $results += Audit-NTFSFolder -Path $folder -Depth $depth
}

# ─── EXPORT CSV ───────────────────────────────────────────────────────────────
$results | Sort-Object Profondeur, Dossier, Statut |
    Export-Csv -Path $OutputCsv -NoTypeInformation -Encoding UTF8
Write-Log "CSV exporté : $OutputCsv" "OK"

# ─── RÉSUMÉ ───────────────────────────────────────────────────────────────────
$nbEcriture     = ($results | Where-Object { $_.Statut -eq "Ecriture détectée" }       | Select-Object -ExpandProperty Dossier -Unique).Count
$nbOk           = ($results | Where-Object { $_.Statut -eq "Lecture seule" }            | Select-Object -ExpandProperty Dossier -Unique).Count
$nbErreur       = ($results | Where-Object { $_.Statut -eq "Erreur lecture ACL" }).Count
$nbExplicite    = ($results | Where-Object { $_.Heritage -eq "Explicite" }).Count
$nbOwnerAnormal = ($results | Where-Object { $_.StatutOwner -eq "Owner inhabituel" }    | Select-Object -ExpandProperty Dossier -Unique).Count

Write-Log "─────────────────────────────────────────────────"
Write-Log "RÉSUMÉ"
Write-Log "  ✔ Dossiers sans écriture              : $nbOk" "OK"
Write-Log "  ⚠ Dossiers avec accès écriture        : $nbEcriture" "WARN"
Write-Log "  ✎ Entrées ACL explicites (non héritées): $nbExplicite" "WARN"
Write-Log "  ⚠ Dossiers avec owner inhabituel      : $nbOwnerAnormal" "WARN"
Write-Log "  ✖ Erreurs de lecture ACL              : $nbErreur" "ERR"
Write-Log "─────────────────────────────────────────────────"
Write-Log "Rapport complet : $OutputCsv" "OK"