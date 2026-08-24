<#
    Applique le fond d'écran d'entreprise depuis un Azure Blob Storage.
    Contexte : utilisateur connecté (HKCU). Ne nécessite pas de droits admin.
#>

$BlobUri   = 'https://image.noelshack.com/fichiers/2026/34/5/1787311420-fond-ecran-verrouillage-1440p.jpg'
$LocalPath = "$env:LOCALAPPDATA\Contoso\Wallpaper"
$Style     = 10   # 10 = Remplir, 6 = Ajuster, 2 = Étirer, 22 = Étendre (multi-écrans)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

try {
    $file = Join-Path $LocalPath ([System.IO.Path]::GetFileName(([uri]$BlobUri).LocalPath))
    New-Item -Path $LocalPath -ItemType Directory -Force | Out-Null

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $BlobUri -OutFile $file -UseBasicParsing -TimeoutSec 120

    Set-ItemProperty 'HKCU:\Control Panel\Desktop' -Name Wallpaper      -Value $file
    Set-ItemProperty 'HKCU:\Control Panel\Desktop' -Name WallpaperStyle -Value "$Style"
    Set-ItemProperty 'HKCU:\Control Panel\Desktop' -Name TileWallpaper  -Value '0'

    Add-Type -Namespace Win32 -Name Api -MemberDefinition @'
[DllImport("user32.dll", CharSet = CharSet.Unicode)]
public static extern bool SystemParametersInfo(uint a, uint b, string c, uint d);
'@
    [Win32.Api]::SystemParametersInfo(0x0014, 0, $file, 0x03) | Out-Null

    Write-Output "Fond d'écran appliqué : $file"
    exit 0
}
catch {
    Write-Output "Échec : $($_.Exception.Message)"
    exit 1
}