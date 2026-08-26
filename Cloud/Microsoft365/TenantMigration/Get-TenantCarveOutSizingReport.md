# Get-TenantCarveOutSizingReport

```
.\Get-TenantCarveOutSizingReport.ps1
.\Get-TenantCarveOutSizingReport.ps1 -Period D90 -OutputFolder C:\Sizing
.\Get-TenantCarveOutSizingReport.ps1 -Period D90 -IncludeOneDrive -OutputFolder C:\Sizing
```

Génère un classeur Excel unique `TenantCarveOutSizing_<horodatage>.xlsx` avec les feuilles :
`Resume`, `Boites`, `Groupes`, `SharePoint` (+ `OneDrive` si `-IncludeOneDrive`).

Nécessite le module `ImportExcel` (proposé à l'installation automatiquement si absent).
