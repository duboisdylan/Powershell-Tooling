$publicGroups = Get-MgGroup -All `
    -Filter "groupTypes/any(c:c eq 'Unified')" `
    -Property Id,DisplayName,Mail,Visibility,GroupTypes,ResourceProvisioningOptions,CreatedDateTime |
    Where-Object { $_.Visibility -eq 'Public' }

$publicGroups |
    Select-Object DisplayName, Mail, Visibility,
        @{N='IsTeam';E={ $_.AdditionalProperties.resourceProvisioningOptions -contains 'Team' }},
        CreatedDateTime, Id |
    Sort-Object DisplayName |
    Format-Table -AutoSize