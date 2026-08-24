Connect-MgGraph -Scopes "Group.Read.All", "GroupMember.Read.All"

$groupNames = @(
"SG-TOTO",
"SG-TOTO-2"
)

$results = foreach ($groupName in $groupNames) {
    $group = Get-MgGroup -Filter "displayName eq '$groupName'" -ConsistencyLevel eventual
    if (-not $group) { Write-Warning "Introuvable : $groupName"; continue }

    Get-MgGroupMember -GroupId $group.Id -All |
        Where-Object { $_.AdditionalProperties["@odata.type"] -eq "#microsoft.graph.user" } |
        ForEach-Object {
            [PSCustomObject]@{
                UPN    = $_.AdditionalProperties["userPrincipalName"]
                Groupe = $groupName
            }
        }
}

$results