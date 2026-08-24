param(
    [Alias("FilePath")]
    [parameter(Mandatory=$true)][string]$LoadFromFile
)

Begin {
    if (!(Test-Path $LoadFromFile)){Throw "Incorrect Source Path."}
    $GroupsList = Import-CSv -Path $LoadFromFile -Delimiter ";"
    # Connect-MgGraph
}

Process {
    Foreach ($Group in $GroupsList) {
        $OldgroupName = Get-MgGroup -Filter "DisplayName eq '$($Group.OldGroups)'"
        $NewGroupName = Get-MgGroup -Filter "DisplayName eq '$($Group.NewGroups)'"
        $MembersInGroup = Get-MgGroupMember -GroupId $OldgroupName.Id
        Write-Host "Migrating Group: $($Group.OldGroups) to $($Group.NewGroups)" -ForegroundColor Yellow
        
        foreach ($m in $MembersInGroup) 
        { 
            New-MgGroupMember -GroupId $NewGroupName.Id -DirectoryObjectId $m.Id 
        }
    }
}