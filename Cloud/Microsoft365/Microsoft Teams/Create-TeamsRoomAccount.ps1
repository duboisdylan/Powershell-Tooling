param(
    [Alias("FilePath")]
    [parameter(Mandatory=$true)][string]$LoadFromFile
)

Begin {
    # Vérification du path.
    if (!(Test-Path $LoadFromFile)){Throw "Incorrect Source Path."}
    $TeamsRoomList = Import-CSV -Path $LoadFromFile -Delimiter ";"

    # Connexion aux services MS.
    Connect-ExchangeOnline
    Connect-MgGraph -Scopes "User.ReadWrite.All", "Directory.ReadWrite.All", "Organization.Read.All"

    # Fonction permettant la génération aléatoirement des mots de passe.
    function New-RandomPassword {
        param (
            [int]$Length = 12
        )
        $upper = Get-Random -Count 2 -InputObject ([char[]]([char]'A'..[char]'Z'))
        $lower = Get-Random -Count 4 -InputObject ([char[]]([char]'a'..[char]'z'))
        $digit = Get-Random -Count 2 -InputObject ([char[]]([char]'0'..[char]'9'))
        $special = Get-Random -Count 2 -InputObject ('!', '@', '#', '$', '%', '^', '&', '*')
        $rest = Get-Random -Count ($Length - 10) -InputObject ([char[]]([char]'A'..[char]'Z') + [char[]]([char]'a'..[char]'z') + [char[]]([char]'0'..[char]'9') + '!@#$%^&*')
        $passwordChars = $upper + $lower + $digit + $special + $rest
        -join ($passwordChars | Sort-Object {Get-Random})
    }
}

Process {
    Foreach ($TeamsRoom in $TeamsRoomList) {
        if ($null -ne (Get-Mailbox -Identity $($TeamsRoom.UPN)))
        {
            Write-Host "$($TeamsRoom.UPN) - Already exist"
        }
        Else {
            # Génération du mot de passe.
            $PasswordTemp = New-RandomPassword -Length "20"
            $PasswordSecure = ConvertTo-SecureString $PasswordTemp -AsPlainText -Force

            $UserExchange = New-Mailbox -Name $TeamsRoom.DisplayName -Alias $TeamsRoom.RoomAlias -EnableRoomMailboxAccount $true -RoomMailboxPassword $PasswordSecure -Room
            Start-Sleep -Seconds 10

            $UserMGGraph = Get-MgUser -UserId $UserExchange.UserPrincipalName
            Update-MgUser -UserId $UserMGGraph.Id -UserPrincipalName $TeamsRoom.UPN
            New-MgGroupMember -GroupId $TeamsRoom.SecurityGroup -DirectoryObjectId $UserMGGraph.Id
            Start-Sleep -Seconds 30

            Set-CalendarProcessing -Identity $TeamsRoom.UPN `
                -AutomateProcessing AutoAccept `
                -AllowConflicts $false `
                -BookingWindowInDays 180 `
                -MaximumDurationInMinutes 720 `
                -AllowRecurringMeetings $true `
                -EnforceSchedulingHorizon $true `
                -ScheduleOnlyDuringWorkHours $true `
                -DeleteSubject $false `
                -AddOrganizerToSubject $true `
                -RemovePrivateProperty $false
            }
        Write-Host "$($TeamsRoom.UPN)`t $($PasswordTemp) "
        }
}