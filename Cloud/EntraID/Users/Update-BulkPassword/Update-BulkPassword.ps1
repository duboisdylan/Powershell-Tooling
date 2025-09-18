param(
    [Alias("FilePath")]
    [parameter(Mandatory=$true)][string]$LoadFromFile
)


Begin {
    # Vérification du path.
    if (!(Test-Path $LoadFromFile)){Throw "Incorrect Source Path."}

    $Users = Get-Content -Path $LoadFromFile

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

    # Connect-MgGraph -Scopes "User.ReadWrite.All"
}

Process
{
    Foreach ($User in $Users)
    {
        $NewPassword = New-RandomPassword -Length "20"
        $NewPasswordSecured = ConvertTo-SecureString $NewPassword -AsPlainText -Force
        # Changer le mot de passe

        Update-MgUser -Verbose -UserId $User -PasswordProfile @{
            password = $NewPassword ;
            forceChangePasswordNextSignIn = $false
        }
        Write-Host "$USer - $NewPassword"
    }
}