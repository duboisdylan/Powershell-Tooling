# This script adds a password credential to an Azure AD application using Microsoft Graph PowerShell SDK.
param (
    [Parameter(Mandatory = $true)]
    [string]$ApplicationId
)

Begin {
    Connect-MgGraph -Scopes "Application.ReadWrite.All" -ErrorAction Stop
    Import-Module Microsoft.Graph.Applications
}

Process {
    # Check if the application exists
    $app = Get-MgApplication -ApplicationId $applicationId -ErrorAction SilentlyContinue
    if (-not $app) {
        Write-Host "Application with ID '$applicationId' not found." -ForegroundColor Red
    }

    $Date5years = (Get-Date).AddYears(5)
    
    $params = @{
        displayName = "Password friendly name"
        endDateTime = $Date5years
    }

    Add-MgApplicationPassword -ApplicationId $applicationId -BodyParameter $params

}



