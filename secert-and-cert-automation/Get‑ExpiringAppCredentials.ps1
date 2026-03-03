# ---------------------------------------------------------------
# Prerequisites:
# Install-Module Microsoft.Graph -Scope CurrentUser
# ---------------------------------------------------------------

# Configuration
$tenantId     = "tenantId"
$clientId     = "clientId"
$clientSecret = "clientSecret"
$thresholdDays = 30

# ---------------------------------------------------------------
# Step 1: Authenticate using Client Credentials
# ---------------------------------------------------------------
$secureSecret = ConvertTo-SecureString $clientSecret -AsPlainText -Force
$credential   = New-Object System.Management.Automation.PSCredential($clientId, $secureSecret)

Connect-MgGraph -TenantId $tenantId -ClientSecretCredential $credential -NoWelcome

# ---------------------------------------------------------------
# Step 2: Fetch all Applications and Service Principals
# servicePrincipalType filter ensures only Application type SPs
# are returned — excludes ManagedIdentity, Legacy, SocialIdp
# ---------------------------------------------------------------
$applications = Get-MgApplication `
    -All `
    -Property "id,appId,displayName,passwordCredentials,keyCredentials"

$servicePrincipals = Get-MgServicePrincipal `
    -All `
    -Filter "servicePrincipalType eq 'Application'" `
    -Property "id,appId,displayName,passwordCredentials,keyCredentials"

# ---------------------------------------------------------------
# Step 3: Helper function to evaluate expiry
# ---------------------------------------------------------------
function Evaluate-Credential {
    param (
        [string]$Source,
        [string]$AppName,
        [string]$AppId,
        [string]$CredentialType,
        [string]$DisplayName,
        [string]$KeyId,
        [datetime]$EndDateTime
    )

    $daysRemaining = ($EndDateTime - (Get-Date)).Days

    if ($daysRemaining -lt 0) {
        $status = "EXPIRED"
    } elseif ($daysRemaining -le $thresholdDays) {
        $status = "EXPIRING SOON"
    } else {
        return $null
    }

    return [PSCustomObject]@{
        Status         = $status
        Source         = $Source
        AppName        = $AppName
        AppId          = $AppId
        CredentialType = $CredentialType
        DisplayName    = $DisplayName
        KeyId          = $KeyId
        EndDateTime    = $EndDateTime
        DaysRemaining  = $daysRemaining
    }
}

# ---------------------------------------------------------------
# Step 4: Scan Applications
# ---------------------------------------------------------------
$report = @()

foreach ($app in $applications) {
    foreach ($secret in $app.PasswordCredentials) {
        if ($null -eq $secret.EndDateTime) { continue }
        $result = Evaluate-Credential -Source "Application" -AppName $app.DisplayName `
            -AppId $app.AppId -CredentialType "Secret" -DisplayName $secret.DisplayName `
            -KeyId $secret.KeyId -EndDateTime $secret.EndDateTime
        if ($result) { $report += $result }
    }

    foreach ($cert in $app.KeyCredentials) {
        if ($null -eq $cert.EndDateTime) { continue }
        $result = Evaluate-Credential -Source "Application" -AppName $app.DisplayName `
            -AppId $app.AppId -CredentialType "Certificate" -DisplayName $cert.DisplayName `
            -KeyId $cert.KeyId -EndDateTime $cert.EndDateTime
        if ($result) { $report += $result }
    }
}

# ---------------------------------------------------------------
# Step 5: Scan Service Principals (type: Application only)
# ---------------------------------------------------------------
foreach ($sp in $servicePrincipals) {
    foreach ($secret in $sp.PasswordCredentials) {
        if ($null -eq $secret.EndDateTime) { continue }
        $result = Evaluate-Credential -Source "ServicePrincipal" -AppName $sp.DisplayName `
            -AppId $sp.AppId -CredentialType "Secret" -DisplayName $secret.DisplayName `
            -KeyId $secret.KeyId -EndDateTime $secret.EndDateTime
        if ($result) { $report += $result }
    }

    foreach ($cert in $sp.KeyCredentials) {
        if ($null -eq $cert.EndDateTime) { continue }
        $result = Evaluate-Credential -Source "ServicePrincipal" -AppName $sp.DisplayName `
            -AppId $sp.AppId -CredentialType "Certificate" -DisplayName $cert.DisplayName `
            -KeyId $cert.KeyId -EndDateTime $cert.EndDateTime
        if ($result) { $report += $result }
    }
}

# ---------------------------------------------------------------
# Step 6: Output report
# ---------------------------------------------------------------
if ($report.Count -eq 0) {
    Write-Host "No expiring or expired credentials found." -ForegroundColor Green
} else {
    $sorted = $report | Sort-Object DaysRemaining

    $timestamp  = Get-Date -Format "yyyyMMdd_HHmmss"
    $outputPath = "ExpiryReport_$timestamp.csv"

    try {
        $sorted | Export-Csv -Path $outputPath -NoTypeInformation
        Write-Host "Report exported to: $outputPath" -ForegroundColor Cyan
    } catch {
        Write-Host "Failed to export CSV: $_" -ForegroundColor Red
    }

    # Console output
    $sorted | Format-Table -AutoSize
}

# ---------------------------------------------------------------
# Step 7: Notification hook
# ---------------------------------------------------------------
foreach ($item in $report) {
    Write-Host "[$($item.Status)] [$($item.Source)] $($item.AppName) | $($item.CredentialType): $($item.DisplayName) | Days Remaining: $($item.DaysRemaining)" `
        -ForegroundColor $(if ($item.Status -eq "EXPIRED") { "Red" } else { "Yellow" })
    # TODO: Send email or Teams notification
}

Disconnect-MgGraph