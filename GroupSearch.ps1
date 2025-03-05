# Ensure required modules are available
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Host "Active Directory module is not installed. Please install RSAT-AD-PowerShell." -ForegroundColor Red
    exit
}

if (-not (Get-Module -ListAvailable -Name Microsoft.Graph)) {
    Write-Host "Microsoft Graph module is not installed. Installing now..." -ForegroundColor Yellow
    try {
        Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted
        Install-Module Microsoft.Graph -Scope CurrentUser -Force
    } catch {
        Write-Host "⚠️ Unable to install Microsoft Graph module. Please install it manually." -ForegroundColor Red
        exit
    }
}

# Function to check if a user and group exist in both AD and Azure AD
function Verify-UserAndGroup($userEmail, $groupName) {
    $existsOnPrem = $false
    $existsAzure = $false

    # Check in On-Prem AD
    $user = Get-ADUser -Filter {UserPrincipalName -eq $userEmail} -Properties MemberOf
    $group = Get-ADGroup -Filter {Name -eq $groupName}

    if ($user -and $group) {
        $existsOnPrem = $true
    }

    # Check in Azure AD
    try {
        Connect-MgGraph -Scopes "User.Read.All", "GroupMember.Read.All" -ErrorAction Stop | Out-Null
    } catch {
        Write-Host "❌ Could not connect to Microsoft Graph. Ensure you have the correct permissions." -ForegroundColor Red
        Write-Host "Diagnostic Information:" -ForegroundColor Yellow
        Write-Host "Error Message: $($_.Exception.Message)" -ForegroundColor Yellow
        exit
    }

    $userAzure = Get-MgUser -Filter "userPrincipalName eq '$userEmail'"
    $groupAzure = Get-MgGroup -Filter "displayName eq '$groupName'"

    if ($userAzure -and $groupAzure) {
        $existsAzure = $true
    }

    return @{
        OnPrem  = $existsOnPrem
        AzureAD = $existsAzure
    }
}

# Function to check if a user is a member of a group
function Check-Membership($userEmail, $groupName) {
    $isMemberOnPrem = $false
    $isMemberAzure = $false

    # Check in On-Prem AD
    $user = Get-ADUser -Filter {UserPrincipalName -eq $userEmail} -Properties MemberOf
    $group = Get-ADGroup -Filter {Name -eq $groupName}
    if ($user -and $group) {
        $isMember = Get-ADGroupMember -Identity $group | Where-Object { $_.DistinguishedName -eq $user.DistinguishedName }
        if ($isMember) { $isMemberOnPrem = $true }
    }

    # Check in Azure AD
    $userAzure = Get-MgUser -Filter "userPrincipalName eq '$userEmail'"
    $groupAzure = Get-MgGroup -Filter "displayName eq '$groupName'"
    if ($userAzure -and $groupAzure) {
        $isMemberAzure = (Get-MgGroupMember -GroupId $groupAzure.Id | Where-Object { $_.Id -eq $userAzure.Id }) -ne $null
    }

    return @{
        OnPrem  = $isMemberOnPrem
        AzureAD = $isMemberAzure
    }
}

# Main menu loop
do {
    # Prompt for user input
    if (-not $upnUsername) { $upnUsername = Read-Host "Enter the username (UPN without domain, e.g., 'jdoe')" }
    if (-not $domain) { $domain = Read-Host "Enter the domain (e.g., 'test.com')" }
    if (-not $groupName) { $groupName = Read-Host "Enter the group name (e.g., 'Service Accounts')" }

    # Construct the full UPN
    $userEmail = "$upnUsername@$domain"

    # Confirm input with the user
    Write-Host "`nYou entered the following details:" -ForegroundColor Cyan
    Write-Host "Username (UPN): $userEmail" -ForegroundColor Yellow
    Write-Host "Group Name: $groupName" -ForegroundColor Yellow
    $confirmation = Read-Host "Is this correct? (Y/N)"
    if ($confirmation -notmatch "^[Yy]$") {
        Write-Host "Exiting script. Please restart and enter correct details." -ForegroundColor Red
        exit
    }

    # Verify that both the user and group exist
    $verification = Verify-UserAndGroup -userEmail $userEmail -groupName $groupName
    if (-not $verification.OnPrem) {
        Write-Host "⚠️ User or group does not exist in On-Prem Active Directory." -ForegroundColor Red
    }
    if (-not $verification.AzureAD) {
        Write-Host "⚠️ User or group does not exist in Azure AD." -ForegroundColor Red
    }
    if (-not $verification.OnPrem -and -not $verification.AzureAD) {
        Write-Host "❌ The user or group does not exist in either directory. Exiting." -ForegroundColor Red
        exit
    }

    # Check group membership
    $result = Check-Membership -userEmail $userEmail -groupName $groupName

    # Display results
    Write-Host "`nChecking membership in On-Prem Active Directory..." -ForegroundColor Cyan
    if ($result.OnPrem) {
        Write-Host "✅ User '$userEmail' IS a member of '$groupName' in On-Prem Active Directory." -ForegroundColor Green
    } else {
        Write-Host "❌ User '$userEmail' is NOT a member of '$groupName' in On-Prem Active Directory." -ForegroundColor Yellow
    }

    Write-Host "`nChecking membership in Azure AD (O365)..." -ForegroundColor Cyan
    if ($result.AzureAD) {
        Write-Host "✅ User '$userEmail' IS a member of '$groupName' in Azure AD (O365)." -ForegroundColor Green
    } else {
        Write-Host "❌ User '$userEmail' is NOT a member of '$groupName' in Azure AD (O365)." -ForegroundColor Yellow
    }

    # Ask the user what they want to do next
    Write-Host "`nWhat would you like to do next?" -ForegroundColor Cyan
    Write-Host "1. Run a brand new search"
    Write-Host "2. Run a new search for the same user in the same domain but a different group"
    Write-Host "3. Run a new search for a different user in the same group"
    Write-Host "4. Run a new search for a different user in a different domain but the same group"
    Write-Host "5. Exit"

    $nextAction = Read-Host "Enter a choice (1-5)"

    switch ($nextAction) {
        "1" { $upnUsername = $null; $domain = $null; $groupName = $null; continue }
        "2" { $groupName = Read-Host "Enter the new group name"; continue }
        "3" { $upnUsername = Read-Host "Enter the new username"; continue }
        "4" { $domain = Read-Host "Enter the new domain"; continue }
        "5" { break }
        default { Write-Host "Invalid choice, exiting." -ForegroundColor Red; break }
    }
} while ($true)

Write-Host "`nCheck complete!" -ForegroundColor Cyan
