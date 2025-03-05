# Ensure required modules are available
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Host "Active Directory module is not installed. Please install RSAT-AD-PowerShell." -ForegroundColor Red
    exit
}

if (-not (Get-Module -ListAvailable -Name Microsoft.Graph)) {
    Write-Host "Microsoft Graph module is not installed. Installing now..." -ForegroundColor Yellow
    Install-Module Microsoft.Graph -Scope CurrentUser -Force
}

# Function to check if a user is a member of a group
function Check-Membership($userEmail, $groupName) {
    $isMemberOnPrem = $false
    $isMemberAzure = $false

    # Check in On-Prem AD
    $user = Get-ADUser -Filter {UserPrincipalName -eq $userEmail} -Properties MemberOf
    if ($user) {
        $group = Get-ADGroup -Filter {Name -eq $groupName}
        if ($group) {
            $isMember = Get-ADGroupMember -Identity $group | Where-Object { $_.DistinguishedName -eq $user.DistinguishedName }
            if ($isMember) { $isMemberOnPrem = $true }
        }
    }

    # Check in Azure AD
    try {
        Connect-MgGraph -Scopes "User.Read.All", "GroupMember.Read.All" -ErrorAction Stop | Out-Null
        $userAzure = Get-MgUser -Filter "userPrincipalName eq '$userEmail'"
        $groupAzure = Get-MgGroup -Filter "displayName eq '$groupName'"
        if ($userAzure -and $groupAzure) {
            $isMemberAzure = (Get-MgGroupMember -GroupId $groupAzure.Id | Where-Object { $_.Id -eq $userAzure.Id }) -ne $null
        }
    } catch {
        Write-Host "⚠️ Could not connect to Microsoft Graph. Ensure you have the correct permissions." -ForegroundColor Red
    }

    return @{
        OnPrem  = $isMemberOnPrem
        AzureAD = $isMemberAzure
    }
}

# Ask user to choose an option
Write-Host "Select an option:" -ForegroundColor Cyan
Write-Host "1. Check a single user"
Write-Host "2. Check multiple users via CSV import"
$choice = Read-Host "Enter 1 or 2"

if ($choice -eq "1") {
    # Prompt for the username and domain
    $upnUsername = Read-Host "Enter the username (UPN without domain, e.g., 'jdoe')"
    $domain = Read-Host "Enter the domain (e.g., 'test.com')"
    $groupName = Read-Host "Enter the group name (e.g., 'Service Accounts')"

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

} elseif ($choice -eq "2") {
    # Prompt for CSV file path
    $csvPath = Read-Host "Enter the full path to the CSV file (e.g., 'C:\Users\Administrator\users.csv')"
    if (-not (Test-Path $csvPath)) {
        Write-Host "⚠️ File not found. Please check the path and try again." -ForegroundColor Red
        exit
    }

    # Prompt for domain and group name
    $domain = Read-Host "Enter the domain (e.g., 'test.com')"
    $groupName = Read-Host "Enter the group name (e.g., 'Service Accounts')"

    # Read CSV
    $users = Import-Csv -Path $csvPath
    if (-not $users) {
        Write-Host "⚠️ No data found in the CSV file. Please check the file format." -ForegroundColor Red
        exit
    }

    # Process each user
    $results = @()
    foreach ($row in $users) {
        $upnUsername = $row.PSObject.Properties.Value[0]  # Read first column
        $userEmail = "$upnUsername@$domain"

        Write-Host "Checking $userEmail..." -ForegroundColor Cyan
        $result = Check-Membership -userEmail $userEmail -groupName $groupName
        $isMember = if ($result.OnPrem -or $result.AzureAD) { "TRUE" } else { "FALSE" }

        # Store result
        $results += [PSCustomObject]@{
            Username         = $upnUsername
            GroupMembership  = $isMember
        }
    }

    # Export results
    $outputPath = $csvPath -replace "\.csv$", "-Results.csv"
    $results | Export-Csv -Path $outputPath -NoTypeInformation
    Write-Host "`n✅ CSV export complete! Results saved to: $outputPath" -ForegroundColor Green

} else {
    Write-Host "⚠️ Invalid selection. Please restart the script and enter 1 or 2." -ForegroundColor Red
    exit
}

Write-Host "`nCheck complete!" -ForegroundColor Cyan
