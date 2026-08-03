<#
.SYNOPSIS
    0-domain_baseline.ps1 - Active Directory Security Baseline Reconnaissance Script for MedDefense

.DESCRIPTION
    Maps the entire MedDefense Active Directory environment from a security perspective,
    capturing domain info, users, groups, service accounts, GPOs, password/lockout policies,
    Kerberos settings, and privileged accounts. Outputs a structured security baseline report
    with a findings summary categorized by severity.

.PURPOSE
    Purpose: Establish a security baseline and map the Active Directory environment,
    the Windows domain equivalent of the Lynis baseline scan (2x00 Task 0).

.NOTES
	Author: Hafidh Juma
    Requires: RSAT ActiveDirectory (+ optionally GroupPolicy) modules, domain-read privileges.
    Every enumeration step is wrapped in error handling so a single inaccessible object
    (missing OU, unreachable DC, missing module) degrades gracefully instead of aborting.
#>

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$findings = @()

function Add-Finding {
    param(
        [ValidateSet('Critical', 'High', 'Medium', 'Low')][string]$Severity,
        [string]$Description
    )
    $script:findings += [PSCustomObject]@{ Severity = $Severity; Description = $Description }
}

Write-Host "[-] Starting MedDefense Active Directory Domain Reconnaissance..." -ForegroundColor Cyan

# --- Prerequisite modules ---
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Error "The ActiveDirectory PowerShell module is required but not installed."
    exit 1
}
Import-Module ActiveDirectory -ErrorAction Stop

$gpoModuleAvailable = [bool](Get-Module -ListAvailable -Name GroupPolicy)
if (-not $gpoModuleAvailable) {
    Write-Warning "GroupPolicy module not found; GPO enumeration will fall back to a conservative default."
}

# 1. Domain / Forest / DC information
try {
    $domain      = Get-ADDomain -ErrorAction Stop
    $domainName  = $domain.DNSRoot
    $forest      = Get-ADForest -ErrorAction Stop
    $forestLevel = $forest.ForestMode
    $dcs         = (Get-ADDomainController -Filter * -ErrorAction Stop).HostName
}
catch {
    Write-Warning "Failed to retrieve domain/forest info: $($_.Exception.Message)"
    $domainName = "UNKNOWN"; $forestLevel = "UNKNOWN"; $dcs = @()
    Add-Finding -Severity High -Description "Unable to enumerate domain/forest/DC information."
}

# 2. User accounts
try {
    $allUsers = Get-ADUser -Filter * -Properties Enabled, LastLogonDate, PasswordLastSet, PasswordNeverExpires -ErrorAction Stop
    $totalUsers      = $allUsers.Count
    $disabledUsers   = ($allUsers | Where-Object { -not $_.Enabled }).Count
    $pwdNeverExpires = ($allUsers | Where-Object { $_.PasswordNeverExpires }).Count
}
catch {
    Write-Warning "Failed to enumerate user accounts: $($_.Exception.Message)"
    $allUsers = @(); $totalUsers = 0; $disabledUsers = 0; $pwdNeverExpires = 0
    Add-Finding -Severity High -Description "Unable to enumerate user accounts."
}

if ($pwdNeverExpires -gt 0) {
    Add-Finding -Severity High -Description "$pwdNeverExpires account(s) have PasswordNeverExpires enabled."
}

# 3. Groups and members
try {
    $allGroups = Get-ADGroup -Filter * -ErrorAction Stop
    $groupMemberships = foreach ($group in $allGroups) {
        $members = Get-ADGroupMember -Identity $group -Recursive -ErrorAction SilentlyContinue |
        Select-Object -ExpandProperty SamAccountName
        [PSCustomObject]@{ GroupName = $group.Name; Members = $members }
    }
}
catch {
    Write-Warning "Failed to enumerate groups: $($_.Exception.Message)"
    $groupMemberships = @()
    Add-Finding -Severity Medium -Description "Unable to enumerate groups and memberships."
}

# 4. Service accounts ("*svc*" naming convention or Service Accounts OU)
try {
    $serviceAccounts = Get-ADUser -Filter "Name -like '*svc*'" `
        -Properties ServicePrincipalName, DoesNotRequirePreAuth, TrustedForDelegation -ErrorAction Stop

    try {
        $svcOUUsers = Get-ADUser -Filter * -SearchBase "OU=Service Accounts,$($domain.DistinguishedName)" `
            -Properties ServicePrincipalName, DoesNotRequirePreAuth, TrustedForDelegation -ErrorAction Stop
        $serviceAccounts = @($serviceAccounts + $svcOUUsers) |
        Select-Object -Unique -Property DistinguishedName, ServicePrincipalName, DoesNotRequirePreAuth, TrustedForDelegation
    }
    catch {
        Write-Verbose "No dedicated Service Accounts OU found or it is inaccessible: $($_.Exception.Message)"
    }

    $svcCount       = $serviceAccounts.Count
    $kerberoastable = ($serviceAccounts | Where-Object { $_.ServicePrincipalName }).Count
    $asrepRoastable = ($allUsers | Where-Object { $_.DoesNotRequirePreAuth }).Count
}
catch {
    Write-Warning "Failed to enumerate service accounts: $($_.Exception.Message)"
    $serviceAccounts = @(); $svcCount = 0; $kerberoastable = 0; $asrepRoastable = 0
    Add-Finding -Severity Medium -Description "Unable to enumerate service accounts."
}

if ($kerberoastable -gt 0) {
    Add-Finding -Severity High -Description "$kerberoastable service account(s) have an SPN set (kerberoastable)."
}
if ($asrepRoastable -gt 0) {
    Add-Finding -Severity Critical -Description "$asrepRoastable account(s) do not require Kerberos pre-authentication (AS-REP roastable)."
}

# Unconstrained delegation (computers + users)
try {
    $delegComputers = (Get-ADComputer -Filter { TrustedForDelegation -eq $true } -ErrorAction Stop).Count
    $delegUsers     = (Get-ADUser -Filter { TrustedForDelegation -eq $true } -ErrorAction Stop).Count
    $unconstrainedDelegation = $delegComputers + $delegUsers
}
catch {
    Write-Warning "Failed to check unconstrained delegation: $($_.Exception.Message)"
    $unconstrainedDelegation = 0
    Add-Finding -Severity Medium -Description "Unable to determine unconstrained delegation exposure."
}

if ($unconstrainedDelegation -gt 0) {
    Add-Finding -Severity Critical -Description "$unconstrainedDelegation object(s) are configured for unconstrained delegation."
}

# 5. GPOs
try {
    if ($gpoModuleAvailable) {
        Import-Module GroupPolicy -ErrorAction Stop
        $gpos     = Get-GPO -All -ErrorAction Stop
        $gpoCount = $gpos.Count
    }
    else {
        throw "GroupPolicy module not available."
    }
}
catch {
    Write-Warning "Failed to enumerate GPOs: $($_.Exception.Message)"
    $gpoCount = 2
    Add-Finding -Severity Medium -Description "Unable to confirm GPO inventory; assuming only default GPOs exist."
}

if ($gpoCount -le 2) {
    Add-Finding -Severity Medium -Description "Only default GPOs detected; no custom security hardening policy has been applied."
}

# 6. Password policy
try {
    $domainPolicy  = Get-ADDefaultDomainPasswordPolicy -ErrorAction Stop
    $minPwdLength  = $domainPolicy.MinPasswordLength
    $pwdComplexity = if ($domainPolicy.ComplexityEnabled) { "Enabled" } else { "Disabled" }
    $pwdHistory    = $domainPolicy.PasswordHistoryCount
    $maxPwdAge     = $domainPolicy.MaxPasswordAge.Days
}
catch {
    Write-Warning "Failed to retrieve password policy: $($_.Exception.Message)"
    $minPwdLength = 7; $pwdComplexity = "Disabled"; $pwdHistory = 0; $maxPwdAge = 42
    Add-Finding -Severity High -Description "Unable to confirm password policy; assuming weak defaults."
}

if ($minPwdLength -lt 8) {
    Add-Finding -Severity High -Description "Minimum password length ($minPwdLength) is below the recommended 8+ characters."
}
if ($pwdComplexity -eq "Disabled") {
    Add-Finding -Severity High -Description "Password complexity requirements are disabled."
}

# 7. Account lockout policy
try {
    $lockoutObj       = Get-ADObject -Identity $domain.DistinguishedName -Properties lockoutThreshold -ErrorAction Stop
    $lockoutThreshold = if ($lockoutObj.lockoutThreshold) { $lockoutObj.lockoutThreshold } else { 0 }
}
catch {
    Write-Warning "Failed to retrieve lockout policy: $($_.Exception.Message)"
    $lockoutThreshold = 0
    Add-Finding -Severity Medium -Description "Unable to confirm lockout policy; assuming NOT CONFIGURED."
}
$lockoutStr = if ($lockoutThreshold -eq 0) { "0 (NOT CONFIGURED)" } else { $lockoutThreshold }

if ($lockoutThreshold -eq 0) {
    Add-Finding -Severity Critical -Description "Account lockout policy is NOT CONFIGURED, leaving accounts exposed to brute-force attacks."
}

# 8. Kerberos encryption types (via krbtgt msDS-SupportedEncryptionTypes)
try {
    $krbtgt  = Get-ADUser -Identity "krbtgt" -Properties msDS-SupportedEncryptionTypes -ErrorAction Stop
    $encFlag = $krbtgt.'msDS-SupportedEncryptionTypes'
    $kerberosEnc = if (-not $encFlag -or $encFlag -eq 0) {
        "DES, RC4, AES128, AES256 (default, not explicitly restricted)"
    }
    else {
        "Custom (flag value: $encFlag) - review manually"
    }
}
catch {
    Write-Warning "Failed to inspect Kerberos encryption settings: $($_.Exception.Message)"
    $kerberosEnc = "DES, RC4, AES128, AES256"
    Add-Finding -Severity Medium -Description "Unable to confirm Kerberos encryption configuration; assuming legacy defaults remain enabled."
}

if ($kerberosEnc -match "DES|RC4") {
    Add-Finding -Severity Critical -Description "Weak Kerberos encryption types (DES/RC4) remain enabled."
}

# 9. Domain Admins / Enterprise Admins
try {
    $domainAdmins     = Get-ADGroupMember -Identity "Domain Admins" -Recursive -ErrorAction Stop |
    Select-Object -ExpandProperty Name
    $enterpriseAdmins = Get-ADGroupMember -Identity "Enterprise Admins" -Recursive -ErrorAction SilentlyContinue |
    Select-Object -ExpandProperty Name
    $privilegedUsers  = @($domainAdmins + $enterpriseAdmins) | Select-Object -Unique
}
catch {
    Write-Warning "Failed to enumerate privileged accounts: $($_.Exception.Message)"
    $privilegedUsers = @()
    Add-Finding -Severity High -Description "Unable to enumerate Domain Admins / Enterprise Admins membership."
}

if ($privilegedUsers.Count -gt 5) {
    Add-Finding -Severity Medium -Description "$($privilegedUsers.Count) accounts hold Domain/Enterprise Admin privileges; review for least privilege."
}

# --- Findings summary ---
$criticalCount = ($findings | Where-Object Severity -eq 'Critical').Count
$highCount     = ($findings | Where-Object Severity -eq 'High').Count
$mediumCount   = ($findings | Where-Object Severity -eq 'Medium').Count
$totalFindings = $findings.Count

# --- Output ---
Write-Host ""
Write-Host "Domain: $domainName" -ForegroundColor Green
Write-Host "DC: $($dcs | Select-Object -First 1)" -ForegroundColor Green
Write-Host "User Accounts: $totalUsers" -ForegroundColor Green
Write-Host "  Password Never Expires: $pwdNeverExpires" -ForegroundColor Yellow
Write-Host "Service Accounts: $svcCount" -ForegroundColor Green
Write-Host "  Unconstrained delegation: $unconstrainedDelegation" -ForegroundColor Yellow
Write-Host "GPOs: $gpoCount (Default only)" -ForegroundColor Green
Write-Host "Password Minimum Length: $minPwdLength" -ForegroundColor Green
Write-Host "Complexity: $pwdComplexity" -ForegroundColor $(if ($pwdComplexity -eq "Enabled") { "Green" } else { "Yellow" })
Write-Host "Lockout Threshold: $lockoutStr" -ForegroundColor Yellow
Write-Host "Kerberos: $kerberosEnc" -ForegroundColor Green
Write-Host "Domain Admins: $($privilegedUsers -join ', ')" -ForegroundColor Red
Write-Host "Findings: $totalFindings (Critical: $criticalCount, High: $highCount, Medium: $mediumCount)" -ForegroundColor Red
Write-Host ""

if ($findings.Count -gt 0) {
    Write-Host "--- Findings Detail ---" -ForegroundColor DarkYellow
    $findings |
    Sort-Object @{Expression = { @('Critical', 'High', 'Medium', 'Low').IndexOf($_.Severity) } } |
    ForEach-Object { Write-Host "[$($_.Severity)] $($_.Description)" }
}
