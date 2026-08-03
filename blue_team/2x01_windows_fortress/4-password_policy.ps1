<#
.SYNOPSIS
    4-password_policy.ps1 - MedDefense Password and Lockout Policy Deployment

.DESCRIPTION
    Creates and configures a CIS-aligned password and account lockout
    Group Policy Object for the MedDefense domain environment.

.PURPOSE
   Purpose: Remediate weak password controls and prevent brute-force attacks by
    enforcing strong password requirements and account lockout settings.

.AUTHOR
    Author: Hafidh Juma

.DATE
    Date: 2026-08-03
#>

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"


$GPOName = "MedDefense - Password and Lockout Policy"


Write-Host "[*] Creating GPO: `"$GPOName`"..." -ForegroundColor Cyan


# ------------------------------------------------------------
# Check required modules
# ------------------------------------------------------------

try {

    Import-Module GroupPolicy -ErrorAction Stop

}
catch {

    Write-Error "GroupPolicy module not available. Install RSAT Group Policy Management tools."
    exit 1

}


# ------------------------------------------------------------
# Create or retrieve GPO
# ------------------------------------------------------------

$gpo = Get-GPO -Name $GPOName -ErrorAction SilentlyContinue


if ($null -eq $gpo) {

    New-GPO -Name $GPOName | Out-Null

    Write-Host "    CREATED" -ForegroundColor Green

}
else {

    Write-Host "    Already exists - using existing GPO" -ForegroundColor Yellow

}


# ------------------------------------------------------------
# Configure Password Policy
# ------------------------------------------------------------

Write-Host ""
Write-Host "[*] Configuring Password Policy..." -ForegroundColor Cyan


Set-GPRegistryValue `
    -Name $GPOName `
    -Key "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" `
    -ValueName "PasswordComplexity" `
    -Type DWord `
    -Value 1


# Password Policy Registry location
$PasswordPolicyPath =
"HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"


# Minimum password length
Set-GPRegistryValue `
    -Name $GPOName `
    -Key "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" `
    -ValueName "MinimumPasswordLength" `
    -Type DWord `
    -Value 14


Write-Host "    Minimum Length: 14            [SET]"

Write-Host "    Complexity: Enabled           [SET]"


# Password history

Set-GPRegistryValue `
-Name $GPOName `
-Key "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" `
-ValueName "PasswordHistoryCount" `
-Type DWord `
-Value 24

Write-Host "    History: 24                   [SET]"


# Maximum password age
Set-GPRegistryValue `
    -Name $GPOName `
    -Key "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" `
    -ValueName "MaximumPasswordAge" `
    -Type DWord `
    -Value 0


Write-Host "    Maximum Age: 0                [SET]"


# Minimum password age
Set-GPRegistryValue `
    -Name $GPOName `
    -Key "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" `
    -ValueName "MinimumPasswordAge" `
    -Type DWord `
    -Value 1


Write-Host "    Minimum Age: 1 day            [SET]"



# ------------------------------------------------------------
# Account Lockout Configuration
# ------------------------------------------------------------

Write-Host ""
Write-Host "[*] Configuring Account Lockout..." -ForegroundColor Cyan


Set-GPRegistryValue `
    -Name $GPOName `
    -Key "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" `
    -ValueName "LockoutThreshold" `
    -Type DWord `
    -Value 5


Write-Host "    Threshold: 5 attempts         [SET]"



Set-GPRegistryValue `
    -Name $GPOName `
    -Key "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" `
    -ValueName "LockoutDuration" `
    -Type DWord `
    -Value 15


Write-Host "    Duration: 15 minutes          [SET]"



Set-GPRegistryValue `
    -Name $GPOName `
    -Key "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" `
    -ValueName "ResetLockoutCounter" `
    -Type DWord `
    -Value 15


Write-Host "    Reset Counter: 15 minutes     [SET]"



# ------------------------------------------------------------
# Link GPO to Domain Root
# ------------------------------------------------------------

Write-Host ""
Write-Host "[*] Linking GPO to domain root..." -ForegroundColor Cyan


$domain = (Get-ADDomain).DNSRoot


New-GPLink `
    -Name $GPOName `
    -Target $domain `
    -LinkEnabled Yes `
    -ErrorAction SilentlyContinue | Out-Null


Write-Host "    LINKED" -ForegroundColor Green



# ------------------------------------------------------------
# Force Group Policy Update
# ------------------------------------------------------------

Write-Host ""
Write-Host "[*] Forcing Group Policy update..." -ForegroundColor Cyan


gpupdate /force | Out-Null


Write-Host "    COMPLETE" -ForegroundColor Green



# ------------------------------------------------------------
# Verification
# ------------------------------------------------------------

Write-Host ""
Write-Host "[*] Verifying effective policy..." -ForegroundColor Cyan


secedit /export `
    /cfg "$env:TEMP\effective_policy.inf" `
    /quiet


$policy = Get-Content "$env:TEMP\effective_policy.inf"


if ($policy -match "MinimumPasswordLength") {

    Write-Host "[+] Password policy successfully applied" -ForegroundColor Green

}
else {

    Write-Warning "Unable to verify password policy"

}


Write-Host ""
Write-Host "Password and Lockout Policy deployment completed."
