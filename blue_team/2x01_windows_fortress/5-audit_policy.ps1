<#
.SYNOPSIS
    5-audit_policy.ps1 - MedDefense Advanced Audit Policy Deployment

.DESCRIPTION
    Creates and configures an Advanced Audit Policy Group Policy Object
    to enable security visibility required for detection and response.

.PURPOSE
    Purpose: Enable granular Windows auditing, process visibility,
    command-line logging, privilege monitoring, and security log protection.

.AUTHOR
    Author: Hafidh Juma

.DATE
    Date: 2026-08-03
#>

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$GPOName = "MedDefense - Advanced Audit Policy"

Write-Host "[*] Creating GPO: `"$GPOName`"..." -ForegroundColor Cyan


# ------------------------------------------------------------
# Import Required Modules
# ------------------------------------------------------------

try {
    Import-Module GroupPolicy -ErrorAction Stop
}
catch {
    Write-Error "GroupPolicy module unavailable. Install RSAT tools."
    exit 1
}


# ------------------------------------------------------------
# Create GPO
# ------------------------------------------------------------

$gpo = Get-GPO -Name $GPOName -ErrorAction SilentlyContinue

if ($null -eq $gpo) {
    New-GPO -Name $GPOName | Out-Null
    Write-Host "    CREATED" -ForegroundColor Green
}
else {
    Write-Host "    GPO already exists" -ForegroundColor Yellow
}


# ------------------------------------------------------------
# Configure Advanced Audit Policy
# ------------------------------------------------------------

Write-Host ""
Write-Host "[*] Configuring Audit Categories..." -ForegroundColor Cyan


# Account Logon

auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable
Write-Host "    Credential Validation: Success, Failure [SET]"

auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable
Write-Host "    Kerberos Authentication: Success, Failure [SET]"



# Logon / Logoff

auditpol /set /subcategory:"Logon" /success:enable /failure:enable
Write-Host "    Logon: Success, Failure [SET]"

auditpol /set /subcategory:"Logoff" /success:enable
Write-Host "    Logoff: Success [SET]"

auditpol /set /subcategory:"Special Logon" /success:enable
Write-Host "    Special Logon: Success [SET]"



# Account Management

auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
Write-Host "    User Account Management: Success, Failure [SET]"



# Privilege Use

auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable
Write-Host "    Sensitive Privilege Use: Success, Failure [SET]"



# Object Access

auditpol /set /subcategory:"File System" /success:enable /failure:enable
Write-Host "    File System: Success, Failure [SET]"

auditpol /set /subcategory:"Registry" /success:enable /failure:enable
Write-Host "    Registry: Success, Failure [SET]"



# Process Tracking

auditpol /set /subcategory:"Process Creation" /success:enable
Write-Host "    Process Creation: Success [SET]"



# ------------------------------------------------------------
# Enable Command Line Logging for Event ID 4688
# ------------------------------------------------------------

# CommandLine logging enables full command line visibility in Event ID 4688

Write-Host ""
Write-Host "[*] Enabling CommandLine logging in process creation events... [SET]"

Set-GPRegistryValue `
-Name $GPOName `
-Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
-ValueName "ProcessCreationIncludeCmdLine_Enabled" `
-Type DWord `
-Value 1



# ------------------------------------------------------------
# Restrict Security Log Clearing
# ------------------------------------------------------------

Write-Host "[*] Restricting Security log clearing... [SET]"

Set-GPRegistryValue `
-Name $GPOName `
-Key "HKLM\Software\Policies\Microsoft\Windows\EventLog\Security" `
-ValueName "RestrictGuestAccess" `
-Type DWord `
-Value 1



# ------------------------------------------------------------
# Configure Security Log Size 1GB
# ------------------------------------------------------------

Write-Host "[*] Setting Security log max size to 1 GB... [SET]"

Set-GPRegistryValue `
-Name $GPOName `
-Key "HKLM\Software\Policies\Microsoft\Windows\EventLog\Security" `
-ValueName "MaxSize" `
-Type DWord `
-Value 1048576



# ------------------------------------------------------------
# Link GPO to Domain Root
# ------------------------------------------------------------

Write-Host ""
Write-Host "[*] Linking GPO and forcing update..." -ForegroundColor Cyan

$domain = (Get-ADDomain).DistinguishedName

New-GPLink `
-Name $GPOName `
-Target $domain `
-LinkEnabled Yes | Out-Null


gpupdate /force

Write-Host "    COMPLETE"



# ------------------------------------------------------------
# Verify Configuration
# ------------------------------------------------------------

Write-Host ""
Write-Host "[*] VERIFY Advanced Audit Policy..." -ForegroundColor Cyan

auditpol /get /category:*

Write-Host ""
Write-Host "Audit Policy VERIFIED" -ForegroundColor Green
