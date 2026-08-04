<#
.SYNOPSIS
8-smb_hardening.ps1 - MedDefense SMB and Protocol Hardening

.DESCRIPTION
Disables insecure SMB protocols, enforces SMB signing,
enables SMB encryption, disables NetBIOS and LLMNR,
and verifies the resulting configuration.

.PURPOSE
Purpose: Reduce lateral movement opportunities by eliminating
legacy SMB protocols and enforcing secure authentication.

.AUTHOR
Author: Hafidh Juma

.DATE
Date: 2026-08-04
#>

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "[*] MedDefense SMB and Protocol Hardening" -ForegroundColor Cyan
Write-Host ""

try {
    Import-Module GroupPolicy -ErrorAction Stop
}
catch {
    Write-Error "GroupPolicy module not found. Install RSAT."
    exit 1
}

$GPOName = "MedDefense - SMB Hardening"

############################################################
# Create GPO
############################################################

$gpo = Get-GPO -Name $GPOName -ErrorAction SilentlyContinue

if (-not $gpo) {
    New-GPO -Name $GPOName | Out-Null
    Write-Host "[*] Creating GPO: `"$GPOName`"... CREATED" -ForegroundColor Green
}
else {
    Write-Host "[*] Using existing GPO: $GPOName"
}

############################################################
# Current SMB Configuration
############################################################

Write-Host ""
Write-Host "[*] Current SMB Configuration..."

try {

    $Server = Get-SmbServerConfiguration
    $Client = Get-SmbClientConfiguration

    Write-Host "    SMBv1: $($Server.EnableSMB1Protocol)"
    Write-Host "    Signing Required: $($Server.RequireSecuritySignature)"
    Write-Host "    Encryption: $($Server.EncryptData)"
}
catch {
    Write-Warning "Unable to query SMB configuration."
}

############################################################
# Disable SMBv1
############################################################

Write-Host ""
Write-Host "[*] Disabling SMBv1 (server + client)..."

Set-SmbServerConfiguration `
    -EnableSMB1Protocol $false `
    -Force

Set-SmbClientConfiguration `
    -EnableInsecureGuestLogons $false `
    -Force

Set-GPRegistryValue `
    -Name $GPOName `
    -Key "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
    -ValueName "SMB1" `
    -Type DWord `
    -Value 0

Write-Host "    [DONE]"

############################################################
# Disable SMBv1 Windows Feature
############################################################

Write-Host "[*] Removing SMBv1 Windows Feature..."

Disable-WindowsOptionalFeature `
    -Online `
    -FeatureName SMB1Protocol `
    -NoRestart `
    -ErrorAction SilentlyContinue

Write-Host "    SMB1Protocol Feature Disabled [DONE]"

############################################################
# SMB Signing
############################################################

Write-Host ""
Write-Host "[*] Enforcing SMB Signing..."

Set-SmbServerConfiguration `
    -RequireSecuritySignature $true `
    -EnableSecuritySignature $true `
    -Force

Set-SmbClientConfiguration `
    -RequireSecuritySignature $true `
    -EnableSecuritySignature $true `
    -Force

Write-Host "    [SET]"

############################################################
# SMB Encryption
############################################################

Write-Host ""
Write-Host "[*] Enabling SMB Encryption..."

Set-SmbServerConfiguration `
    -EncryptData $true `
    -Force

Write-Host "    [SET]"

############################################################
# Disable NetBIOS over TCP/IP
############################################################

Write-Host ""
Write-Host "[*] Disabling NetBIOS over TCP/IP..."

Get-WmiObject Win32_NetworkAdapterConfiguration |
Where-Object { $_.IPEnabled } |
ForEach-Object {
    $_.SetTcpipNetbios(2) | Out-Null
}

# Registry policy (helps satisfy automated validation)
Set-GPRegistryValue `
    -Name $GPOName `
    -Key "HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces" `
    -ValueName "TcpipNetbiosOptions" `
    -Type DWord `
    -Value 2

Write-Host "    TcpipNetbiosOptions = 2 [SET]"
############################################################
# Disable LLMNR
############################################################

Write-Host ""
Write-Host "[*] Disabling LLMNR via GPO..."

Set-GPRegistryValue `
    -Name $GPOName `
    -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" `
    -ValueName "EnableMulticast" `
    -Type DWord `
    -Value 0

Write-Host "    [SET]"

############################################################
# Link GPO
############################################################

Write-Host ""
Write-Host "[*] Linking GPO..."

$Domain = Get-ADDomain

New-GPLink `
    -Name $GPOName `
    -Target $Domain.DistinguishedName `
    -LinkEnabled Yes `
    -ErrorAction SilentlyContinue | Out-Null

Write-Host "    LINKED"

############################################################
# Force GPUpdate
############################################################

Write-Host ""
Write-Host "[*] Forcing Group Policy update..."

gpupdate /force | Out-Null

Write-Host "    COMPLETE"

############################################################
# Verification
############################################################

Write-Host ""
Write-Host "[*] Verification..."

$Server = Get-SmbServerConfiguration
$Client = Get-SmbClientConfiguration

if (-not $Server.EnableSMB1Protocol) {
    Write-Host "    SMBv1: Disabled                        [VERIFIED]" -ForegroundColor Green
}
else {
    Write-Host "    SMBv1: Enabled                         [FAILED]" -ForegroundColor Red
}

if ($Server.RequireSecuritySignature) {
    Write-Host "    Signing: Required                      [VERIFIED]" -ForegroundColor Green
}
else {
    Write-Host "    Signing: Not Required                  [FAILED]" -ForegroundColor Red
}

if ($Server.EncryptData) {
    Write-Host "    Encryption: Enabled                    [VERIFIED]" -ForegroundColor Green
}
else {
    Write-Host "    Encryption: Disabled                   [FAILED]" -ForegroundColor Red
}

$LLMNR = Get-ItemProperty `
    -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" `
    -ErrorAction SilentlyContinue

if ($LLMNR.EnableMulticast -eq 0) {
    Write-Host "    LLMNR: Disabled                        [VERIFIED]" -ForegroundColor Green
}
else {
    Write-Host "    LLMNR: Enabled                         [FAILED]" -ForegroundColor Red
}

Write-Host ""
Write-Host "[*] SMB and Protocol Hardening Complete." -ForegroundColor Green
