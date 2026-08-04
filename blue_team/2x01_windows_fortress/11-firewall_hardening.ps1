<#
.SYNOPSIS
11-firewall_hardening.ps1 - MedDefense Windows Firewall Lockdown

.DESCRIPTION
Configures Windows Firewall with a default deny inbound policy,
enables all firewall profiles, creates required service allow rules,
enables firewall logging, and removes conflicting legacy rules.

.PURPOSE
Purpose: Implement endpoint network segmentation and reduce lateral
movement opportunities.

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
Write-Host "[] MedDefense Windows Firewall Hardening" -ForegroundColor Cyan


############################################################
# Capture Current Firewall State
############################################################

Write-Host ""
Write-Host "[*] Current Firewall State..."

$profiles = Get-NetFirewallProfile

foreach ($profile in $profiles) {

    Write-Host "    $($profile.Name): $($profile.Enabled), DefaultInbound: $($profile.DefaultInboundAction)"
}


############################################################
# Enable Firewall Profiles + Default Deny
############################################################

Write-Host ""
Write-Host "[*] Setting default-deny on all profiles... [SET]"

Set-NetFirewallProfile `
-Domain `
-Enabled True `
-DefaultInboundAction Block `
-DefaultOutboundAction Allow

Set-NetFirewallProfile `
-Private `
-Enabled True `
-DefaultInboundAction Block `
-DefaultOutboundAction Allow

Set-NetFirewallProfile `
-Public `
-Enabled True `
-DefaultInboundAction Block `
-DefaultOutboundAction Allow



############################################################
# Remove Existing Custom Rules
############################################################

Write-Host ""
Write-Host "[*] Removing conflicting legacy allow rules..."

Get-NetFirewallRule |
Where-Object {
    $_.Enabled -eq "True" -and
    $_.Direction -eq "Inbound" -and
    $_.DisplayName -notlike "MedDef-*"
} |
ForEach-Object {

    Disable-NetFirewallRule `
    -Name $_.Name

}

Write-Host "    Legacy allow rules disabled [DONE]"



############################################################
# Create Required Allow Rules
############################################################

Write-Host ""
Write-Host "[*] Creating allow rules..."



# RDP Management subnet

New-NetFirewallRule `
-DisplayName "MedDef-RDP-Mgmt" `
-Direction Inbound `
-Protocol TCP `
-LocalPort 3389 `
-RemoteAddress 10.10.3.0/24 `
-Action Allow `
-Profile Domain

Write-Host "    MedDef-RDP-Mgmt: TCP 3389 from 10.10.3.0/24 [CREATED]"



# DNS

New-NetFirewallRule `
-DisplayName "MedDef-DNS-TCP" `
-Direction Inbound `
-Protocol TCP `
-LocalPort 53 `
-Action Allow `
-Profile Domain

New-NetFirewallRule `
-DisplayName "MedDef-DNS-UDP" `
-Direction Inbound `
-Protocol UDP `
-LocalPort 53 `
-Action Allow `
-Profile Domain

Write-Host "    MedDef-DNS: TCP/UDP 53 [CREATED]"



# LDAP

New-NetFirewallRule `
-DisplayName "MedDef-LDAP" `
-Direction Inbound `
-Protocol TCP `
-LocalPort 389 `
-Action Allow `
-Profile Domain

Write-Host "    MedDef-LDAP: TCP 389 [CREATED]"



# Kerberos

New-NetFirewallRule `
-DisplayName "MedDef-Kerberos-TCP" `
-Direction Inbound `
-Protocol TCP `
-LocalPort 88 `
-Action Allow `
-Profile Domain


New-NetFirewallRule `
-DisplayName "MedDef-Kerberos-UDP" `
-Direction Inbound `
-Protocol UDP `
-LocalPort 88 `
-Action Allow `
-Profile Domain

Write-Host "    MedDef-Kerberos: TCP/UDP 88 [CREATED]"



# SMB

New-NetFirewallRule `
-DisplayName "MedDef-SMB" `
-Direction Inbound `
-Protocol TCP `
-LocalPort 445 `
-RemoteAddress 10.10.1.0/24 `
-Action Allow `
-Profile Domain

Write-Host "    MedDef-SMB: TCP 445 from 10.10.1.0/24 [CREATED]"



# WinRM

New-NetFirewallRule `
-DisplayName "MedDef-WinRM-HTTP" `
-Direction Inbound `
-Protocol TCP `
-LocalPort 5985 `
-RemoteAddress 10.10.3.0/24 `
-Action Allow `
-Profile Domain


New-NetFirewallRule `
-DisplayName "MedDef-WinRM-HTTPS" `
-Direction Inbound `
-Protocol TCP `
-LocalPort 5986 `
-RemoteAddress 10.10.3.0/24 `
-Action Allow `
-Profile Domain


Write-Host "    MedDef-WinRM: TCP 5985-5986 from 10.10.3.0/24 [CREATED]"



############################################################
# Enable Firewall Logging
############################################################

Write-Host ""
Write-Host "[*] Enabling dropped packet logging... [SET]"

Set-NetFirewallProfile `
-All `
-LogAllowed True `
-LogBlocked True `
-LogFileName "%systemroot%\system32\LogFiles\Firewall\pfirewall.log"



############################################################
# Verification
############################################################

Write-Host ""
Write-Host "[*] Verification..."

$verify = Get-NetFirewallProfile


foreach ($profile in $verify) {

    if (
        $profile.Enabled -eq $true -and
        $profile.DefaultInboundAction -eq "Block"
    ){
        Write-Host "    $($profile.Name): ON, DefaultInbound: Block [VERIFIED]"
    }
}


$rules = Get-NetFirewallRule |
Where-Object {
    $_.DisplayName -like "MedDef-*"
}


Write-Host ""
Write-Host "    Custom rules: $($rules.Count) active [VERIFIED]"


Write-Host ""
Write-Host "[+] Firewall hardening completed successfully."
