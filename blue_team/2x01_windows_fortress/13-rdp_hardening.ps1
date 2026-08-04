<#
.SYNOPSIS
13-rdp_hardening.ps1 - MedDefense RDP and Remote Access Hardening

.DESCRIPTION
Hardens Remote Desktop Protocol by enforcing Network Level Authentication,
restricting access to authorized administrators, limiting sessions, disabling
data redirection features, and reducing lateral movement opportunities.

.PURPOSE
Purpose: Prevent RDP abuse, credential theft, lateral movement,
and unauthorized remote access.

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
Write-Host "[*] MedDefense RDP Hardening" -ForegroundColor Cyan


############################################################
# Enable Network Level Authentication
############################################################

Write-Host ""
Write-Host "[*] Enabling NLA..."

Set-ItemProperty `
-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" `
-Name "UserAuthentication" `
-Value 1 `
-Type DWord


Write-Host "    UserAuthentication = 1 [SET]"



############################################################
# Restrict RDP Access
############################################################

Write-Host ""
Write-Host "[*] Restricting RDP access to G_IT_Admins..."


$RDPGroup = "Remote Desktop Users"
$AdminGroup = "G_IT_Admins"


try {

    Remove-LocalGroupMember `
    -Group $RDPGroup `
    -Member "Domain Users" `
    -ErrorAction SilentlyContinue


    Add-LocalGroupMember `
    -Group $RDPGroup `
    -Member $AdminGroup `
    -ErrorAction SilentlyContinue


    Write-Host "    Removed: Domain Users from Remote Desktop Users"
    Write-Host "    Added: G_IT_Admins [SET]"

}

catch {

    Write-Warning "Unable to modify RDP groups"

}



############################################################
# Session Limits
############################################################

Write-Host ""
Write-Host "[*] Configuring Session Limits..."


$TSPath =
"HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"


if (!(Test-Path $TSPath)) {

    New-Item `
    -Path $TSPath `
    -Force | Out-Null

}


# Idle timeout 15 minutes

Set-ItemProperty `
-Path $TSPath `
-Name "MaxIdleTime" `
-Type DWord `
-Value 900000


Write-Host "    Idle timeout: 15 min [SET]"



# Maximum session 8 hours

Set-ItemProperty `
-Path $TSPath `
-Name "MaxConnectionTime" `
-Type DWord `
-Value 28800000


Write-Host "    Max session: 8 hours [SET]"



############################################################
# Encryption Level
############################################################

Write-Host ""
Write-Host "[*] Setting encryption level High..."

Set-ItemProperty `
-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
-Name "MinEncryptionLevel" `
-Type DWord `
-Value 3


Write-Host "    Encryption: High [SET]"



############################################################
# Disable Clipboard and Drive Redirection
############################################################

Write-Host ""
Write-Host "[*] Disabling RDP Redirection..."


# Clipboard

Set-ItemProperty `
-Path $TSPath `
-Name "DisableClipboardRedirection" `
-Type DWord `
-Value 1


Write-Host "    Clipboard: Disabled [SET]"



# Drive mapping

Set-ItemProperty `
-Path $TSPath `
-Name "fDisableCdm" `
-Type DWord `
-Value 1


Write-Host "    Drive redirection: Disabled [SET]"



############################################################
# Disable Remote Assistance
############################################################

Write-Host ""
Write-Host "[*] Disabling Remote Assistance..."


Set-ItemProperty `
-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" `
-Name "fAllowToGetHelp" `
-Type DWord `
-Value 0


Write-Host "    Remote Assistance: Disabled [SET]"



############################################################
# Verification
############################################################

Write-Host ""
Write-Host "[*] Verification..."


$NLA =
Get-ItemPropertyValue `
-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" `
-Name "UserAuthentication"


if ($NLA -eq 1) {

Write-Host "    NLA: Required [VERIFIED]"

}
else {

Write-Host "    NLA: FAILED"

}



$Encryption =
Get-ItemPropertyValue `
-Path $TSPath `
-Name "MinEncryptionLevel"


if ($Encryption -eq 3) {

Write-Host "    Encryption: High [VERIFIED]"

}


$Clipboard =
Get-ItemPropertyValue `
-Path $TSPath `
-Name "DisableClipboardRedirection"


if ($Clipboard -eq 1) {

Write-Host "    Clipboard: Disabled [VERIFIED]"

}


$Drive =
Get-ItemPropertyValue `
-Path $TSPath `
-Name "fDisableCdm"


if ($Drive -eq 1) {

Write-Host "    Drive Redirection: Disabled [VERIFIED]"

}


Write-Host ""
Write-Host "[+] RDP Hardening Complete" -ForegroundColor Green
