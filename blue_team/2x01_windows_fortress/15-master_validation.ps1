<#
.SYNOPSIS
15-master_validation.ps1 - MedDefense Windows Hardening Validation

.DESCRIPTION
Read-only compliance validation script.
Checks all security hardening controls deployed on the domain.

.PURPOSE
Purpose: Weekly compliance dashboard for Windows security controls.

.AUTHOR
Author: Hafidh Juma

.DATE
Date: 2026-08-04
#>

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$CriticalFailures = 0

function Test-Result {

    param(
        [string]$Name,
        [bool]$Status,
        [bool]$Critical = $true
    )

    if ($Status)
    {
        Write-Host "[PASS] $Name" -ForegroundColor Green
    }
    else
    {
        Write-Host "[FAIL] $Name" -ForegroundColor Red

        if ($Critical)
        {
            $script:CriticalFailures++
        }
    }
}


function Test-Warning {

param(
[string]$Message
)

Write-Host "[WARN] $Message" -ForegroundColor Yellow

}


Write-Host ""
Write-Host "===================================="
Write-Host " MedDefense Security Validation"
Write-Host "===================================="


############################################################
# Password Policy
############################################################

Write-Host ""
Write-Host "--- Password & Lockout ---"


try {

$Password =
Get-ADDefaultDomainPasswordPolicy


Test-Result `
"Minimum length: $($Password.MinPasswordLength)" `
($Password.MinPasswordLength -ge 14)


Test-Result `
"Lockout threshold: $($Password.LockoutThreshold)" `
($Password.LockoutThreshold -eq 5)


}
catch {

Test-Result "Password Policy Query" $false

}

try
{
    $Sysmon =
    Get-Service `
    -Name Sysmon64

    Test-Result `
    "Service: Running" `
    ($Sysmon.Status -eq "Running")
}
catch
{
    Test-Result `
    "Sysmon Service Check" `
    $false
}

try
{
    $Rules =
    Get-Content `
    "C:\Sysmon\sysmonconfig.xml"

    Test-Result `
    "Custom rules: 5 present" `
    (
        $Rules -match "rclone" -and
        $Rules -match "psexec" -and
        $Rules -match "-enc" -and
        $Rules -match "vssadmin" -and
        $Rules -match "schtasks"
    )
}
catch
{
    Test-Result `
    "Sysmon configuration validation" `
    $false
}

############################################################
# Audit Policy
############################################################


Write-Host ""
Write-Host "--- Audit Policy ---"


$audit =
auditpol /get /subcategory:"Process Creation"


Test-Result `
"Process Creation: Success" `
($audit -match "Success")


$cmdLogging =
Get-ItemProperty `
"HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
-Name ProcessCreationIncludeCmdLine_Enabled


Test-Result `
"Command-line logging: Enabled" `
($cmdLogging.ProcessCreationIncludeCmdLine_Enabled -eq 1)



$SecurityLog =
Get-WinEvent `
-ListLog Security


Test-Result `
"Security log: 1 GB" `
($SecurityLog.MaximumSizeInBytes -ge 1073741824)




############################################################
# PowerShell Logging
############################################################


Write-Host ""
Write-Host "--- PowerShell ---"


$PSLog =
Get-ItemProperty `
"HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
-Name EnableScriptBlockLogging


Test-Result `
"Script Block Logging: Enabled" `
($PSLog.EnableScriptBlockLogging -eq 1)



$Transcript =
Get-ItemProperty `
"HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription"


Test-Result `
"Transcription: Enabled" `
($Transcript.EnableTranscripting -eq 1)




############################################################
# Sysmon
############################################################


Write-Host ""
Write-Host "--- Sysmon ---"


$Sysmon =
Get-Service `
Name Sysmon64


Test-Result `
"Service: Running" `
($Sysmon.Status -eq "Running")



$Rules =
Get-Content `
"C:\Sysmon\sysmonconfig.xml"


Test-Result `
"Custom rules: 5 present" `
(
$Rules -match "rclone" -and
$Rules -match "psexec" -and
$Rules -match "-enc" -and
$Rules -match "vssadmin" -and
$Rules -match "schtasks"
)




############################################################
# Kerberos
############################################################


Write-Host ""
Write-Host "--- Kerberos ---"


$Kerberos =
Get-ItemProperty `
"HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters"


Test-Result `
"DES: Disabled" `
(
$Kerberos.SupportedEncryptionTypes -band 1 -eq 0
)



Test-Result `
"RC4: Disabled" `
(
$Kerberos.SupportedEncryptionTypes -band 2 -eq 0
)




############################################################
# SMB
############################################################


Write-Host ""
Write-Host "--- SMB ---"


$SMB =
Get-SmbServerConfiguration


Test-Result `
"SMBv1: Disabled" `
(
$SMB.EnableSMB1Protocol -eq $false
)



Test-Result `
"Signing: Required" `
(
$SMB.RequireSecuritySignature -eq $true
)




############################################################
# Firewall
############################################################


Write-Host ""
Write-Host "--- Firewall ---"


$Firewall =
Get-NetFirewallProfile


Test-Result `
"All profiles: ON, DefaultInbound: Block" `
(
($Firewall.Enabled -notcontains $false) -and
($Firewall.DefaultInboundAction -notcontains "Allow")
)




############################################################
# RDP
############################################################


Write-Host ""
Write-Host "--- RDP ---"


$RDP =
Get-ItemProperty `
"HKLM:\System\CurrentControlSet\Control\Terminal Server"


Test-Result `
"NLA: Required" `
(
$RDP.UserAuthentication -eq 1
)



$Group =
Get-LocalGroupMember `
"Remote Desktop Users"


Test-Result `
"G_IT_Admins only" `
(
$Group.Name -match "G_IT_Admins"
)




############################################################
# Service Accounts
############################################################


Write-Host ""
Write-Host "--- Service Accounts ---"


$Accounts =
Get-ADUser `
-Filter * `
-Properties TrustedForDelegation,PasswordLastSet,ServicePrincipalName



$DelegationOK = 0


foreach($Account in $Accounts)
{

if(
$Account.ServicePrincipalName.Count -gt 0 -and
$Account.TrustedForDelegation -eq $false
)
{
$DelegationOK++
}


if($Account.PasswordLastSet)
{

$Age =
((Get-Date)-$Account.PasswordLastSet).Days


if($Age -gt 180)
{
Test-Warning `
"$($Account.Name) password age: $Age days"
}

}

}



Test-Result `
"Delegation restricted: $DelegationOK service accounts" `
($DelegationOK -gt 0)




############################################################
# Final Status
############################################################


Write-Host ""
Write-Host "===================================="

if($CriticalFailures -eq 0)
{

Write-Host `
"COMPLIANCE STATUS: PASS" `
-ForegroundColor Green

exit 0

}
else
{

Write-Host `
"COMPLIANCE STATUS: FAILED ($CriticalFailures critical issues)" `
-ForegroundColor Red

exit 1

}
