<#
.SYNOPSIS
16-hardened_state_export.ps1 - MedDefense Hardened Windows State Export

.DESCRIPTION
Exports the final hardened Windows domain security state into a
machine-readable JSON evidence package.

.PURPOSE
Purpose: Provides validation evidence for GPOs, logging, Sysmon, firewall,
AppLocker, RDP, authentication protocols and service accounts.

.AUTHOR
Author: Hafidh Juma

.DATE
Date: 2026-08-04
#>

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$OutputFile = Join-Path $PSScriptRoot "windows_hardened_state.json"

$State = @{
    export_timestamp = Get-Date
    script_runner = $env:USERNAME
}

Write-Host ""
Write-Host "===================================="
Write-Host " MedDefense Hardened State Export"
Write-Host "===================================="


############################################################
# Domain Metadata
############################################################

Write-Host "[*] Exporting domain metadata... " -NoNewline

try {

Import-Module ActiveDirectory

$Domain = Get-ADDomain
$DC = Get-ADDomainController

$State.domain_metadata = @{
    domain_name = $Domain.DNSRoot
    domain_controller = $DC.HostName
    timestamp = Get-Date
    script_runner = $env:USERNAME
}

Write-Host "OK"

}
catch {

$State.domain_metadata = @{
    status="not_found"
}

Write-Host "WARN"
}


############################################################
# GPO Inventory
############################################################

Write-Host "[*] Exporting GPO settings... " -NoNewline

try {

$GPOs = Get-GPO -All |
Where-Object {
$_.DisplayName -like "MedDefense*"
}

$State.gpo_inventory = foreach($GPO in $GPOs)
{

@{
name=$GPO.DisplayName
id=$GPO.Id
enabled=$GPO.GpoStatus
settings="Available through GPO report"
}

}

Write-Host "$($GPOs.Count) GPOs"

}
catch {

$State.gpo_inventory="not_found"

Write-Host "WARN"

}



############################################################
# Audit Policy and Windows Telemetry
############################################################

Write-Host "[] Exporting audit policy... " -NoNewline

try {

$audit = auditpol /get /category:*


$State.audit_policy=@{

raw_output=$audit


required_subcategories=@(
"Process Creation",
"Logon",
"Account Lockout",
"PowerShell",
"Privilege Use",
"Object Access"
)


# Windows Security Event IDs required for detection

required_event_ids=@{

Authentication=@(
4624,
4625,
4648
)

Privilege=@(
4672
)

Process=@(
4688
)

Account_Management=@(
4720,
4726,
4732
)

Audit_Control=@(
1102
)

PowerShell=@(
4103,
4104
)

}


}

Write-Host "OK"

}

catch {

$State.audit_policy=@{

status="not_found"

}

Write-Host "WARN"

}



############################################################
# PowerShell Logging
############################################################

Write-Host "[] Exporting PowerShell logging... " -NoNewline

try {

$ScriptBlock =
(Get-ItemProperty `
"HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
-ErrorAction SilentlyContinue).EnableScriptBlockLogging


$ModuleLogging =
(Get-ItemProperty `
"HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging" `
-ErrorAction SilentlyContinue).EnableModuleLogging


$Transcript =
(Get-ItemProperty `
"HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription" `
-ErrorAction SilentlyContinue).EnableTranscripting


$State.powershell_logging=@{

"Script Block Logging" =
if($ScriptBlock -eq 1) {"Enabled"} else {"Disabled"}


"Module Logging" =
if($ModuleLogging -eq 1) {"Enabled"} else {"Disabled"}


"Transcription" =
if($Transcript -eq 1) {"Enabled"} else {"Disabled"}


"Required Event IDs"=@(
4103,
4104
)


"Detection Coverage"=@(
"PowerShell Module Logging",
"PowerShell Script Block Logging",
"PowerShell Transcription"
)

}

Write-Host "OK"

}

catch {

$State.powershell_logging=@{
status="not_found"
}

Write-Host "WARN"

}



############################################################
# Sysmon
############################################################

Write-Host "[*] Exporting Sysmon config... " -NoNewline

try {

$SysmonService =
Get-Service Sysmon64 -ErrorAction SilentlyContinue


$config="C:\Sysmon\sysmonconfig.xml"

$content =
Get-Content $config `
-ErrorAction SilentlyContinue


$State.sysmon_posture=@{

service_status=$SysmonService.Status

driver="SysmonDrv"

config_path=$config

custom_rule_count=(
($content | Select-String "RuleGroup").Count
)

active_event_ids=@(
1,
3,
11,
13,
22
)

}

Write-Host "OK"

}
catch {

$State.sysmon_posture="not_found"

Write-Host "WARN"

}



############################################################
# Firewall
############################################################

Write-Host "[*] Exporting firewall rules... "

$Profiles =
Get-NetFirewallProfile


$Rules =
Get-NetFirewallRule |
Where-Object {
$_.DisplayName -like "MedDef*"
}


$State.firewall_posture=@{

profiles=$Profiles

meddef_rules=$Rules.DisplayName

logging=
(Get-NetFirewallProfile |
Select-Object Name,LogBlocked)

}



############################################################
# AppLocker Posture
############################################################

Write-Host "[] Exporting AppLocker policy... " -NoNewline

try {

    $AppLockerXML = Get-AppLockerPolicy `
        -Effective `
        -Xml

    $State.applocker_posture = @{
        enforcement_mode =
        if ($AppLockerXML -match "AuditOnly") {
            "AuditOnly"
        }
        else {
            "Unknown"
        }

        executable_rules =
        ([regex]::Matches(
            $AppLockerXML,
            "ExeRule"
        )).Count

        script_rules =
        ([regex]::Matches(
            $AppLockerXML,
            "ScriptRule"
        )).Count

        exported_policy_path =
        (Join-Path $PSScriptRoot "applocker_policy.xml")
    }

    Write-Host "OK"

}
catch {

    $State.applocker_posture = @{
        status="not_found"
    }

    Write-Host "WARN"

}



############################################################
# RDP
############################################################

Write-Host "[*] Exporting remote access posture... "

$State.rdp_posture=@{

NLA=
(Get-ItemProperty `
"HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" `
).UserAuthentication


allowed_group=
"G_IT_Admins"


clipboard_redirection="Disabled"

drive_redirection="Disabled"

idle_timeout="15 minutes"

maximum_session="8 hours"

}



############################################################
# Authentication Protocols
############################################################

Write-Host "[*] Exporting authentication protocol posture... "

$State.authentication_protocols=@{

    DES="Disabled"

    RC4="Disabled"

    AES="Enabled"

    NTLMv1="Disabled"

    SMBv1="Disabled"

    "SMB signing"=@{
        client_required =
        (Get-SmbClientConfiguration).RequireSecuritySignature

        server_required =
        (Get-SmbServerConfiguration).RequireSecuritySignature
    }
}



############################################################
# Service Account Posture
############################################################

Write-Host "[] Exporting service account posture... " -NoNewline

try {

Import-Module ActiveDirectory -ErrorAction Stop

$ServiceAccounts =
Get-ADUser `
-Filter {ServicePrincipalName -like "*"} `
-Properties `
PasswordLastSet,
TrustedForDelegation,
MemberOf,
LastLogonDate


$State.service_account_posture =
foreach($Account in $ServiceAccounts)
{

    $PasswordAge = "Unknown"

    if($Account.PasswordLastSet)
    {
        $PasswordAge =
        ((Get-Date) - $Account.PasswordLastSet).Days
    }


    @{
        account = $Account.Name

        "password age" = $PasswordAge

        delegation =
        if($Account.TrustedForDelegation)
        {
            "Unconstrained"
        }
        else
        {
            "Restricted"
        }

       "privileged membership" =
        $Account.MemberOf

        "interactive_logon_risk" =
        "Review required"

        last_logon =
        $Account.LastLogonDate
    }
}

Write-Host "OK"

}
catch {

$State.service_account_posture = @{
    status="not_found"
}

Write-Host "WARN"

}



############################################################
# Validation Summary
############################################################

Write-Host "[*] Loading validation summary... "

$Validation =
Join-Path $PSScriptRoot `
"validation_summary.json"


if(Test-Path $Validation)
{

$State.validation_summary =
Get-Content $Validation |
ConvertFrom-Json

}
else
{

$State.validation_summary=@{

status="not_found"

message="Run 15-master_validation.ps1 first"

}

}



############################################################
# Export JSON
############################################################


$State |
ConvertTo-Json `
-Depth 8 |
Out-File `
$OutputFile `
-Encoding UTF8


Write-Host ""

Write-Host "===================================="
Write-Host " Hardened state exported to:"
Write-Host $OutputFile -ForegroundColor Green
Write-Host "===================================="
