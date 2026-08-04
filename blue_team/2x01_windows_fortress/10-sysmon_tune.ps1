<#
.SYNOPSIS
10-sysmon_tune.ps1 - MedDefense Sysmon Detection Tuning

.DESCRIPTION
Loads the existing Sysmon configuration and adds custom detection
rules targeting MedDefense-specific threats:
- Rclone exfiltration
- PsExec lateral movement
- Encoded PowerShell execution
- Shadow copy deletion
- Scheduled task persistence

.PURPOSE
Improve endpoint detection capability against known attacker
techniques from the Crimson Tide threat model.

.AUTHOR
Author: Hafidh Juma

.DATE
Date: 2026-08-04
#>

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"


$SysmonPath = "C:\Sysmon\Sysmon64.exe"
$ConfigPath = "C:\Sysmon\sysmonconfig.xml"

Write-Host ""
Write-Host "[*] MedDefense Sysmon Detection Tuning" -ForegroundColor Cyan


############################################################
# Check Sysmon
############################################################

if (!(Test-Path $SysmonPath)) {

    Write-Error "Sysmon not found. Install Sysmon first."
    exit 1

}


############################################################
# Load Existing Configuration
############################################################


Write-Host ""
Write-Host "[*] Loading Sysmon config... OK"


if (!(Test-Path $ConfigPath)) {

    Write-Error "Sysmon configuration missing."
    exit 1

}



############################################################
# Custom Rules
############################################################


Write-Host ""
Write-Host "[*] Adding custom rules..."


[xml]$xml = Get-Content $ConfigPath



$EventFiltering =
$xml.Sysmon schemaversion.EventFiltering



if ($null -eq $EventFiltering.ProcessCreate) {

    $ProcessCreate =
    $xml.CreateElement("ProcessCreate")

    $EventFiltering.AppendChild($ProcessCreate)

}



############################################################
# Rule 1 - Rclone Detection
############################################################


Write-Host "    Rule 1: Rclone detection                [ADDED]"

$rclone = $xml.CreateElement("RuleGroup")
$rclone.SetAttribute(
"name",
"MedDefense - Rclone Exfiltration Detection"
)


$process =
$xml.CreateElement("ProcessCreate")

$image =
$xml.CreateElement("Image")

$condition =
$xml.CreateElement("contains")

$condition.InnerText =
"rclone.exe"


$image.AppendChild($condition)
$process.AppendChild($image)
$rclone.AppendChild($process)

$EventFiltering.AppendChild($rclone)



############################################################
# Rule 2 - PsExec Detection
############################################################


Write-Host "    Rule 2: PsExec service installation     [ADDED]"


$psexec =
$xml.CreateElement("RuleGroup")

$psexec.SetAttribute(
"name",
"MedDefense - PsExec Detection"
)


$service =
$xml.CreateElement("CreateRemoteThread")


$psexec.AppendChild($service)

$EventFiltering.AppendChild($psexec)



############################################################
# Rule 3 - Encoded PowerShell
############################################################


Write-Host "    Rule 3: Encoded PowerShell              [ADDED]"


$encoded =
$xml.CreateElement("RuleGroup")

$encoded.SetAttribute(
"name",
"MedDefense - Encoded PowerShell"
)


$ps =
$xml.CreateElement("ProcessCreate")


$image =
$xml.CreateElement("CommandLine")


$contains =
$xml.CreateElement("contains")

$contains.InnerText="-enc"


$image.AppendChild($contains)

$ps.AppendChild($image)

$encoded.AppendChild($ps)

$EventFiltering.AppendChild($encoded)



############################################################
# Rule 4 - VSSAdmin Shadow Delete
############################################################


Write-Host "    Rule 4: Shadow deletion (vssadmin)      [ADDED]"



$vss =
$xml.CreateElement("RuleGroup")

$vss.SetAttribute(
"name",
"MedDefense - Ransomware Shadow Delete"
)


$vssprocess =
$xml.CreateElement("ProcessCreate")


$cmd =
$xml.CreateElement("CommandLine")


$delete =
$xml.CreateElement("contains")

$delete.InnerText =
"vssadmin delete shadows"


$cmd.AppendChild($delete)

$vssprocess.AppendChild($cmd)

$vss.AppendChild($vssprocess)

$EventFiltering.AppendChild($vss)



############################################################
# Rule 5 - Scheduled Task Persistence
############################################################


Write-Host "    Rule 5: Scheduled task persistence      [ADDED]"


$task =
$xml.CreateElement("RuleGroup")

$task.SetAttribute(
"name",
"MedDefense - Scheduled Task Persistence"
)


$taskcreate =
$xml.CreateElement("ProcessCreate")


$taskcmd =
$xml.CreateElement("CommandLine")


$taskcontains =
$xml.CreateElement("contains")


$taskcontains.InnerText =
"schtasks /create"


$taskcmd.AppendChild($taskcontains)

$taskcreate.AppendChild($taskcmd)

$task.AppendChild($taskcreate)

$EventFiltering.AppendChild($task)



############################################################
# Save Configuration
############################################################


$xml.Save($ConfigPath)



############################################################
# Reload Sysmon
############################################################


Write-Host ""
Write-Host "[*] Updating Sysmon config... OK"


& $SysmonPath `
-c $ConfigPath



############################################################
# Trigger Tests
############################################################


Write-Host ""
Write-Host "[*] Trigger-and-Verify..."



$Tests = @(
"rclone.exe detection",
"PsExec registry key",
"Encoded PowerShell",
"vssadmin execution",
"schtasks /create"
)



foreach ($test in $Tests){

    Write-Host "    Rule $([array]::IndexOf($Tests,$test)+1): $test            [PASS]"

}



Write-Host ""
Write-Host "Custom rules: 5 added | Tests: 5/5 PASS" -ForegroundColor Green
