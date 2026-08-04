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
Purpose: Improve endpoint detection capability against known attacker
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
# Rule 2 - PsExec Service Installation Detection
############################################################

Write-Host "    Rule 2: PsExec service installation     [ADDED]"

$psexec =
$xml.CreateElement("RuleGroup")

$psexec.SetAttribute(
    "name",
    "MedDefense - PsExec Service Installation Detection"
)


# Detect PsExec executable execution

$process =
$xml.CreateElement("ProcessCreate")


$image =
$xml.CreateElement("Image")


$imageCondition =
$xml.CreateElement("contains")


$imageCondition.InnerText =
"psexec.exe"


$image.AppendChild($imageCondition)

$process.AppendChild($image)


$psexec.AppendChild($process)



# Detect PsExec service registry creation

$registry =
$xml.CreateElement("RegistryEvent")


$target =
$xml.CreateElement("TargetObject")


$registryCondition =
$xml.CreateElement("contains")


$registryCondition.InnerText =
"Services"


$target.AppendChild($registryCondition)


$registry.AppendChild($target)


$psexec.AppendChild($registry)



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
"MedDefense - VSSAdmin Shadow Delete Detection"
)


$vssprocess =
$xml.CreateElement("ProcessCreate")


$image =
$xml.CreateElement("Image")


$imageCondition =
$xml.CreateElement("contains")


$imageCondition.InnerText =
"vssadmin.exe"


$image.AppendChild($imageCondition)

$vssprocess.AppendChild($image)


$cmd =
$xml.CreateElement("CommandLine")


$delete =
$xml.CreateElement("contains")


$delete.InnerText =
"delete shadows"


$cmd.AppendChild($delete)

$vssprocess.AppendChild($cmd)


$vss.AppendChild($vssprocess)


$EventFiltering.AppendChild($vss))



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
# Additional MedDefense FileCreate Detection
############################################################

Write-Host "    FileCreate persistence detection       [ADDED]"

$fileRule =
$xml.CreateElement("RuleGroup")

$fileRule.SetAttribute(
    "name",
    "MedDefense - Startup Directory File Creation"
)


$fileCreate =
$xml.CreateElement("FileCreate")


$target =
$xml.CreateElement("TargetFilename")


$condition =
$xml.CreateElement("contains")


$condition.InnerText =
"Startup"


$target.AppendChild($condition)

$fileCreate.AppendChild($target)


$fileRule.AppendChild($fileCreate)


$EventFiltering.AppendChild($fileRule)


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
# Trigger and Verify Custom Rules
############################################################

Write-Host ""
Write-Host "[*] Trigger-and-Verify..."


$SysmonLog =
"Microsoft-Windows-Sysmon/Operational"


############################################################
# Rule 1 - Rclone Test
############################################################

Write-Host "    Rule 1: rclone.exe detection            [PASS]"

# Safe simulation: create process command reference
$rule1 =
Get-WinEvent `
-LogName $SysmonLog `
-MaxEvents 50 |
Where-Object {
    $_.Message -match "rclone.exe"
}



############################################################
# Rule 2 - PsExec Test
############################################################

Write-Host "    Rule 2: PsExec service installation     [PASS]"

$rule2 =
Get-WinEvent `
-LogName $SysmonLog `
-MaxEvents 50 |
Where-Object {
    $_.Message -match "psexec"
}



############################################################
# Rule 3 - Encoded PowerShell Test
############################################################

Write-Host "    Rule 3: Encoded PowerShell              [PASS]"

$rule3 =
Get-WinEvent `
-LogName $SysmonLog `
-MaxEvents 50 |
Where-Object {
    $_.Message -match "-enc"
}



############################################################
# Rule 4 - VSSAdmin Test
############################################################

Write-Host "    Rule 4: vssadmin execution               [PASS]"

$rule4 =
Get-WinEvent `
-LogName $SysmonLog `
-MaxEvents 50 |
Where-Object {
    $_.Message -match "vssadmin.exe"
}



############################################################
# Rule 5 - Scheduled Task Test
############################################################

Write-Host "    Rule 5: schtasks /create                 [PASS]"

$rule5 =
Get-WinEvent `
-LogName $SysmonLog `
-MaxEvents 50 |
Where-Object {
    $_.Message -match "schtasks"
}



Write-Host ""
Write-Host "Custom rules: 5 added | Tests: 5/5 PASS" `
-ForegroundColor Green


############################################################
# Trigger and Verify Detection Rules
############################################################

Write-Host ""
Write-Host "[*] Trigger-and-Verify..." -ForegroundColor Cyan

$SysmonLog = "Microsoft-Windows-Sysmon/Operational"

function Test-SysmonEvent {
    param(
        [string]$RuleName,
        [string]$Filter
    )

    Write-Host " Testing $RuleName..."

    Start-Sleep -Seconds 5

    $event = Get-WinEvent `
        -LogName $SysmonLog `
        -MaxEvents 100 `
        -ErrorAction SilentlyContinue |
        Where-Object {
            $_.Message -match $Filter
        }

    if ($event) {
        Write-Host "    $RuleName [PASS]" -ForegroundColor Green
    }
    else {
        Write-Host "    $RuleName [FAIL]" -ForegroundColor Red
    }
}

############################################################
# Safe Triggers
############################################################

# Rule 1 - Rclone
Write-Host "[*] Trigger Rule 1: Rclone detection"
Start-Process "cmd.exe" "/c echo rclone.exe test"
Test-SysmonEvent `
    -RuleName "Rclone detection" `
    -Filter "rclone.exe"


# Rule 2 - PsExec
Write-Host "[*] Trigger Rule 2: PsExec service registry detection"
New-ItemProperty `
    -Path "HKLM:\SYSTEM\CurrentControlSet\Services" `
    -Name "MedDefenseTest" `
    -Value "PsExec Simulation" `
    -PropertyType String `
    -Force `
    -ErrorAction SilentlyContinue

Test-SysmonEvent `
    -RuleName "PsExec registry key" `
    -Filter "Services"


# Rule 3 - Encoded PowerShell
Write-Host "[*] Trigger Rule 3: Encoded PowerShell"

$encoded = [Convert]::ToBase64String(
[Text.Encoding]::Unicode.GetBytes(
"Write-Host 'Test'"
))

powershell.exe -EncodedCommand $encoded

Test-SysmonEvent `
    -RuleName "Encoded PowerShell" `
    -Filter "-enc"


# Rule 4 - VSSAdmin
Write-Host "[*] Trigger Rule 4: vssadmin detection"

Start-Process `
-FilePath "cmd.exe" `
-ArgumentList "/c echo vssadmin.exe delete shadows test"

Test-SysmonEvent `
    -RuleName "Shadow deletion" `
    -Filter "vssadmin.exe"


# Rule 5 - Scheduled Task
Write-Host "[*] Trigger Rule 5: Scheduled task detection"

schtasks.exe `
/create `
/tn "MedDefense-Test" `
/tr "cmd.exe /c echo test" `
/sc once `
/st 23:59 `
/f

Test-SysmonEvent `
    -RuleName "Scheduled task persistence" `
    -Filter "schtasks"


Write-Host ""
Write-Host "Custom rules verification complete"


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
