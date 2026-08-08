```powershell
#!/usr/bin/env pwsh

# Name: 9-windows_attack_sim.ps1
# Purpose: Execute a controlled attacker simulation and record ground truth telemetry.
# Author: Hafidh Juma
# Project: MedDefense Endpoint Telemetry Engineering

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

##############################################################
# Configuration
##############################################################

$TestUser = "support_update"
$TestPassword = ConvertTo-SecureString "MedDefense-Test-2026!" -AsPlainText -Force
$GroundTruthFile = Join-Path $PSScriptRoot "windows_attack_log.json"
$StartupDirectory = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
$StartupFile = Join-Path $StartupDirectory "meddefense_telemetry_test.txt"
$ScheduledTaskName = "MedDefense-Telemetry-Test"

$GroundTruth = @()

##############################################################
# Helper Functions
##############################################################

function Get-UtcTimestamp {
    return (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
}

function Add-GroundTruth {
    param (
        [int]$ActionNumber,
        [string]$Description,
        [string]$ExpectedDetectionSource,
        [string]$MitreTechnique,
        [string]$Timestamp
    )

    $script:GroundTruth += [PSCustomObject]@{
        action_number = $ActionNumber
        description = $Description
        timestamp = $Timestamp
        expected_detection_source = $ExpectedDetectionSource
        mitre_attack_technique = $MitreTechnique
    }
}

##############################################################
# Administrator Check
##############################################################

$CurrentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
$Principal = New-Object Security.Principal.WindowsPrincipal($CurrentIdentity)

if (-not $Principal.IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)) {
    Write-Host "[!] Run this script as Administrator."
    exit 1
}

##############################################################
# Simulation Start
##############################################################

Write-Host "[*] Running Windows attacker simulation..."

try {

    ##########################################################
    # 1. Create Local User
    ##########################################################

    $Timestamp = Get-UtcTimestamp

    Write-Host "    [1/6] Creating local user '$TestUser'... $Timestamp"

    $ExistingUser = Get-LocalUser `
        -Name $TestUser `
        -ErrorAction SilentlyContinue

    if ($null -ne $ExistingUser) {
        Remove-LocalUser `
            -Name $TestUser `
            -ErrorAction SilentlyContinue
    }

    New-LocalUser `
        -Name $TestUser `
        -Password $TestPassword `
        -Description "MedDefense controlled telemetry test account" `
        -AccountNeverExpires | Out-Null

    Add-GroundTruth `
        -ActionNumber 1 `
        -Description "Created local user support_update" `
        -ExpectedDetectionSource "Security Event ID 4720" `
        -MitreTechnique "T1136.001 - Create Account: Local Account" `
        -Timestamp $Timestamp

    ##########################################################
    # 2. Add User to Administrators
    ##########################################################

    $Timestamp = Get-UtcTimestamp

    Write-Host "    [2/6] Adding to Administrators group... $Timestamp"

    Add-LocalGroupMember `
        -Group "Administrators" `
        -Member $TestUser

    Add-GroundTruth `
        -ActionNumber 2 `
        -Description "Added support_update to local Administrators group" `
        -ExpectedDetectionSource "Security Event ID 4732" `
        -MitreTechnique "T1098 - Account Manipulation" `
        -Timestamp $Timestamp

    ##########################################################
    # 3. Encoded PowerShell
    ##########################################################

    $Timestamp = Get-UtcTimestamp

    Write-Host "    [3/6] Running encoded PowerShell... $Timestamp"

    $Payload = 'Write-Host "C2 beacon"'

    $EncodedCommand = [Convert]::ToBase64String(
        [Text.Encoding]::Unicode.GetBytes($Payload)
    )

    # Explicit -enc is intentional for telemetry validation.
    powershell.exe -NoProfile -enc $EncodedCommand

    Add-GroundTruth `
        -ActionNumber 3 `
        -Description "Executed harmless encoded PowerShell command" `
        -ExpectedDetectionSource "Sysmon Event ID 1; PowerShell Event ID 4104" `
        -MitreTechnique "T1059.001 - PowerShell" `
        -Timestamp $Timestamp

    ##########################################################
    # 4. Scheduled Task Persistence
    ##########################################################

    $Timestamp = Get-UtcTimestamp

    Write-Host "    [4/6] Creating scheduled task... $Timestamp"

    schtasks.exe /create `
        /tn $ScheduledTaskName `
        /tr "cmd.exe /c exit" `
        /sc once `
        /st 23:59 `
        /f | Out-Null

    Add-GroundTruth `
        -ActionNumber 4 `
        -Description "Created scheduled task for persistence simulation" `
        -ExpectedDetectionSource "Security Event ID 4698; Sysmon Event ID 1" `
        -MitreTechnique "T1053.005 - Scheduled Task/Job: Scheduled Task" `
        -Timestamp $Timestamp

    ##########################################################
    # 5. Outbound Network Connection
    ##########################################################

    $Timestamp = Get-UtcTimestamp

    Write-Host "    [5/6] Outbound network connection... $Timestamp"

    Test-NetConnection `
        -ComputerName "1.1.1.1" `
        -Port 443 `
        -InformationLevel Quiet | Out-Null

    Add-GroundTruth `
        -ActionNumber 5 `
        -Description "Initiated outbound TCP connection to safe external IP" `
        -ExpectedDetectionSource "Sysmon Event ID 3" `
        -MitreTechnique "T1071 - Application Layer Protocol" `
        -Timestamp $Timestamp

    ##########################################################
    # 6. Startup File
    ##########################################################

    $Timestamp = Get-UtcTimestamp

    Write-Host "    [6/6] Dropping file in Startup... $Timestamp"

    if (-not (Test-Path $StartupDirectory)) {
        New-Item `
            -Path $StartupDirectory `
            -ItemType Directory `
            -Force | Out-Null
    }

    Set-Content `
        -Path $StartupFile `
        -Value "MedDefense telemetry validation test" `
        -Encoding UTF8

    Add-GroundTruth `
        -ActionNumber 6 `
        -Description "Dropped test file in Windows Startup directory" `
        -ExpectedDetectionSource "Sysmon Event ID 11" `
        -MitreTechnique "T1547.001 - Registry Run Keys / Startup Folder" `
        -Timestamp $Timestamp

    ##############################################################
    # Write Ground Truth
    ##############################################################

    $GroundTruth |
        ConvertTo-Json -Depth 5 |
        Set-Content `
            -Path $GroundTruthFile `
            -Encoding UTF8

    Write-Host "[*] Cleaning up artifacts..."

}
finally {

    ##############################################################
    # Cleanup
    ##############################################################

    if (Get-ScheduledTask `
        -TaskName $ScheduledTaskName `
        -ErrorAction SilentlyContinue) {

        schtasks.exe /delete `
            /tn $ScheduledTaskName `
            /f | Out-Null
    }

    if (Test-Path $StartupFile) {
        Remove-Item `
            -Path $StartupFile `
            -Force `
            -ErrorAction SilentlyContinue
    }

    $ExistingUser = Get-LocalUser `
        -Name $TestUser `
        -ErrorAction SilentlyContinue

    if ($null -ne $ExistingUser) {
        Remove-LocalUser `
            -Name $TestUser `
            -ErrorAction SilentlyContinue
    }

    Write-Host "    User removed, task deleted, file removed [CLEAN]"
}

##############################################################
# Final Output
##############################################################

Write-Host "Actions executed: $($GroundTruth.Count)"
Write-Host "Ground truth saved to: $GroundTruthFile"
```
