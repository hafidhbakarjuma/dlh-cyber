# name: 9-windows_attack_sim.ps1
# purpose: Execute controlled attacker-like actions and record ground truth telemetry.
# author: Hafidh Juma
# project: MedDefense Endpoint Telemetry Engineering

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

##############################################################
# Configuration
##############################################################

$OutputFile = ".\windows_attack_log.json"

$TestUser = "support_update"
$TestPasswordPlain = "MedDefense-Test-2026!"
$TestPassword = ConvertTo-SecureString $TestPasswordPlain -AsPlainText -Force

$TaskName = "MedDefense-Security-Test"

$StartupDir = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
$StartupFile = Join-Path $StartupDir "meddefense_test.ps1"

$SafeExternalIP = "1.1.1.1"

$GroundTruth = @()

##############################################################
# Administrator Check
##############################################################

$CurrentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
$Principal = New-Object Security.Principal.WindowsPrincipal($CurrentIdentity)

if (-not $Principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )) {

    Write-Host "[!] This script must be run as Administrator."
    exit 1
}

##############################################################
# Helper Function
##############################################################

function Get-UtcTimestamp {
    return (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
}

function Add-GroundTruth {
    param(
        [int]$ActionNumber,
        [string]$Description,
        [string]$ExpectedDetectionSource,
        [string]$MitreTechnique,
        [string]$Timestamp
    )

    $script:GroundTruth += [PSCustomObject]@{
        action_number              = $ActionNumber
        description               = $Description
        timestamp                 = $Timestamp
        expected_detection_source = $ExpectedDetectionSource
        mitre_attack_technique    = $MitreTechnique
    }
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

    if (Get-LocalUser -Name $TestUser -ErrorAction SilentlyContinue) {
        Remove-LocalUser -Name $TestUser -ErrorAction SilentlyContinue
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

    schtasks.exe /Create `
        /TN $TaskName `
        /TR "cmd.exe /c echo MedDefense telemetry test" `
        /SC ONCE `
        /ST 23:59 `
        /F | Out-Null

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
        -ComputerName $SafeExternalIP `
        -Port 443 `
        -InformationLevel Quiet `
        -WarningAction SilentlyContinue | Out-Null

    Add-GroundTruth `
        -ActionNumber 5 `
        -Description "Initiated outbound TCP connection test to 1.1.1.1:443" `
        -ExpectedDetectionSource "Sysmon Event ID 3" `
        -MitreTechnique "T1071.001 - Web Protocols: HTTP/HTTPS" `
        -Timestamp $Timestamp

    ##########################################################
    # 6. Startup File
    ##########################################################

    $Timestamp = Get-UtcTimestamp

    Write-Host "    [6/6] Dropping file in Startup... $Timestamp"

    if (-not (Test-Path $StartupDir)) {
        New-Item `
            -Path $StartupDir `
            -ItemType Directory `
            -Force | Out-Null
    }

    Set-Content `
        -Path $StartupFile `
        -Value '# MedDefense controlled telemetry test' `
        -Encoding UTF8

    Add-GroundTruth `
        -ActionNumber 6 `
        -Description "Created test file in Windows Startup directory" `
        -ExpectedDetectionSource "Sysmon Event ID 11" `
        -MitreTechnique "T1547.001 - Registry Run Keys / Startup Folder" `
        -Timestamp $Timestamp

}
finally {

    ##########################################################
    # Cleanup
    ##########################################################

    Write-Host "[*] Cleaning up artifacts..."

    # Remove scheduled task
    schtasks.exe /Delete `
        /TN $TaskName `
        /F 2>$null | Out-Null

    # Remove startup file
    if (Test-Path $StartupFile) {
        Remove-Item `
            -Path $StartupFile `
            -Force `
            -ErrorAction SilentlyContinue
    }

    # Remove test user
    if (Get-LocalUser -Name $TestUser -ErrorAction SilentlyContinue) {
        Remove-LocalUser `
            -Name $TestUser `
            -ErrorAction SilentlyContinue
    }

    Write-Host "    User removed, task deleted, file removed [CLEAN]"
}

##############################################################
# Save Ground Truth
##############################################################

$GroundTruth |
    ConvertTo-Json -Depth 5 |
    Set-Content -Path $OutputFile -Encoding UTF8

##############################################################
# Summary
##############################################################

Write-Host "Actions executed: $($GroundTruth.Count)"
Write-Host "Ground truth saved to: $OutputFile"
