<#
name:
    0-sysmon_validation.ps1

    purpose: Validates that Sysmon is correctly capturing critical security telemetry
    by generating controlled events and verifying expected Sysmon Event IDs.

author:
    Hafidh Juma

project:
    MedDefense Endpoint Telemetry Engineering
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$SysmonLog = "Microsoft-Windows-Sysmon/Operational"

$Results = @()
$Captured = 0
$Missed = 0

Write-Host "[*] Running Sysmon telemetry validation..." -ForegroundColor Cyan

function Wait-SysmonEvent {
    param(
        [int]$EventID,
        [string]$SearchText,
        [int]$Timeout = 15
    )

    $Start = Get-Date

    while ((Get-Date) -lt $Start.AddSeconds($Timeout)) {

        $Event = Get-WinEvent -LogName $SysmonLog -MaxEvents 80 |
            Where-Object {
                $_.Id -eq $EventID -and
                $_.TimeCreated -ge $Start.AddSeconds(-5) -and
                $_.Message -match [regex]::Escape($SearchText)
            } |
            Select-Object -First 1

        if ($Event) {
            return $Event
        }

        Start-Sleep -Milliseconds 500
    }

    return $null
}

function Report-Result {

    param(
        [string]$Name,
        [bool]$Success,
        [string]$Message
    )

    if ($Success) {
        Write-Host "          $Message   [PASS]" -ForegroundColor Green
        $script:Captured++
    }
    else {
        Write-Host "          $Message   [FAIL]" -ForegroundColor Red
        $script:Missed++
    }

    $script:Results += [PSCustomObject]@{
        Test      = $Name
        Success   = $Success
        Timestamp = Get-Date
        Detail    = $Message
    }
}

##############################################################
# Test 1: Process Creation
##############################################################

Write-Host "    [1/5] Process creation (Event ID 1)..."

Start-Process cmd.exe "/c whoami" -Wait -NoNewWindow

$Event = Wait-SysmonEvent -EventID 1 -SearchText "whoami"

if (
    $Event -and
    $Event.Message -match "CommandLine" -and
    $Event.Message -match "cmd.exe" -and
    $Event.Message -match "whoami"
) {
    Report-Result `
        "Process Creation" `
        $true `
        "cmd.exe /c whoami -> Sysmon EID 1 captured, CommandLine present"
}
else {
    Report-Result `
        "Process Creation" `
        $false `
        "Sysmon Event ID 1 missing CommandLine details"
}
##############################################################
# Test 2
##############################################################

Write-Host "    [2/5] Network connection (Event ID 3)..."

Test-NetConnection 1.1.1.1 -Port 443 | Out-Null

$Event = Wait-SysmonEvent -EventID 3 -SearchText "1.1.1.1"

if ($Event -and $Event.Message -match "DestinationPort") {
    Report-Result "Network Connection" $true "Outbound TCP -> Sysmon EID 3 captured, dest IP/port present"
}
else {
    Report-Result "Network Connection" $false "Sysmon Event ID 3 missing"
}

##############################################################
# Test 3
##############################################################

Write-Host "    [3/5] File creation (Event ID 11)..."

$TestFile = "C:\Windows\Temp\sysmon_validation.txt"

New-Item -ItemType File -Path $TestFile -Force | Out-Null

$Event = Wait-SysmonEvent -EventID 11 -SearchText "sysmon_validation.txt"

if ($Event) {
    Report-Result "File Creation" $true "$TestFile -> Sysmon EID 11 captured"
}
else {
    Report-Result "File Creation" $false "Sysmon Event ID 11 missing"
}

##############################################################
# Test 4
##############################################################

Write-Host "    [4/5] Registry modification (Event ID 13)..."

$RegKey = "HKCU:\Software\SysmonValidation"

if (!(Test-Path $RegKey)) {
    New-Item $RegKey | Out-Null
}

New-ItemProperty `
    -Path $RegKey `
    -Name TestValue `
    -Value "Telemetry" `
    -PropertyType String `
    -Force | Out-Null

$Event = Wait-SysmonEvent -EventID 13 -SearchText "SysmonValidation"

if ($Event) {
    Report-Result "Registry Modification" $true "HKCU\\Software\\SysmonValidation -> Sysmon EID 13 captured"
}
else {
    Report-Result "Registry Modification" $false "Sysmon Event ID 13 missing"
}

##############################################################
# Test 5
##############################################################

Write-Host "    [5/5] DNS query (Event ID 22)..."

Resolve-DnsName example.com | Out-Null

$Event = Wait-SysmonEvent -EventID 22 -SearchText "example.com"

if ($Event) {
    Report-Result "DNS Query" $true "Resolve example.com -> Sysmon EID 22 captured"
}
else {
    Report-Result "DNS Query" $false "Sysmon Event ID 22 missing"
}

##############################################################
# Cleanup
##############################################################

Write-Host "[*] Cleanup: removing test artifacts..."

if (Test-Path $TestFile) {
    Remove-Item $TestFile -Force
}

if (Test-Path $RegKey) {
    Remove-Item $RegKey -Recurse -Force
}

##############################################################
# Summary
##############################################################

Write-Host ""
Write-Host "Actions tested: $($Captured + $Missed) | Captured: $Captured | Missed: $Missed" -ForegroundColor Cyan

##############################################################
# Export Results
##############################################################

$Results | Export-Csv `
    -Path ".\sysmon_validation_results.csv" `
    -NoTypeInformation

Write-Host "Results exported to sysmon_validation_results.csv"
