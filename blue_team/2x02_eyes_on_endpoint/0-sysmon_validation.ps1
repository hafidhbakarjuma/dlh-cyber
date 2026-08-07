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

        # Log event timestamp
        $Event | Add-Member `
            -MemberType NoteProperty `
            -Name Timestamp `
            -Value $Event.TimeCreated `
            -Force

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
# Test 2: Network Connection
##############################################################

Write-Host "    [2/5] Network connection (Event ID 3)..."

Test-NetConnection 1.1.1.1 -Port 443 | Out-Null

$Event = Wait-SysmonEvent -EventID 3 -SearchText "1.1.1.1"

if (
    $Event -and
    $Event.Message -match "DestinationIp" -and
    $Event.Message -match "DestinationPort" -and
    $Event.Message -match "Image"
) {
    Report-Result `
        "Network Connection" `
        $true `
        "Outbound TCP -> Sysmon EID 3 captured, DestinationIp/DestinationPort/Image present"
}
else {
    Report-Result `
        "Network Connection" `
        $false `
        "Sysmon Event ID 3 missing network details"
}

##############################################################
# Test 3: File Creation
##############################################################

Write-Host "    [3/5] File creation (Event ID 11)..."

$TestFile = "C:\Windows\Temp\sysmon_validation.txt"

New-Item -ItemType File -Path $TestFile -Force | Out-Null

$Event = Wait-SysmonEvent -EventID 11 -SearchText "sysmon_validation.txt"

if (
    $Event -and
    $Event.Message -match "TargetFilename" -and
    $Event.Message -match "sysmon_validation.txt"
) {
    Report-Result `
        "File Creation" `
        $true `
        "$TestFile -> Sysmon EID 11 captured, TargetFilename present"
}
else {
    Report-Result `
        "File Creation" `
        $false `
        "Sysmon Event ID 11 missing TargetFilename details"
}
##############################################################
# Test 4: Registry Modification
##############################################################

Write-Host "    [4/5] Registry modification (Event ID 13)..."

$RegKey = "HKCU:\Software\SysmonTest"

if (!(Test-Path $RegKey)) {
    New-Item $RegKey | Out-Null
}

New-ItemProperty `
    -Path $RegKey `
    -Name "SysmonTest" `
    -Value "TelemetryValidation" `
    -PropertyType String `
    -Force | Out-Null

$Event = Wait-SysmonEvent -EventID 13 -SearchText "SysmonTest"

if (
    $Event -and
    $Event.Message -match "TargetObject" -and
    $Event.Message -match "SysmonTest"
) {
    Report-Result `
        "Registry Modification" `
        $true `
        "HKCU\Software\SysmonTest -> Sysmon EID 13 captured, registry details present"
}
else {
    Report-Result `
        "Registry Modification" `
        $false `
        "Sysmon Event ID 13 missing registry details"
}

##############################################################
# Test 5: DNS Query
##############################################################

Write-Host "    [5/5] DNS query (Event ID 22)..."

# Generate DNS telemetry using both native tools
nslookup example.com | Out-Null

Resolve-DnsName example.com | Out-Null

$Event = Wait-SysmonEvent -EventID 22 -SearchText "example.com"

if (
    $Event -and
    $Event.Message -match "QueryName" -and
    $Event.Message -match "example.com"
) {
    Report-Result `
        "DNS Query" `
        $true `
        "nslookup/Resolve-DnsName example.com -> Sysmon EID 22 captured, QueryName present"
}
else {
    Report-Result `
        "DNS Query" `
        $false `
        "Sysmon Event ID 22 missing DNS details"
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
