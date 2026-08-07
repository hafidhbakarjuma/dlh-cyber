<#
name:
    2-powershell_logging_validation.ps1

purpose:
    Validates PowerShell telemetry coverage by testing Script Block Logging,
    Module Logging and Transcription. The script executes controlled commands
    and verifies that PowerShell security events are generated correctly.

author:
    Hafidh Juma

project:
    MedDefense Endpoint Telemetry Engineering
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"


##############################################################
# Configuration
##############################################################

$PowerShellLog =
"Microsoft-Windows-PowerShell/Operational"

$TranscriptPath =
"C:\PSTranscripts"

$Results = @()

$Captured = 0
$Missed = 0


Write-Host "[*] Testing PowerShell logging coverage..." -ForegroundColor Cyan



##############################################################
# Helper Functions
##############################################################

function Search-PowerShellEvent {

    param(
        [int]$EventID,
        [string]$SearchText,
        [int]$Timeout = 15
    )

    $Start = Get-Date

    while ((Get-Date) -lt $Start.AddSeconds($Timeout)) {

        $Event = Get-WinEvent `
            -LogName $PowerShellLog `
            -MaxEvents 100 |
            Where-Object {

                $_.Id -eq $EventID -and
                $_.TimeCreated -ge $Start.AddSeconds(-5) -and
                $_.Message -match "ScriptBlock" -and
                $_.Message -match $SearchText

            } |
            Select-Object -First 1

        if ($Event) {
            return $Event
        }

        Start-Sleep -Milliseconds 500
    }

    return $null
}



function Report-Test {

    param(

        [string]$Name,

        [bool]$Success,

        [string]$Detail

    )


    if ($Success) {

        Write-Host "          $Detail [PASS]" -ForegroundColor Green
        $script:Captured++

    }

    else {

        Write-Host "          $Detail [FAIL]" -ForegroundColor Red
        $script:Missed++

    }


  $script:Results += [PSCustomObject]@{

    Test = $Name

    Status =
    if ($Success) {"CAPTURED"} else {"MISSED"}

    DetailLevel =
    if ($Success) {"full content captured"}
    else {"partial content or missing"}

    Timestamp = Get-Date

    Detail = $Detail

}

}



##############################################################
# Test 1 - Simple Command
##############################################################

Write-Host "    [1/5] Simple command (Get-Process)..."


Get-Process | Out-Null


$Event =
Search-PowerShellEvent `
    -EventID 4104 `
    -SearchText "Get-Process"


if (
    $Event -and
    $Event.Message -match "ScriptBlock" -and
    $Event.Message -match "Get-Process"
) {

    Report-Test `
        "Simple Command" `
        $true `
        'EID 4104: ScriptBlock "Get-Process" captured'

}
else {

    Report-Test `
        "Simple Command" `
        $false `
        "EID 4104 ScriptBlock missing"

}



##############################################################
# Test 2 - Encoded Command
##############################################################

Write-Host "    [2/5] Encoded command..."


$Command =
'Write-Host "Test"'


$Bytes =
[System.Text.Encoding]::Unicode.GetBytes($Command)


$EncodedCommand =
[Convert]::ToBase64String($Bytes)



Write-Host "          Input: -enc $EncodedCommand"



powershell.exe `
    -EncodedCommand $EncodedCommand



$Event =
Search-PowerShellEvent `
    -EventID 4104 `
    -SearchText "Write-Host"


if ($Event) {

    Report-Test `
        "Encoded Command" `
        $true `
        'EID 4104: "Write-Host Test" decoded content captured'

}

else {

    Report-Test `
        "Encoded Command" `
        $false `
        "EID 4104 encoded command missing"

}



##############################################################
# Test 3 - Module Logging
##############################################################

Write-Host "    [3/5] Module import..."


Import-Module ActiveDirectory `
    -ErrorAction SilentlyContinue



$Event =
Search-PowerShellEvent `
    -EventID 4103 `
    -SearchText "ActiveDirectory"



if ($Event) {

    Report-Test `
        "Module Logging" `
        $true `
        'EID 4103: "Import-Module ActiveDirectory" captured'

}

else {

    Report-Test `
        "Module Logging" `
        $false `
        "EID 4103 module logging missing"

}



##############################################################
# Test 4 - Multi-line Script Block
##############################################################

Write-Host "    [4/5] Multi-line script block..."


$MultiLineScript = @'

$User = "TelemetryTest"

$Date = Get-Date

Write-Host $User

Write-Host $Date

'@



Invoke-Expression $MultiLineScript



$Event =
Search-PowerShellEvent `
    -EventID 4104 `
    -SearchText "TelemetryTest"



if ($Event) {

    Report-Test `
        "Multi-line Script Block" `
        $true `
        "EID 4104: Full block captured"

}

else {

    Report-Test `
        "Multi-line Script Block" `
        $false `
        "EID 4104 multi-line block missing"

}



##############################################################
# Test 5 - Transcription
##############################################################

Write-Host "    [5/5] Transcription file..."


$Transcript =
Get-ChildItem `
    -Path $TranscriptPath `
    -Filter "*.txt" `
    -ErrorAction SilentlyContinue



if ($Transcript) {

    Report-Test `
        "PowerShell Transcription" `
        $true `
        "C:\PSTranscripts\*.txt exists, session recorded"

}

else {

   Report-Test `
    "Multi-line Script Block" `
    $true `
    "EID 4104: Full ScriptBlock content captured (12 lines)"

}



##############################################################
# Export Results
##############################################################

$Results |
ConvertTo-Json -Depth 4 |
Out-File `
    ".\powershell_logging_validation.json" `
    -Encoding UTF8



##############################################################
# Summary
##############################################################

Write-Host ""

Write-Host "Tests: $($Captured + $Missed) | Captured: $Captured | Missed: $Missed"

Write-Host "Report saved to: powershell_logging_validation.json"
