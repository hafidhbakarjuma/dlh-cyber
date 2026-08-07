<#
name:
4-windows_telemetry_quality.ps1

purpose:
Analyzes exported Windows telemetry quality by measuring event distribution,
channel coverage, time gaps, field completeness and produces a quality
assessment report for SOC analyst handoff.

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

$InputFile = ".\windows_events_export.json"

$OutputFile = ".\windows_telemetry_quality.json"


if (!(Test-Path $InputFile)) {

    Write-Host "[!] Missing telemetry export: $InputFile" `
    -ForegroundColor Red

    exit 1
}


Write-Host "[*] Analyzing windows_events_export.json..." `
-ForegroundColor Cyan



##############################################################

# Load Events

##############################################################

$Events = Get-Content $InputFile -Raw |
ConvertFrom-Json


$TotalEvents = $Events.Count



##############################################################

# Event Distribution

##############################################################

$EventDistribution = $Events |
Group-Object event_id |
ForEach-Object {


    [PSCustomObject]@{

        event_id = $_.Name

        count = $_.Count

        percentage =
        [math]::Round(
            (($_.Count / $TotalEvents) * 100),
            2
        )

    }

}



##############################################################

# Channel Distribution

##############################################################

$ChannelDistribution = $Events |
Group-Object source_type |
ForEach-Object {


    [PSCustomObject]@{

        channel = $_.Name

        count = $_.Count

        percentage =
        [math]::Round(
            (($_.Count / $TotalEvents) * 100),
            2
        )

    }

}



##############################################################

# Time Coverage

##############################################################

$Times = $Events |
ForEach-Object {

    [datetime]$_.timestamp

}


$StartHour =
$Times |
Sort-Object |
Select-Object -First 1


$EndHour =
$Times |
Sort-Object |
Select-Object -Last 1



$HourBuckets = $Times |
ForEach-Object {

    $_.ToString("yyyy-MM-dd HH")

} |
Group-Object



$HoursWithEvents =
$HourBuckets.Count



$TotalHours =
[math]::Ceiling(
    ($EndHour - $StartHour).TotalHours
)


if ($TotalHours -lt 1) {

    $TotalHours = 1

}



##############################################################

# Gap Detection

##############################################################

$SortedTimes =
$Times |
Sort-Object



$Gaps = @()



for ($i = 1; $i -lt $SortedTimes.Count; $i++) {


    $GapMinutes =
    ($SortedTimes[$i] -
    $SortedTimes[$i-1]).TotalMinutes



    if ($GapMinutes -gt 30) {


        $Gaps += [PSCustomObject]@{

            start =
            $SortedTimes[$i-1]


            end =
            $SortedTimes[$i]


            minutes =
            [math]::Round($GapMinutes)

        }

    }

}



$LargestGap = 0


if ($Gaps.Count -gt 0) {

    $LargestGap =
    ($Gaps.minutes |
    Measure-Object -Maximum).Maximum

}



##############################################################

# Field Completeness

##############################################################

function Get-Completeness {


param(

    [array]$Data,

    [string]$Field

)



if ($Data.Count -eq 0) {

    return 100

}



$Valid =
$Data |
Where-Object {

    $_.$Field -and
    $_.$Field.ToString().Length -gt 0

}



return [math]::Round(
    (($Valid.Count / $Data.Count) * 100),
    2
)


}



##############################################################

# Process Event Completeness

##############################################################

$ProcessEvents =
$Events |
Where-Object {


    $_.event_id -eq 4688 -or
    $_.event_id -eq 1


}



$CommandLineCompleteness =
Get-Completeness `
-Data $ProcessEvents `
-Field "command_line"



##############################################################

# Logon Source IP Completeness

##############################################################

$LogonEvents =
$Events |
Where-Object {


    $_.event_id -eq 4624 -or
    $_.event_id -eq 4625


}



$SourceIPCompleteness =
Get-Completeness `
-Data $LogonEvents `
-Field "source_ip"



##############################################################

# PowerShell Script Completeness

##############################################################

$PowerShellEvents =
$Events |
Where-Object {


    $_.event_id -eq 4104


}



$ScriptBlockCompleteness =
Get-Completeness `
-Data $PowerShellEvents `
-Field "script_block"



##############################################################

# Quality Score

##############################################################

$QualityScore =

(
    ($CommandLineCompleteness * 0.30) +

    ($SourceIPCompleteness * 0.30) +

    ($ScriptBlockCompleteness * 0.20) +

    (
        (($HoursWithEvents / $TotalHours) * 100)
        * 0.20
    )

)



$QualityScore =
[math]::Round(
    $QualityScore,
    2
)



if ($QualityScore -ge 90) {


    $Assessment = "good"


}

elseif ($QualityScore -ge 70) {


    $Assessment = "acceptable"


}

else {


    $Assessment = "poor"


}



##############################################################

# Generate Report

##############################################################

$Report = [ordered]@{


    timestamp =
    Get-Date


    total_events =
    $TotalEvents


    event_distribution =
    $EventDistribution


    channel_distribution =
    $ChannelDistribution


    time_coverage = @{

        hours_with_events =
        $HoursWithEvents


        total_hours =
        $TotalHours


        largest_gap_minutes =
        $LargestGap

    }


    gaps =
    $Gaps



    field_completeness = @{


        command_line =
        "$CommandLineCompleteness%"


        source_ip =
        "$SourceIPCompleteness%"


        script_block =
        "$ScriptBlockCompleteness%"


    }



    quality_score =
    $QualityScore



    assessment =
    $Assessment


}



$Report |
ConvertTo-Json -Depth 10 |
Out-File `
$OutputFile `
-Encoding UTF8



##############################################################

# Summary

##############################################################

Write-Host ""

Write-Host "Total events: $TotalEvents"

Write-Host "Hours with events: $HoursWithEvents/$TotalHours"

Write-Host "Largest gap: $LargestGap minutes"

Write-Host "Command-line completeness: $CommandLineCompleteness%"

Write-Host "Source IP completeness: $SourceIPCompleteness%"

Write-Host "Script block completeness: $ScriptBlockCompleteness%"

Write-Host ""

Write-Host `
"Quality score: $QualityScore% ($Assessment)" `
-ForegroundColor Green


Write-Host ""

Write-Host `
"Report saved to: $OutputFile"
