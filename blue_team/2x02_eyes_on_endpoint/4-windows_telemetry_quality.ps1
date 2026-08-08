```powershell
<#
name:
4-windows_telemetry_quality.ps1

purpose:
Analyzes exported Windows telemetry quality by measuring event distribution,
channel coverage, events per hour, time gaps, field completeness and produces
a quality assessment report for SOC analyst handoff.

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

$GapThresholdMinutes = 30

if (!(Test-Path -LiteralPath $InputFile)) {
    Write-Host "[!] Missing telemetry export: $InputFile" -ForegroundColor Red
    exit 1
}

Write-Host "[*] Analyzing windows_events_export.json..." -ForegroundColor Cyan

##############################################################
# Load Events
##############################################################

try {
    $Events = @(Get-Content -LiteralPath $InputFile -Raw | ConvertFrom-Json)
}
catch {
    Write-Host "[!] Unable to parse $InputFile" -ForegroundColor Red
    exit 1
}

$TotalEvents = $Events.Count

if ($TotalEvents -eq 0) {
    Write-Host "[!] No events found in telemetry export." -ForegroundColor Red
    exit 1
}

##############################################################
# Event Distribution
##############################################################

$EventDistribution = @(
    $Events |
    Group-Object -Property event_id |
    ForEach-Object {
        [PSCustomObject]@{
            event_id = $_.Name
            count = $_.Count
            percentage = [math]::Round(
                (($_.Count / $TotalEvents) * 100),
                2
            )
        }
    } |
    Sort-Object -Property count -Descending
)

##############################################################
# Channel Distribution
##############################################################

$ChannelDistribution = @(
    $Events |
    Group-Object -Property source_type |
    ForEach-Object {
        [PSCustomObject]@{
            channel = $_.Name
            count = $_.Count
            percentage = [math]::Round(
                (($_.Count / $TotalEvents) * 100),
                2
            )
        }
    } |
    Sort-Object -Property count -Descending
)

##############################################################
# Time Coverage - Events Per Hour
##############################################################

$HourlyDistribution = @()

$SortedTimestamps = @(
    $Events |
    ForEach-Object {
        try {
            ([datetime]$_.timestamp).ToUniversalTime()
        }
        catch {
            $null
        }
    } |
    Where-Object {
        $null -ne $_
    } |
    Sort-Object
)

if ($SortedTimestamps.Count -gt 0) {

    $StartHour = $SortedTimestamps[0].Date.AddHours(
        $SortedTimestamps[0].Hour
    )

    $EndHour = $SortedTimestamps[-1].Date.AddHours(
        $SortedTimestamps[-1].Hour
    )

    # Calculate events per hour.
    for (
        $Hour = $StartHour;
        $Hour -le $EndHour;
        $Hour = $Hour.AddHours(1)
    ) {

        $NextHour = $Hour.AddHours(1)

        $Count = @(
            $Events |
            Where-Object {
                $Timestamp = ([datetime]$_.timestamp).ToUniversalTime()

                $Timestamp -ge $Hour -and
                $Timestamp -lt $NextHour
            }
        ).Count

        $HourlyDistribution += [PSCustomObject]@{
            hour = $Hour.ToString("yyyy-MM-dd HH:00")
            events_per_hour = $Count
            event_count = $Count
        }
    }
}

# Hours with events.
$HoursWithEvents = @(
    $HourlyDistribution |
    Where-Object {
        $_.events_per_hour -gt 0
    }
)

# Hours without events.
$HoursWithoutEvents = @(
    $HourlyDistribution |
    Where-Object {
        $_.events_per_hour -eq 0
    }
)

$HoursWithEventsCount = $HoursWithEvents.Count
$HoursWithoutEventsCount = $HoursWithoutEvents.Count
$TotalHours = $HourlyDistribution.Count

##############################################################
# Gap Detection - Periods Longer Than 30 Minutes
##############################################################

# A gap longer than 30 minutes indicates a potential telemetry
# coverage or collection problem.

$SortedEvents = @(
    $Events |
    Sort-Object {
        [datetime]$_.timestamp
    }
)

$Gaps = @()

for ($i = 1; $i -lt $SortedEvents.Count; $i++) {

    $Previous = ([datetime]$SortedEvents[$i - 1].timestamp).ToUniversalTime()
    $Current = ([datetime]$SortedEvents[$i].timestamp).ToUniversalTime()

    $GapMinutes = ($Current - $Previous).TotalMinutes

    if ($GapMinutes -gt $GapThresholdMinutes) {

        $Gaps += [PSCustomObject]@{
            start = $Previous.ToString("yyyy-MM-ddTHH:mm:ssZ")
            end = $Current.ToString("yyyy-MM-ddTHH:mm:ssZ")
            duration_minutes = [math]::Round($GapMinutes, 2)
        }
    }
}

$LargestGap = 0

if ($Gaps.Count -gt 0) {
    $LargestGap = [math]::Round(
        (($Gaps | Measure-Object -Property duration_minutes -Maximum).Maximum),
        2
    )
}

##############################################################
# Field Completeness Helper
##############################################################

function Test-FieldCompleteness {

    param(
        [Parameter(Mandatory = $true)]
        [object[]]$InputEvents,

        [Parameter(Mandatory = $true)]
        [string]$FieldName
    )

    $Total = $InputEvents.Count

    if ($Total -eq 0) {
        return [PSCustomObject]@{
            field = $FieldName
            total = 0
            populated = 0
            empty = 0
            percentage = 100
        }
    }

    $Populated = @(
        $InputEvents |
        Where-Object {
            $Value = $_.$FieldName

            $null -ne $Value -and
            -not [string]::IsNullOrWhiteSpace([string]$Value)
        }
    ).Count

    $Empty = $Total - $Populated

    [PSCustomObject]@{
        field = $FieldName
        total = $Total
        populated = $Populated
        empty = $Empty
        percentage = [math]::Round(
            (($Populated / $Total) * 100),
            2
        )
    }
}

##############################################################
# Required Common Field Completeness
##############################################################

$RequiredFields = @(
    "timestamp",
    "hostname",
    "platform",
    "source_type",
    "channel",
    "event_id",
    "event_category",
    "provider",
    "raw_message"
)

$RequiredFieldCompleteness = @()

foreach ($Field in $RequiredFields) {

    $RequiredFieldCompleteness +=
        Test-FieldCompleteness `
            -InputEvents $Events `
            -FieldName $Field
}

##############################################################
# Process Event Completeness
##############################################################

$ProcessEvents = @(
    $Events |
    Where-Object {
        [int]$_.event_id -eq 4688 -or
        [int]$_.event_id -eq 1
    }
)

$CommandLineCompleteness = $null

if ($ProcessEvents.Count -gt 0) {

    $CommandLineCompleteness =
        Test-FieldCompleteness `
            -InputEvents $ProcessEvents `
            -FieldName "command_line"
}
else {

    $CommandLineCompleteness = [PSCustomObject]@{
        field = "CommandLine"
        total = 0
        populated = 0
        empty = 0
        percentage = 100
    }
}

##############################################################
# Logon Source IP Completeness
##############################################################

$LogonEvents = @(
    $Events |
    Where-Object {
        [int]$_.event_id -eq 4624 -or
        [int]$_.event_id -eq 4625
    }
)

$SourceIPCompleteness = $null

if ($LogonEvents.Count -gt 0) {

    $SourceIPCompleteness =
        Test-FieldCompleteness `
            -InputEvents $LogonEvents `
            -FieldName "source_ip"
}
else {

    $SourceIPCompleteness = [PSCustomObject]@{
        field = "SourceIP"
        total = 0
        populated = 0
        empty = 0
        percentage = 100
    }
}

##############################################################
# PowerShell Script Block Completeness
##############################################################

$PowerShellEvents = @(
    $Events |
    Where-Object {
        [int]$_.event_id -eq 4104
    }
)

$ScriptBlockCompleteness = $null

if ($PowerShellEvents.Count -gt 0) {

    # ScriptBlockText is the expected normalized field.
    # script_block is also accepted for compatibility with the
    # Windows telemetry export script.

    $ScriptBlockPopulated = @(
        $PowerShellEvents |
        Where-Object {

            $Value = $null

            if ($null -ne $_.ScriptBlockText) {
                $Value = $_.ScriptBlockText
            }
            elseif ($null -ne $_.script_block) {
                $Value = $_.script_block
            }

            $null -ne $Value -and
            -not [string]::IsNullOrWhiteSpace([string]$Value)
        }
    ).Count

    $ScriptBlockEmpty =
        $PowerShellEvents.Count - $ScriptBlockPopulated

    $ScriptBlockCompleteness = [PSCustomObject]@{
        field = "ScriptBlockText"
        total = $PowerShellEvents.Count
        populated = $ScriptBlockPopulated
        empty = $ScriptBlockEmpty
        percentage = [math]::Round(
            (($ScriptBlockPopulated / $PowerShellEvents.Count) * 100),
            2
        )
    }
}
else {

    $ScriptBlockCompleteness = [PSCustomObject]@{
        field = "ScriptBlockText"
        total = 0
        populated = 0
        empty = 0
        percentage = 100
    }
}

##############################################################
# Enriched Field Completeness
##############################################################

$EnrichedCompleteness = [ordered]@{
    CommandLine = $CommandLineCompleteness
    SourceIP = $SourceIPCompleteness
    ScriptBlockText = $ScriptBlockCompleteness
}

##############################################################
# Overall Field Completeness
##############################################################

$AllFieldPercentages = @(
    $RequiredFieldCompleteness |
    ForEach-Object {
        [double]$_.percentage
    }
)

if ($AllFieldPercentages.Count -gt 0) {

    $AverageFieldCompleteness = [math]::Round(
        (
            ($AllFieldPercentages |
            Measure-Object -Average).Average
        ),
        2
    )
}
else {
    $AverageFieldCompleteness = 0
}

##############################################################
# Quality Score
##############################################################

# Weighted quality model:
#
# 25% Event distribution
# 25% Channel coverage
# 20% Time coverage
# 30% Field completeness

# Event distribution score:
# A non-empty distribution receives full credit.
$EventDistributionScore = 100

# Channel coverage score:
# Security, Sysmon and PowerShell are expected.
$ExpectedChannels = @(
    "Security",
    "Sysmon",
    "PowerShell"
)

$PresentChannels = @(
    $Events |
    Select-Object -ExpandProperty source_type -Unique
)

$ChannelsPresent = @(
    $ExpectedChannels |
    Where-Object {
        $_ -in $PresentChannels
    }
).Count

$ChannelCoverageScore = [math]::Round(
    (($ChannelsPresent / $ExpectedChannels.Count) * 100),
    2
)

# Time coverage score.
if ($TotalHours -gt 0) {

    $TimeCoverageScore = [math]::Round(
        (($HoursWithEventsCount / $TotalHours) * 100),
        2
    )
}
else {
    $TimeCoverageScore = 0
}

# Field completeness score.
$FieldCompletenessScore = $AverageFieldCompleteness

# Weighted final score.
$QualityScore = [math]::Round(
    (
        ($EventDistributionScore * 0.25) +
        ($ChannelCoverageScore * 0.25) +
        ($TimeCoverageScore * 0.20) +
        ($FieldCompletenessScore * 0.30)
    ),
    2
)

##############################################################
# Quality Assessment
##############################################################

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
# Quality Report
##############################################################

$QualityReport = [ordered]@{

    generated_at =
        (Get-Date).ToUniversalTime().ToString(
            "yyyy-MM-ddTHH:mm:ssZ"
        )

    input_file =
        $InputFile

    total_events =
        $TotalEvents

    event_distribution =
        $EventDistribution

    channel_distribution =
        $ChannelDistribution

    time_coverage = [ordered]@{
        events_per_hour =
            $HourlyDistribution

        hours_with_events =
            $HoursWithEventsCount

        hours_without_events =
            $HoursWithoutEventsCount

        total_hours =
            $TotalHours
    }

    gap_detection = [ordered]@{
        threshold_minutes =
            $GapThresholdMinutes

        description =
            "Gaps longer than 30 minutes are potential telemetry coverage gaps."

        gaps =
            $Gaps

        gap_count =
            $Gaps.Count

        largest_gap_minutes =
            $LargestGap
    }

    field_completeness = [ordered]@{
        required_fields =
            $RequiredFieldCompleteness

        enriched_fields =
            $EnrichedCompleteness

        average_required_field_completeness =
            $AverageFieldCompleteness
    }

    quality_score = [ordered]@{
        score =
            $QualityScore

        assessment =
            $Assessment

        components = [ordered]@{
            event_distribution =
                $EventDistributionScore

            channel_coverage =
                $ChannelCoverageScore

            time_coverage =
                $TimeCoverageScore

            field_completeness =
                $FieldCompletenessScore
        }

        weights = [ordered]@{
            event_distribution = 25
            channel_coverage = 25
            time_coverage = 20
            field_completeness = 30
        }
    }
}

##############################################################
# Export Quality Report
##############################################################

$QualityReport |
ConvertTo-Json -Depth 10 |
Set-Content -LiteralPath $OutputFile -Encoding UTF8

##############################################################
# Console Summary
##############################################################

Write-Host ""
Write-Host "Total events: $TotalEvents"

Write-Host "Hours with events: $HoursWithEventsCount/$TotalHours"
Write-Host "Hours without events: $HoursWithoutEventsCount/$TotalHours"

Write-Host "Largest gap: $LargestGap minutes"

Write-Host (
    "Command-line completeness: {0}%" -f
    $CommandLineCompleteness.percentage
)

Write-Host (
    "Source IP completeness: {0}%" -f
    $SourceIPCompleteness.percentage
)

Write-Host (
    "Script block completeness: {0}%" -f
    $ScriptBlockCompleteness.percentage
)

Write-Host (
    "Quality score: {0}% ({1})" -f
    $QualityScore,
    $Assessment
)

Write-Host "Report saved to: $OutputFile" -ForegroundColor Green
```
