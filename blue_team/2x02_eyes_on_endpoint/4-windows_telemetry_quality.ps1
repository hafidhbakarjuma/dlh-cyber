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
Write-Host "[!] Missing telemetry export: $InputFile" -ForegroundColor Red
exit 1
}

Write-Host "[*] Analyzing windows_events_export.json..." -ForegroundColor Cyan

##############################################################

# Load Events

##############################################################

$Events = @(Get-Content $InputFile -Raw | ConvertFrom-Json)
$TotalEvents = $Events.Count

if ($TotalEvents -eq 0) {
Write-Host "[!] Telemetry export contains no events." -ForegroundColor Red
exit 1
}

##############################################################

# Event Distribution

##############################################################

$EventDistribution = @(
$Events |
Group-Object event_id |
ForEach-Object {
[PSCustomObject]@{
event_id   = $*.Name
count      = $*.Count
percentage = [math]::Round(
(($_.Count / $TotalEvents) * 100),
2
)
}
}
)

##############################################################

# Channel Distribution

##############################################################

$ChannelDistribution = @(
$Events |
Group-Object source_type |
ForEach-Object {
[PSCustomObject]@{
channel    = $*.Name
count      = $*.Count
percentage = [math]::Round(
(($_.Count / $TotalEvents) * 100),
2
)
}
}
)

##############################################################

# Time Coverage - Events Per Hour

##############################################################

$HourlyDistribution = @()

$SortedTimestamps = @(
$Events |
ForEach-Object {
[datetime]$_.timestamp
} |
Sort-Object
)

if ($SortedTimestamps.Count -gt 0) {

```
$StartHour = $SortedTimestamps[0].ToUniversalTime()
$StartHour = $StartHour.Date.AddHours($StartHour.Hour)

$EndHour = $SortedTimestamps[-1].ToUniversalTime()
$EndHour = $EndHour.Date.AddHours($EndHour.Hour)

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
        hour           = $Hour.ToString("yyyy-MM-dd HH:00")
        events_per_hour = $Count
        event_count     = $Count
    }
}
```

}

$HoursWithEvents = @(
$HourlyDistribution |
Where-Object {
$_.events_per_hour -gt 0
}
)

$HoursWithoutEvents = @(
$HourlyDistribution |
Where-Object {
$_.events_per_hour -eq 0
}
)

$HoursWithEventsCount = $HoursWithEvents.Count
$HoursWithoutEventsCount = $HoursWithoutEvents.Count

##############################################################

# Gap Detection - Periods Longer Than 30 Minutes

##############################################################

# A gap longer than 30 minutes indicates a potential telemetry

# coverage or collection problem.

$GapThresholdMinutes = 30

$SortedEvents = @(
$Events |
Sort-Object {
[datetime]$_.timestamp
}
)

$Gaps = @()

for ($i = 1; $i -lt $SortedEvents.Count; $i++) {

```
$Previous = [datetime]$SortedEvents[$i - 1].timestamp
$Current = [datetime]$SortedEvents[$i].timestamp

$GapMinutes = ($Current - $Previous).TotalMinutes

if ($GapMinutes -gt $GapThresholdMinutes) {

    $Gaps += [PSCustomObject]@{
        start = $Previous.ToUniversalTime().ToString(
            "yyyy-MM-ddTHH:mm:ssZ"
        )

        end = $Current.ToUniversalTime().ToString(
            "yyyy-MM-ddTHH:mm:ssZ"
        )

        duration_minutes = [math]::Round(
            $GapMinutes,
            2
        )
    }
}
```

}

$LargestGap = 0

if ($Gaps.Count -gt 0) {
$LargestGap = (
$Gaps |
Measure-Object -Property duration_minutes -Maximum
).Maximum
}

##############################################################

# Field Completeness Helper

##############################################################

function Test-FieldCompleteness {

```
param(
    [object[]]$InputEvents,
    [string]$FieldName
)

if ($InputEvents.Count -eq 0) {
    return [PSCustomObject]@{
        field      = $FieldName
        total      = 0
        populated  = 0
        empty      = 0
        percentage = 100
    }
}

$Populated = @(
    $InputEvents |
    Where-Object {
        $Value = $_.$FieldName

        $null -ne $Value -and
        -not [string]::IsNullOrWhiteSpace(
            [string]$Value
        )
    }
).Count

$Empty = $InputEvents.Count - $Populated

[PSCustomObject]@{
    field      = $FieldName
    total      = $InputEvents.Count
    populated  = $Populated
    empty      = $Empty
    percentage = [math]::Round(
        (($Populated / $InputEvents.Count) * 100),
        2
    )
}
```

}

##############################################################

# Required Common Fields

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

```
$RequiredFieldCompleteness +=
    Test-FieldCompleteness `
        -InputEvents $Events `
        -FieldName $Field
```

}

##############################################################

# Process Event Completeness

##############################################################

$ProcessEvents = @(
$Events |
Where-Object {
[int]$*.event_id -eq 4688 -or
[int]$*.event_id -eq 1
}
)

$CommandLineCompleteness =
Test-FieldCompleteness `        -InputEvents $ProcessEvents`
-FieldName "command_line"

##############################################################

# Logon Source IP Completeness

##############################################################

$LogonEvents = @(
$Events |
Where-Object {
[int]$*.event_id -eq 4624 -or
[int]$*.event_id -eq 4625
}
)

$SourceIPCompleteness =
Test-FieldCompleteness `        -InputEvents $LogonEvents`
-FieldName "source_ip"

##############################################################

# PowerShell Script Block Completeness

##############################################################

$PowerShellEvents = @(
$Events |
Where-Object {
[int]$_.event_id -eq 4104
}
)

# ScriptBlockText is the original Windows PowerShell event field.

# The normalized export stores this content in script_block.

# Check both names so the quality gate supports either format.

$ScriptBlockTextEvents = @(
$PowerShellEvents |
Where-Object {
$Value = $_.script_block

```
    if ($null -eq $Value) {
        $Value = $_.ScriptBlockText
    }

    $null -ne $Value -and
    -not [string]::IsNullOrWhiteSpace(
        [string]$Value
    )
}
```

)

if ($PowerShellEvents.Count -gt 0) {

```
$ScriptBlockPopulated = $ScriptBlockTextEvents.Count
$ScriptBlockEmpty =
    $PowerShellEvents.Count - $ScriptBlockPopulated

$ScriptBlockPercentage = [math]::Round(
    (
        ($ScriptBlockPopulated /
        $PowerShellEvents.Count) * 100
    ),
    2
)
```

}
else {

```
$ScriptBlockPopulated = 0
$ScriptBlockEmpty = 0
$ScriptBlockPercentage = 100
```

}

$ScriptBlockCompleteness = [PSCustomObject]@{
field      = "ScriptBlockText"
normalized_field = "script_block"
total      = $PowerShellEvents.Count
populated  = $ScriptBlockPopulated
empty      = $ScriptBlockEmpty
percentage = $ScriptBlockPercentage
}

##############################################################

# Quality Score

##############################################################

$EventDistributionScore = 100

if ($TotalEvents -eq 0) {
$EventDistributionScore = 0
}

$ChannelScore = 100

$ExpectedChannels = @(
"Security",
"Sysmon",
"PowerShell"
)

foreach ($Channel in $ExpectedChannels) {

```
$ChannelExists = @(
    $ChannelDistribution |
    Where-Object {
        $_.channel -eq $Channel
    }
).Count

if ($ChannelExists -eq 0) {
    $ChannelScore -= 33.33
}
```

}

$HourlyCoverageScore = 100

if ($HourlyDistribution.Count -gt 0) {

```
$HourlyCoverageScore = [math]::Round(
    (
        (
            $HoursWithEventsCount /
            $HourlyDistribution.Count
        ) * 100
    ),
    2
)
```

}

$GapScore = 100

if ($Gaps.Count -gt 0) {

```
$GapScore = [math]::Max(
    0,
    100 - ($Gaps.Count * 10)
)
```

}

$CommandScore =
$CommandLineCompleteness.percentage

$SourceIPScore =
$SourceIPCompleteness.percentage

$ScriptBlockScore =
$ScriptBlockCompleteness.percentage

##############################################################

# Weighted Quality Score

##############################################################

$QualityScore = [math]::Round(
(
($EventDistributionScore * 0.10) +
($ChannelScore * 0.10) +
($HourlyCoverageScore * 0.20) +
($GapScore * 0.15) +
($CommandScore * 0.15) +
($SourceIPScore * 0.15) +
($ScriptBlockScore * 0.15)
),
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

# Quality Report

##############################################################

$QualityReport = [ordered]@{

```
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
        $HourlyDistribution.Count
}

gap_detection = [ordered]@{

    threshold_minutes =
        $GapThresholdMinutes

    threshold_description =
        "Periods longer than 30 minutes with no events"

    gaps =
        $Gaps

    gap_count =
        $Gaps.Count

    largest_gap_minutes =
        [math]::Round(
            $LargestGap,
            2
        )
}

field_completeness = [ordered]@{

    required_fields =
        $RequiredFieldCompleteness

    command_line =
        $CommandLineCompleteness

    source_ip =
        $SourceIPCompleteness

    ScriptBlockText =
        $ScriptBlockCompleteness
}

quality_score = [ordered]@{

    score =
        $QualityScore

    assessment =
        $Assessment

    scale =
        "0-100"

    weights = [ordered]@{
        event_distribution = 10
        channel_coverage   = 10
        time_coverage      = 20
        gap_detection      = 15
        command_line       = 15
        source_ip          = 15
        script_block       = 15
    }
}
```

}

##############################################################

# Write Quality Report

##############################################################

$QualityReport |
ConvertTo-Json -Depth 10 |
Out-File $OutputFile -Encoding UTF8

##############################################################

# Console Summary

##############################################################

$LargestGapDisplay = [math]::Round(
$LargestGap,
0
)

Write-Host ""
Write-Host "Total events: $TotalEvents"
Write-Host "Hours with events: $HoursWithEventsCount/$($HourlyDistribution.Count)"
Write-Host "Hours without events: $HoursWithoutEventsCount/$($HourlyDistribution.Count)"
Write-Host "Largest gap: $LargestGapDisplay minutes"
Write-Host "Command-line completeness: $($CommandLineCompleteness.percentage)%"
Write-Host "Source IP completeness: $($SourceIPCompleteness.percentage)%"
Write-Host "Script block completeness: $($ScriptBlockCompleteness.percentage)%"
Write-Host "Quality score: $QualityScore% ($Assessment)"
Write-Host "Report saved to: $OutputFile"
Write-Host ""
