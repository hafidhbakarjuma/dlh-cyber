<#
name:
    1-sysmon_coverage_matrix.ps1

purpose:
    Parses Sysmon configuration and generates an ATT&CK-aligned telemetry
    coverage matrix showing which attacker techniques are covered, partial,
    or blind based on enabled Sysmon Event IDs, filtering rules, and evidence
    availability.

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

$SysmonConfig = ".\sysmonconfig.xml"
$OutputFile = ".\sysmon_coverage_matrix.json"


if (!(Test-Path $SysmonConfig)) {
    Write-Host "[!] Sysmon configuration not found: $SysmonConfig" -ForegroundColor Red
    exit 1
}


##############################################################
# Parse Sysmon XML
##############################################################

Write-Host "[*] Parsing Sysmon config: sysmonconfig.xml"


[xml]$XmlConfig = Get-Content $SysmonConfig


$EnabledEvents = @()

$EventNodes = $XmlConfig.Sysmon schemaversion.EventFiltering.ChildNodes


foreach ($Event in $EventNodes) {

    if ($Event.Name -match "Event") {

        $EventID = $Event.Name.Replace("Event", "")

        if ($EventID -match "^\d+$") {
            $EnabledEvents += [int]$EventID
        }
    }
}


$EnabledEvents = $EnabledEvents | Sort-Object -Unique


Write-Host ""
Write-Host "Enabled Event IDs: $($EnabledEvents -join ', ')"



##############################################################
# Detect filtering conflicts
##############################################################

$ConfigText = Get-Content $SysmonConfig -Raw

$FilterConflicts = @()

# Detect exclude filters
if ($ConfigText -match "exclude") {

    $FilterConflicts += "Exclude rules detected; some telemetry may be suppressed"

}

# Detect include filters
if ($ConfigText -match "include") {

    $FilterConflicts += "Include rules detected; verify allowed telemetry is not too restrictive"

}


##############################################################
# ATT&CK Coverage Mapping
##############################################################

$TechniqueMatrix = @(

    @{
        technique_id = "T1059"
        technique_name = "Command and Scripting Interpreter"
        required_event_ids = @(1)
        evidence_fields_expected = @(
            "Image",
            "CommandLine",
            "ParentImage"
        )
    },

    @{
        technique_id = "T1053"
        technique_name = "Scheduled Task/Job"
        required_event_ids = @(1)
        evidence_fields_expected = @(
            "Image",
            "CommandLine",
            "ParentImage"
        )
    },

    @{
        technique_id = "T1547"
        technique_name = "Boot or Logon Autostart Execution"
        required_event_ids = @(13)
        evidence_fields_expected = @(
            "TargetObject",
            "Details"
        )
    },

    @{
        technique_id = "T1055"
        technique_name = "Process Injection"
        required_event_ids = @(8,10)
        evidence_fields_expected = @(
            "SourceImage",
            "TargetImage",
            "GrantedAccess"
        )
    },

    @{
        technique_id = "T1071"
        technique_name = "Application Layer Protocol"
        required_event_ids = @(3,22)
        evidence_fields_expected = @(
            "DestinationIp",
            "DestinationPort",
            "QueryName"
        )
    },

    @{
        technique_id = "T1574.002"
        technique_name = "DLL Side-Loading"
        required_event_ids = @(7)
        evidence_fields_expected = @(
            "ImageLoaded",
            "Image"
        )
    },

    @{
        technique_id = "T1027"
        technique_name = "Obfuscated or Compressed Files"
        required_event_ids = @(11,15)
        evidence_fields_expected = @(
            "TargetFilename",
            "Hash"
        )
    }

)



##############################################################
# Evaluate Coverage
##############################################################

$Results = @()


foreach ($Technique in $TechniqueMatrix) {


    $Required = $Technique.required_event_ids


    $Enabled = @(
        $Required | Where-Object {
            $EnabledEvents -contains $_
        }
    )


    $Missing = @(
        $Required | Where-Object {
            $EnabledEvents -notcontains $_
        }
    )


    if ($Enabled.Count -eq $Required.Count) {

        if ($FilterConflicts.Count -gt 0) {

            $Status = "partial"

            $Reason = "Required events enabled but filtering rules may suppress activity"

        }
        else {

            $Status = "covered"

            $Reason = "Required Sysmon events enabled with no detected filter conflicts"

        }

    }
    elseif ($Enabled.Count -gt 0) {


        $Status = "partial"

        $Reason = "Some required Event IDs enabled: Missing $($Missing -join ', ')"

    }
    else {


        $Status = "blind"

        $Reason = "Required Sysmon Event IDs are not enabled"

    }



    $Recommendation = ""


    if ($Status -eq "partial" -or $Status -eq "blind") {

        $Recommendation =
        "Enable missing Sysmon events and review filtering rules to ensure required telemetry fields are collected"

    }
    else {

        $Recommendation =
        "Maintain current configuration and monitor telemetry quality"

    }



    $Results += [PSCustomObject]@{

        technique_id = $Technique.technique_id

        technique_name = $Technique.technique_name

        required_event_ids = $Required

        enabled_event_ids = $Enabled

        filter_conflicts = $FilterConflicts

        coverage_status = $Status

        reason = $Reason

        evidence_fields_expected =
            $Technique.evidence_fields_expected

        recommendation =
            $Recommendation

    }

}



##############################################################
# Export JSON
##############################################################

$Results |
ConvertTo-Json -Depth 5 |
Out-File $OutputFile -Encoding UTF8



##############################################################
# Summary
##############################################################

$Covered =
    ($Results | Where-Object {$_.coverage_status -eq "covered"}).Count

$Partial =
    ($Results | Where-Object {$_.coverage_status -eq "partial"}).Count

$Blind =
    ($Results | Where-Object {$_.coverage_status -eq "blind"}).Count


Write-Host ""
Write-Host "Techniques assessed: $($Results.Count)"
Write-Host "Covered: $Covered"
Write-Host "Partial: $Partial"
Write-Host "Blind: $Blind"
Write-Host "Report saved to: $OutputFile"
