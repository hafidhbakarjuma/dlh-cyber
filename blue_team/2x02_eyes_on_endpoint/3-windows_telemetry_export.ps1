<#
name:
    3-windows_telemetry_export.ps1

purpose:
    Exports Windows Security, Sysmon and PowerShell telemetry into
    analyst-ready JSON format with normalized timestamps, common fields
    and event-specific enrichment.

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

$OutputFile = ".\windows_events_export.json"

$StartTime =
(Get-Date).AddHours(-24)


$Hostname =
$env:COMPUTERNAME


$Logs = @(

    @{
        Name = "Security"
        Channel = "Security"
        Source = "Security"
    },

    @{
        Name = "Sysmon"
        Channel = "Microsoft-Windows-Sysmon/Operational"
        Source = "Sysmon"
    },

    @{
        Name = "PowerShell"
        Channel = "Microsoft-Windows-PowerShell/Operational"
        Source = "PowerShell"
    }

)


$ExportedEvents = @()


Write-Host "[*] Exporting Windows telemetry from last 24 hours..." `
    -ForegroundColor Cyan



##############################################################
# Event Parser
##############################################################

function Get-EventCategory {

    param(
        [int]$EventID,
        [string]$Source
    )


    switch ($EventID) {


        4624 { return "Successful Logon" }

        4625 { return "Failed Logon" }

        4672 { return "Privilege Assignment" }

        4688 { return "Process Creation" }

        4104 { return "PowerShell Script Block" }


        1 { return "Sysmon Process Creation" }

        3 { return "Sysmon Network Connection" }

        11 { return "Sysmon File Creation" }

        13 { return "Sysmon Registry Modification" }

        22 { return "Sysmon DNS Query" }


        default {

            return "Other"

        }

    }

}



function Convert-WindowsEvent {


    param(

        [System.Diagnostics.Eventing.Reader.EventRecord]
        $Event,

        [string]
        $Source

    )


    $Message =
    $Event.FormatDescription()


    $Record = [ordered]@{


        timestamp =
            $Event.TimeCreated.ToUniversalTime().ToString(
                "yyyy-MM-ddTHH:mm:ssZ"
            )


        hostname =
            $Hostname


        platform =
            "Windows"


        source_type =
            $Source


        channel =
            $Event.LogName


        event_id =
            $Event.Id


        event_category =
            Get-EventCategory `
                -EventID $Event.Id `
                -Source $Source


        provider =
            $Event.ProviderName


        raw_message =
            $Message


    }



##############################################################
# Security Event Enrichment
##############################################################

    switch ($Event.Id) {


        4624 {


            $Record.target_user =
                ($Message -split "`n" |
                Select-String "Account Name").Line


            $Record.logon_type =
                ($Message -split "`n" |
                Select-String "Logon Type").Line


            $Record.source_ip =
                ($Message -split "`n" |
                Select-String "Source Network Address").Line


            $Record.workstation =
                ($Message -split "`n" |
                Select-String "Workstation Name").Line


        }


        4625 {


            $Record.target_user =
                ($Message -split "`n" |
                Select-String "Account Name").Line


            $Record.failure_reason =
                ($Message -split "`n" |
                Select-String "Failure Reason").Line


            $Record.source_ip =
                ($Message -split "`n" |
                Select-String "Source Network Address").Line


        }


        4672 {


            $Record.privileged_account =
                ($Message -split "`n" |
                Select-String "Account Name").Line


        }


        4688 {


            $Record.process_name =
                ($Message -split "`n" |
                Select-String "New Process Name").Line


            $Record.command_line =
                ($Message -split "`n" |
                Select-String "Command Line").Line


            $Record.parent_process =
                ($Message -split "`n" |
                Select-String "Creator Process Name").Line


        }



##############################################################
# PowerShell
##############################################################

        4104 {


            $Record.script_block =
                ($Message -split "`n" |
                Select-String "ScriptBlockText").Line


        }



##############################################################
# Sysmon
##############################################################

        1 {


            $Record.image =
                ($Message -split "`n" |
                Select-String "Image").Line


            $Record.command_line =
                ($Message -split "`n" |
                Select-String "CommandLine").Line


            $Record.parent_image =
                ($Message -split "`n" |
                Select-String "ParentImage").Line


            $Record.hashes =
                ($Message -split "`n" |
                Select-String "Hashes").Line


        }


        3 {


            $Record.destination_ip =
                ($Message -split "`n" |
                Select-String "DestinationIp").Line


            $Record.destination_port =
                ($Message -split "`n" |
                Select-String "DestinationPort").Line


            $Record.process =
                ($Message -split "`n" |
                Select-String "Image").Line


        }


        11 {


            $Record.target_filename =
                ($Message -split "`n" |
                Select-String "TargetFilename").Line


            $Record.creating_process =
                ($Message -split "`n" |
                Select-String "Image").Line


        }


        13 {


            $Record.registry_key =
                ($Message -split "`n" |
                Select-String "TargetObject").Line


            $Record.value_name =
                ($Message -split "`n" |
                Select-String "Details").Line


        }


        22 {


            $Record.query_name =
                ($Message -split "`n" |
                Select-String "QueryName").Line


            $Record.query_results =
                ($Message -split "`n" |
                Select-String "QueryResults").Line


        }


    }


    return [PSCustomObject]$Record

}



##############################################################
# Collect Events
##############################################################


foreach ($Log in $Logs) {


    try {


        $Events =
        Get-WinEvent `
            -FilterHashtable @{
                LogName = $Log.Channel
                StartTime = $StartTime
            } `
            -ErrorAction Stop



        foreach ($Event in $Events) {


            $ExportedEvents +=
                Convert-WindowsEvent `
                    -Event $Event `
                    -Source $Log.Source


        }


    }

    catch {


        Write-Host `
            "[!] Unable to read $($Log.Channel)" `
            -ForegroundColor Yellow


    }

}



##############################################################
# Export JSON
##############################################################

$ExportedEvents |
ConvertTo-Json -Depth 8 |
Out-File `
    $OutputFile `
    -Encoding UTF8



##############################################################
# Statistics
##############################################################

$SecurityCount =
($ExportedEvents |
Where-Object {
    $_.source_type -eq "Security"
}).Count


$SysmonCount =
($ExportedEvents |
Where-Object {
    $_.source_type -eq "Sysmon"
}).Count


$PowerShellCount =
($ExportedEvents |
Where-Object {
    $_.source_type -eq "PowerShell"
}).Count



Write-Host ""

Write-Host "Security events: $SecurityCount"

Write-Host "Sysmon events: $SysmonCount"

Write-Host "PowerShell events: $PowerShellCount"

Write-Host "Total events: $($ExportedEvents.Count)"



$TopEvents =
$ExportedEvents |
Group-Object event_id |
Sort-Object Count -Descending |
Select-Object -First 5



Write-Host ""

Write-Host "Top Event IDs:"

foreach ($Event in $TopEvents) {

    Write-Host `
        "$($Event.Name) ($($Event.Count))"

}


Write-Host ""

Write-Host "Output: $OutputFile"
