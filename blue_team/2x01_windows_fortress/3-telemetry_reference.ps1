<#
.SYNOPSIS
    3-telemetry_reference.ps1 - Windows Telemetry Reference Builder for MedDefense

.DESCRIPTION
    Generates a machine-readable Windows telemetry reference mapping
    security events, PowerShell events, and Sysmon events to detection
    use cases.

.PURPOSE
   Purpose: Build an operational telemetry reference connecting event visibility,
    audit dependencies, Sysmon deployment, PowerShell logging, and detection.

.AUTHOR
    Author: Hafidh Juma

.DATE
    Date: 2026-08-03
#>

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"


$outputFile = "windows_event_reference.json"


$events = @(

# -------------------------
# Windows Security Events
# -------------------------

@{
event_id = 4624
event_name = "Successful Logon"
log_source = "Windows Security Log"
audit_or_sensor_dependency = "Audit Logon enabled"
security_meaning = "Records successful user authentication attempts"
normal_frequency = "High"
triage_priority = "Medium"
crimson_tide_phase = "Initial Access"
example_suspicious_pattern = "Multiple successful logons from unusual locations or accounts"
validation_method = "Review Logon Type, Source IP, Account Name and TimeCreated"
},

@{
event_id = 4625
event_name = "Failed Logon"
log_source = "Windows Security Log"
audit_or_sensor_dependency = "Audit Logon enabled"
security_meaning = "Records failed authentication attempts"
normal_frequency = "Medium"
triage_priority = "High"
crimson_tide_phase = "Credential Access"
example_suspicious_pattern = "Multiple failed logon attempts indicating password spraying or brute force attacks"
validation_method = "Check failure reason, source IP and account target"
},

@{
event_id = 4648
event_name = "Explicit Credential Usage"
log_source = "Windows Security Log"
audit_or_sensor_dependency = "Audit Logon enabled"
security_meaning = "Tracks authentication using supplied credentials"
normal_frequency = "Low"
triage_priority = "High"
crimson_tide_phase = "Credential Access"
example_suspicious_pattern = "Unexpected privileged credential usage"
validation_method = "Validate Subject Account and Target Account"
},

@{
event_id = 4672
event_name = "Special Privilege Logon"
log_source = "Windows Security Log"
audit_or_sensor_dependency = "Audit Special Logon enabled"
security_meaning = "Shows assignment of administrative privileges"
normal_frequency = "Medium"
triage_priority = "High"
crimson_tide_phase = "Privilege Escalation"
example_suspicious_pattern = "Unexpected administrator privilege assignment"
validation_method = "Compare account privileges with authorized roles"
},

@{
event_id = 4688
event_name = "Process Creation"
log_source = "Windows Security Log"
audit_or_sensor_dependency = "Audit Process Creation enabled"
security_meaning = "Records newly created processes"
normal_frequency = "Very High"
triage_priority = "High"
crimson_tide_phase = "Execution"
example_suspicious_pattern = "PowerShell, cmd, or unknown binaries execution"
validation_method = "Review New Process Name, Parent Process and Command Line"
},

@{
event_id = 4720
event_name = "User Account Created"
log_source = "Windows Security Log"
audit_or_sensor_dependency = "Audit User Account Management enabled"
security_meaning = "Records creation of user accounts"
normal_frequency = "Low"
triage_priority = "High"
crimson_tide_phase = "Persistence"
example_suspicious_pattern = "Unauthorized account creation"
validation_method = "Verify creator account and created user"
},

@{
event_id = 4726
event_name = "User Account Deleted"
log_source = "Windows Security Log"
audit_or_sensor_dependency = "Audit User Account Management enabled"
security_meaning = "Records account deletion activity"
normal_frequency = "Low"
triage_priority = "Medium"
crimson_tide_phase = "Defense Evasion"
example_suspicious_pattern = "Deletion of investigation or admin accounts"
validation_method = "Review deleting account and target account"
},

@{
event_id = 4732
event_name = "Member Added to Local Security Group"
log_source = "Windows Security Log"
audit_or_sensor_dependency = "Audit Security Group Management enabled"
security_meaning = "Tracks security group membership changes"
normal_frequency = "Low"
triage_priority = "High"
crimson_tide_phase = "Privilege Escalation"
example_suspicious_pattern = "User added to Administrators group"
validation_method = "Verify group name, member account and actor"
},

@{
event_id = 1102
event_name = "Audit Log Cleared"
log_source = "Windows Security Log"
audit_or_sensor_dependency = "Audit System enabled"
security_meaning = "Indicates Windows audit logs were deleted"
normal_frequency = "Very Low"
triage_priority = "Critical"
crimson_tide_phase = "Defense Evasion"
example_suspicious_pattern = "Attacker clearing evidence after compromise"
validation_method = "Investigate Subject Account and timeline"
},


# -------------------------
# PowerShell Events
# -------------------------

@{
event_id = 4103
event_name = "PowerShell Module Logging"
log_source = "PowerShell Operational Log"
audit_or_sensor_dependency = "PowerShell Module Logging enabled"
security_meaning = "Records PowerShell command execution details"
normal_frequency = "Medium"
triage_priority = "High"
crimson_tide_phase = "Execution"
example_suspicious_pattern = "Encoded commands or suspicious scripts"
validation_method = "Review command content and user context"
},

@{
event_id = 4104
event_name = "PowerShell Script Block Logging"
log_source = "PowerShell Operational Log"
audit_or_sensor_dependency = "PowerShell Script Block Logging enabled"
security_meaning = "Captures executed PowerShell script blocks"
normal_frequency = "Medium"
triage_priority = "Critical"
crimson_tide_phase = "Execution"
example_suspicious_pattern = "Encoded PowerShell commands, malicious script blocks, and hidden payload execution"
validation_method = "Analyze script block content, encoded commands, and indicators"
},


# -------------------------
# Sysmon Events
# -------------------------

@{
event_id = 1
event_name = "Process Creation"
log_source = "Sysmon"
audit_or_sensor_dependency = "Sysmon Process Creation monitoring"
security_meaning = "Provides detailed process execution visibility"
normal_frequency = "Very High"
triage_priority = "High"
crimson_tide_phase = "Execution"
example_suspicious_pattern = "Suspicious binaries or LOLBins"
validation_method = "Review process tree and hashes"
},

@{
event_id = 3
event_name = "Network Connection"
log_source = "Sysmon"
audit_or_sensor_dependency = "Sysmon Network Monitoring"
security_meaning = "Tracks outbound network connections"
normal_frequency = "High"
triage_priority = "High"
crimson_tide_phase = "Command and Control"
example_suspicious_pattern = "Connection to malicious IP addresses"
validation_method = "Check destination IP, port and process"
},

@{
event_id = 7
event_name = "Image Loaded"
log_source = "Sysmon"
audit_or_sensor_dependency = "Sysmon Image Load Monitoring"
security_meaning = "Tracks DLL and executable loading"
normal_frequency = "High"
triage_priority = "Medium"
crimson_tide_phase = "Defense Evasion"
example_suspicious_pattern = "DLL injection or unsigned modules"
validation_method = "Review loaded module path and signature"
},

@{
event_id = 11
event_name = "File Created"
log_source = "Sysmon"
audit_or_sensor_dependency = "Sysmon File Creation Monitoring"
security_meaning = "Tracks new file creation"
normal_frequency = "High"
triage_priority = "Critical"
crimson_tide_phase = "Impact"
example_suspicious_pattern = "Ransomware creating and encrypting large numbers of files"
validation_method = "Check file path, hash, creator process, and file modification activity"
},

@{
event_id = 13
event_name = "Registry Value Set"
log_source = "Sysmon"
audit_or_sensor_dependency = "Sysmon Registry Monitoring"
security_meaning = "Detects registry modifications"
normal_frequency = "Medium"
triage_priority = "High"
crimson_tide_phase = "Persistence"
example_suspicious_pattern = "Registry Run Key modification"
validation_method = "Review registry path and modifying process"
},

@{
event_id = 22
event_name = "DNS Query"
log_source = "Sysmon"
audit_or_sensor_dependency = "Sysmon DNS Monitoring"
security_meaning = "Records DNS resolution activity"
normal_frequency = "High"
triage_priority = "Medium"
crimson_tide_phase = "Command and Control"
example_suspicious_pattern = "DNS queries to malicious domains"
validation_method = "Compare queried domains against threat intelligence"
}

)


# Convert to JSON

$events |
ConvertTo-Json -Depth 5 |
Out-File -Encoding UTF8 $outputFile


# Output summary

$securityCount = ($events | Where-Object {$_.log_source -eq "Windows Security Log"}).Count
$powerShellCount = ($events | Where-Object {$_.log_source -eq "PowerShell Operational Log"}).Count
$sysmonCount = ($events | Where-Object {$_.log_source -eq "Sysmon"}).Count


Write-Host "Security events mapped: $securityCount"
Write-Host "PowerShell events mapped: $powerShellCount"
Write-Host "Sysmon events mapped: $sysmonCount"
Write-Host "Total events documented: $($events.Count)"
Write-Host "Reference saved to: $outputFile"
