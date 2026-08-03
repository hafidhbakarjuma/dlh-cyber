<#
.SYNOPSIS
    2-eventlog_assessment.ps1 - Windows Event Log Assessment Script for MedDefense

.DESCRIPTION
    Assesses the current event logging capability by auditing the current
    Windows audit policy and determining whether critical Security Event IDs
    have been generated within the last 24 hours.

.PURPOSE
    Purpose: Quantify the gap between current domain visibility and the required event logging baseline.

.AUTHOR
   Author: Hafidh Juma

.DATE
    2026-08-03
#>

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Write-Host "[-] Assessing Windows Event Log and Audit Policy Configuration..." -ForegroundColor Cyan

# Critical Event IDs
$criticalEvents = @(
    [PSCustomObject]@{
        EventID            = 4624
        Description        = "Successful Logon"
        AuditPolicy        = "Logon"
        AuditSubcategory   = "Logon"
    }

    [PSCustomObject]@{
        EventID            = 4625
        Description        = "Failed Logon"
        AuditPolicy        = "Logon"
        AuditSubcategory   = "Logon"
    }

    [PSCustomObject]@{
        EventID            = 4648
        Description        = "Explicit Credentials"
        AuditPolicy        = "Logon"
        AuditSubcategory   = "Logon"
    }

    [PSCustomObject]@{
        EventID            = 4688
        Description        = "Process Creation"
        AuditPolicy        = "Process Creation"
        AuditSubcategory   = "Process Tracking"
    }

    [PSCustomObject]@{
        EventID            = 4720
        Description        = "Account Created"
        AuditPolicy        = "User Account Management"
        AuditSubcategory   = "Account Management"
    }

    [PSCustomObject]@{
        EventID            = 4726
        Description        = "Account Deleted"
        AuditPolicy        = "User Account Management"
        AuditSubcategory   = "Account Management"
    }

    [PSCustomObject]@{
        EventID            = 4732
        Description        = "Member Added to Group"
        AuditPolicy        = "Security Group Management"
        AuditSubcategory   = "Account Management"
    }

    [PSCustomObject]@{
        EventID            = 4672
        Description        = "Special Logon"
        AuditPolicy        = "Special Logon"
        AuditSubcategory   = "Special Logon"
    }

    [PSCustomObject]@{
        EventID            = 1102
        Description        = "Audit Log Cleared"
        AuditPolicy        = "Audit Log"
        AuditSubcategory   = "System Integrity"
    }
)

# --------------------------------------------------------------------
# Get current audit policy
# --------------------------------------------------------------------
try {
    $auditPolOutput = & auditpol.exe /get /category:* 2>&1

    if ($LASTEXITCODE -ne 0) {
        throw "auditpol.exe returned exit code $LASTEXITCODE"
    }
}
catch {
    Write-Error "Failed to retrieve audit policy: $($_.Exception.Message)"
    exit 1
}

# --------------------------------------------------------------------
# Query Security log (last 24 hours)
# --------------------------------------------------------------------
$cutoffTime = (Get-Date).AddHours(-24)
$recentEvents = @()

try {
    $recentEvents = Get-WinEvent `
        -FilterHashtable @{
            LogName   = "Security"
            StartTime = $cutoffTime
        } `
        -ErrorAction Stop |
        Select-Object -ExpandProperty Id
}
catch {
    Write-Warning "Unable to query Security event log: $($_.Exception.Message)"
}

# --------------------------------------------------------------------
# Evaluate each Event ID
# --------------------------------------------------------------------
$results = foreach ($event in $criticalEvents) {

    $isConfigured = $false

    $policyLine = $auditPolOutput | Where-Object {
        $_ -match [regex]::Escape($event.AuditPolicy)
    }

    if ($policyLine) {

        if (
            $policyLine -match "Success and Failure" -or
            $policyLine -match "Success" -or
            $policyLine -match "Failure"
        ) {

            if ($policyLine -notmatch "No Auditing") {
                $isConfigured = $true
            }
        }
    }

    $hasGenerated = $recentEvents -contains $event.EventID

    if ($isConfigured -or $hasGenerated) {
        $status = "[GENERATING]"
    }
    else {
        $status = "[NOT CONFIGURED]"
    }

    [PSCustomObject]@{
        EventID          = $event.EventID
        Description      = $event.Description
        AuditSubcategory = $event.AuditSubcategory
        Status           = $status
    }
}

# --------------------------------------------------------------------
# Display Results
# --------------------------------------------------------------------

Write-Host ""

$results |
Format-Table `
    EventID,
    Description,
    @{Label="Audit Subcategory";Expression={$_.AuditSubcategory}},
    Status -AutoSize

Write-Host ""
