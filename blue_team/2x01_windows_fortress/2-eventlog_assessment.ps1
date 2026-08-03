<#
.SYNOPSIS
    2-eventlog_assessment.ps1 - Windows Event Log Assessment Script for MedDefense
.DESCRIPTION
    Assesses the current event logging capability by auditing policy settings via auditpol
    and querying the local Security event log to see which critical Event IDs have actually 
    been generated in the past 24 hours.
.PURPOSE
    Quantify the gap between current domain visibility and the required event logging baseline.
#>

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

Write-Host "[-] Assessing Windows Event Log and Audit Policy Configuration..." -ForegroundColor Cyan

# Define critical Event IDs and their corresponding audit subcategories & descriptions
$criticalEvents = @(
    [PSCustomObject]@{ EventID = 4624; Description = "Successful Logon"; Subcategory = "Logon"; Category = "Logon/Logoff" },
    [PSCustomObject]@{ EventID = 4625; Description = "Failed Logon"; Subcategory = "Logon"; Category = "Logon/Logoff" },
    [PSCustomObject]@{ EventID = 4648; Description = "Explicit Credentials"; Subcategory = "Logon"; Category = "Logon/Logoff" },
    [PSCustomObject]@{ EventID = 4688; Description = "Process Creation"; Subcategory = "Process Creation"; Category = "Detailed Tracking" },
    [PSCustomObject]@{ EventID = 4720; Description = "Account Created"; Subcategory = "User Account Management"; Category = "Account Management" },
    [PSCustomObject]@{ EventID = 4726; Description = "Account Deleted"; Subcategory = "User Account Management"; Category = "Account Management" },
    [PSCustomObject]@{ EventID = 4732; Description = "Member Added to Group"; Subcategory = "Security Group Management"; Category = "Account Management" },
    [PSCustomObject]@{ EventID = 4672; Description = "Special Logon"; Subcategory = "Special Logon"; Category = "Logon/Logoff" },
    [PSCustomObject]@{ EventID = 1102; Description = "Audit Log Cleared"; Subcategory = "Audit Log"; Category = "System" }
)

# 1. Fetch current audit policy configuration using auditpol
$auditPolOutput = & auditpol.exe /get /category:* 2>&1

# 2. Check recent event generation in the Security log (last 24 hours)
$cutoffTime = (Get-Date).AddHours(-24)
$recentEvents = @()
try {
    $recentEvents = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; StartTime = $cutoffTime } -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Id
} catch {
    # Fallback or empty if access denied / log empty
}

# 3. Evaluate Status for each critical Event ID
$results = foreach ($event in $criticalEvents) {
    # Check if subcategory is enabled in auditpol output (looking for Success and/or Failure)
    $subCategoryLine = $auditPolOutput | Where-Object { $_ -match [regex]::Escape($event.Subcategory) }
    $isConfigured = $false
    if ($subCategoryLine) {
        if ($subCategoryLine -match 'Success' -or $subCategoryLine -match 'Failure' -or $subCategoryLine -match 'Success and Failure') {
            if ($subCategoryLine -notmatch 'No Auditing') {
                $isConfigured = $true
            }
        }
    }

    # Also verify if the event actually generated recently
    $hasGenerated = $recentEvents -contains $event.EventID

    # Determine status string matching expected output format
    $status = if ($isConfigured -or $hasGenerated) { "[GENERATING]" } else { "[NOT CONFIGURED]" }

    [PSCustomObject]@{
        EventID           = $event.EventID
        Description       = $event.Description
        AuditSubcategory  = $event.Subcategory
        Status            = $status
    }
}

# Print formatted table output matching expected layout
Write-Host ""
$results | Format-Table -Property EventID, Description, AuditSubcategory, Status -AutoSize
Write-Host ""
