# Exit codes: 0 = success, 1 = check failed, 2 = environment error
# Capstone Windows environment intake script for administrative endpoint (hawthorne-adm-01)
$ErrorActionPreference = "Stop"

$OutputPath = "C:\ProgramData\MedDefense\windows_intake.json"
$ParentDir = Split-Path $OutputPath

if (!(Test-Path $ParentDir)) {
    New-Item -ItemType Directory -Force -Path $ParentDir | Out-Null
}

try {
    $Hostname = $env:COMPUTERNAME
    $OS = Get-CimInstance Win32_OperatingSystem
    
    # Feature count depending on OS type (Server vs Client)
    $FeatureCount = 0
    try {
        if ((Get-CimInstance Win32_OperatingSystem).ProductType -eq 1) {
            $FeatureCount = (Get-WindowsOptionalFeature -Online | Where-Object {$_.State -eq 'Enabled'}).Count
        } else {
            $FeatureCount = (Get-WindowsFeature | Where-Object {$_.InstallState -eq 'Installed'}).Count
        }
    } catch {
        $FeatureCount = -1
    }

    $RunningServices = (Get-Service | Where-Object {$_.Status -eq 'Running'}).Count
    $LocalUsers = Get-LocalUser | Select-Object Name, Enabled, PasswordRequired
    $FirewallState = Get-NetFirewallProfile | Select-Object Name, Enabled
    
    # Sysmon presence and channel size check
    $SysmonService = Get-Service Sysmon -ErrorAction SilentlyContinue
    $SysmonStatus = if ($SysmonService) { $SysmonService.Status } else { "Not Installed" }
    $SysmonLogSize = 0
    try {
        $LogProp = Get-WinEvent -ListLog "Microsoft-Windows-Sysmon/Operational" -ErrorAction SilentlyContinue
        if ($LogProp) { $SysmonLogSize = $LogProp.MaximumSize }
    } catch {
        $SysmonLogSize = 0
    }

    # PowerShell Script Block Logging Registry Check
    $ScriptBlockPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
    $ScriptBlockEnabled = 0
    if (Test-Path $ScriptBlockPath) {
        $ScriptBlockEnabled = (Get-ItemProperty -Path $ScriptBlockPath -Name "EnableScriptBlockLogging" -ErrorAction SilentlyContinue).EnableScriptBlockLogging
    }

    # Audit Policy summary via auditpol
    $AuditPolOutput = & auditpol /get /category:*

    # Account Lockout and Password policy via net accounts
    $NetAccountsOutput = & net accounts

    $IntakeData = [PSCustomObject]@{
        capstone_project         = "meddefense_hawthorne_endpoint"
        intake_type              = "windows_administrative_endpoint"
        Timestamp                = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        Hostname                 = $Hostname
        OSBuild                  = $OS.BuildNumber
        OSVersion                = $OS.Caption
        InstalledFeatureCount    = $FeatureCount
        RunningServicesCount     = $RunningServices
        LocalUsers               = $LocalUsers
        FirewallProfiles         = $FirewallState
        Sysmon                   = @{
            Status               = $SysmonStatus
            MaxChannelSize       = $SysmonLogSize
        }
        PowerShellLogging        = @{
            ScriptBlockLogging   = $ScriptBlockEnabled
        }
        AuditPolicySummary       = $AuditPolOutput
        AccountPolicy            = $NetAccountsOutput
    }

    $IntakeData | ConvertTo-Json -Depth 5 | Set-Content -Path $OutputPath
    Write-Host "[+] Windows capstone intake record successfully written to $OutputPath"
    exit 0
} catch {
    Write-Error "[-] Environment error during Windows capstone intake: $_"
    exit 2
}
