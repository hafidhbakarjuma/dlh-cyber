<#
.SYNOPSIS
9-sysmon_deploy.ps1 - MedDefense Sysmon Deployment

.DESCRIPTION
Downloads, installs, and validates Sysmon using a detection-focused
SwiftOnSecurity baseline configuration.

.PURPOSE
Deploy Sysmon endpoint telemetry to provide visibility into:
process execution, network connections, file creation,
registry changes, DNS activity, and persistence techniques.

.AUTHOR
Author: Hafidh Juma

.DATE
Date: 2026-08-04
#>

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"


############################################################
# Variables
############################################################

$DownloadPath = "C:\Tools\Sysmon"
$SysmonZip = "$DownloadPath\Sysmon.zip"
$SysmonExe = "$DownloadPath\Sysmon64.exe"
$ConfigFile = "$DownloadPath\sysmonconfig.xml"

$SysmonURL = "https://download.sysinternals.com/files/Sysmon.zip"

$ConfigURL = "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml"


############################################################
# Create working directory
############################################################

Write-Host ""
Write-Host "[*] Preparing Sysmon directory..."

if (!(Test-Path $DownloadPath)) {
    New-Item `
        -Path $DownloadPath `
        -ItemType Directory | Out-Null
}


############################################################
# Download Sysmon
############################################################

Write-Host ""
Write-Host "[*] Downloading Sysmon..."

try {

    Invoke-WebRequest `
        -Uri $SysmonURL `
        -OutFile $SysmonZip

    Expand-Archive `
        -Path $SysmonZip `
        -DestinationPath $DownloadPath `
        -Force


    Write-Host "    Downloading Sysmon... OK" `
        -ForegroundColor Green

}
catch {

    Write-Error "Failed downloading Sysmon."
    exit 1
}



############################################################
# Download Sysmon Configuration
############################################################

Write-Host ""
Write-Host "[*] Downloading SwiftOnSecurity configuration..."

try {

    Invoke-WebRequest `
        -Uri $ConfigURL `
        -OutFile $ConfigFile


    Write-Host "    Downloading SwiftOnSecurity config... OK" `
        -ForegroundColor Green

}
catch {

    Write-Error "Failed downloading Sysmon configuration."
    exit 1
}



############################################################
# Install Sysmon
############################################################

Write-Host ""
Write-Host "[*] Installing Sysmon with config..."

Start-Process `
    -FilePath $SysmonExe `
    -ArgumentList "-accepteula -i $ConfigFile" `
    -Wait


Write-Host ""
Write-Host "    Sysmon64.exe -accepteula -i sysmonconfig.xml"



############################################################
# Verify Sysmon Service
############################################################

Write-Host ""
Write-Host "[*] Verifying Sysmon service..."

$SysmonService = Get-Service `
    -Name Sysmon64 `
    -ErrorAction SilentlyContinue


if ($SysmonService.Status -eq "Running") {

    Write-Host `
    "    Service: Sysmon64 - Running             [OK]" `
    -ForegroundColor Green

}
else {

    Write-Host `
    "    Service: Sysmon64 not running            [FAILED]" `
    -ForegroundColor Red
}



############################################################
# Verify Driver
############################################################

Write-Host ""
Write-Host "[*] Checking Sysmon driver..."

$Driver = fltmc | Select-String "SysmonDrv"


if ($Driver) {

    Write-Host `
    "    Driver: SysmonDrv - Loaded              [OK]" `
    -ForegroundColor Green

}
else {

    Write-Host `
    "    Driver: SysmonDrv not loaded             [FAILED]" `
    -ForegroundColor Red
}



############################################################
# Verify Event Generation
############################################################

Write-Host ""
Write-Host "[*] Verifying event generation..."


$Events = Get-WinEvent `
    -FilterHashtable @{
        LogName="Microsoft-Windows-Sysmon/Operational"
        StartTime=(Get-Date).AddMinutes(-1)
    } `
    -ErrorAction SilentlyContinue


if ($Events.Count -gt 0) {

    Write-Host `
    "    Events in last 60 seconds: $($Events.Count)       [OK]" `
    -ForegroundColor Green

}
else {

    Write-Host `
    "    No Sysmon events detected                 [FAILED]" `
    -ForegroundColor Red

}



############################################################
# Test FileCreate Event ID 11
############################################################

Write-Host ""
Write-Host "[*] Testing FileCreate detection..."


$TestFile = "C:\Windows\Temp\sysmon_test.txt"


New-Item `
    -Path $TestFile `
    -ItemType File `
    -Force | Out-Null


Write-Host "    Created: $TestFile"


Start-Sleep -Seconds 5


$FileCreateEvent = Get-WinEvent `
    -FilterHashtable @{
        LogName="Microsoft-Windows-Sysmon/Operational"
        Id=11
    } `
    -MaxEvents 20 `
    -ErrorAction SilentlyContinue |
    Where-Object {

        $_.Message -match "sysmon_test.txt"

    }


if ($FileCreateEvent) {

    Write-Host `
    "    Event ID 11 captured                 [VERIFIED]" `
    -ForegroundColor Green

}
else {

    Write-Host `
    "    Event ID 11 not found                [FAILED]" `
    -ForegroundColor Red

}



############################################################
# Final Output
############################################################

Write-Host ""
Write-Host "[*] Sysmon Deployment Complete" `
    -ForegroundColor Cyan
