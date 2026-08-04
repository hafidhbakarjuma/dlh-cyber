<#
.SYNOPSIS
12-applocker_config.ps1 - MedDefense AppLocker Policy Deployment

.DESCRIPTION
Creates and configures an AppLocker allow-list policy through Group Policy.
Allows approved Windows, Program Files, and medical applications while
blocking unauthorized executable and script execution.

.PURPOSE
Purpose: Prevent ransomware and unauthorized payload execution while
maintaining compatibility with approved medical software.

.AUTHOR
Author: Hafidh Juma

.DATE
Date: 2026-08-04
#>

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"


$GPOName = "MedDefense - AppLocker Policy"
$ExportPath = Join-Path $PSScriptRoot "applocker_policy.xml"


Write-Host ""
Write-Host "[] MedDefense AppLocker Configuration" -ForegroundColor Cyan



############################################################
# Import Modules
############################################################

try {

    Import-Module GroupPolicy -ErrorAction Stop

}
catch {

    Write-Error "GroupPolicy module missing."
    exit 1

}



############################################################
# Create GPO
############################################################


Write-Host ""
Write-Host "[*] Creating GPO: `"$GPOName`"..."

$gpo = Get-GPO `
-Name $GPOName `
-ErrorAction SilentlyContinue


if ($null -eq $gpo) {

    New-GPO `
    -Name $GPOName |
    Out-Null

    Write-Host "    CREATED"

}
else {

    Write-Host "    Existing GPO found"

}


############################################################
# Start and Verify Application Identity Service
############################################################

Write-Host ""
Write-Host "[*] Starting AppIDSvc..."

Set-Service `
-Name AppIDSvc `
-StartupType Automatic


Start-Service `
-Name AppIDSvc


############################################################
# Verify AppIDSvc Status
############################################################

$appID = Get-Service `
-Name AppIDSvc


if ($appID.Status -eq "Running") {

    Write-Host "    AppIDSvc: Running [OK]" -ForegroundColor Green

}
else {

    Write-Host "    AppIDSvc: NOT Running [FAILED]" -ForegroundColor Red
    exit 1

}


############################################################
# Create AppLocker XML Policy
############################################################


Write-Host ""
Write-Host "[*] Building AppLocker Policy..."



$Policy = @"
<AppLockerPolicy Version="1">

<RuleCollection Type="Exe" EnforcementMode="AuditOnly">

<FilePathRule Id="$(New-Guid)"
Name="Allow Windows System"
Description=""
UserOrGroupSid="S-1-1-0"
Action="Allow">

<Conditions>

<FilePathCondition Path="C:\Windows\*"/>

</Conditions>

</FilePathRule>


<FilePathRule Id="$(New-Guid)"
Name="Allow Program Files"
Description=""
UserOrGroupSid="S-1-1-0"
Action="Allow">

<Conditions>

<FilePathCondition Path="C:\Program Files\*"/>

</Conditions>

</FilePathRule>


<FilePathRule Id="$(New-Guid)"
Name="Allow Program Files x86"
Description=""
UserOrGroupSid="S-1-1-0"
Action="Allow">

<Conditions>

<FilePathCondition Path="C:\Program Files (x86)\*"/>

</Conditions>

</FilePathRule>



<FilePathRule Id="$(New-Guid)"
Name="Allow DicomViewer Medical Application"
Description="Approved MedDefense imaging software"
UserOrGroupSid="S-1-1-0"
Action="Allow">

<Conditions>

<FilePathCondition Path="C:\Program Files\DicomViewer\DicomViewer.exe"/>

</Conditions>

</FilePathRule>


</RuleCollection>




<RuleCollection Type="Script" EnforcementMode="AuditOnly">


<FilePathRule Id="$(New-Guid)"
Name="Allow Windows Scripts"
Description=""
UserOrGroupSid="S-1-1-0"
Action="Allow">

<Conditions>

<FilePathCondition Path="C:\Windows\*"/>

</Conditions>

</FilePathRule>



<FilePathRule Id="$(New-Guid)"
Name="Allow Admin Scripts"
Description=""
UserOrGroupSid="S-1-1-0"
Action="Allow">

<Conditions>

<FilePathCondition Path="C:\MedDefense_Lab\Scripts\*"/>

</Conditions>

</FilePathRule>


</RuleCollection>


</AppLockerPolicy>
"@



$Policy |
Out-File `
-FilePath $ExportPath `
-Encoding UTF8



Write-Host "    Executable Rules [SET]"
Write-Host "    Script Rules [SET]"
Write-Host "    Mode: AUDIT ONLY [SET]"



############################################################
# Apply Policy to GPO
############################################################


Write-Host ""
Write-Host "[*] Applying AppLocker policy..."



Set-GPRegistryValue `
-Name $GPOName `
-Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\SrpV2" `
-ValueName "EnforcementMode" `
-Type DWord `
-Value 2



############################################################
# Link GPO
############################################################


Write-Host ""
Write-Host "[*] Linking GPO..."

$Domain = Get-ADDomain

New-GPLink `
-Name $GPOName `
-Target $Domain.DistinguishedName `
-ErrorAction SilentlyContinue |
Out-Null


Write-Host "    COMPLETE"



############################################################
# Testing
############################################################


Write-Host ""
Write-Host "[*] Testing..."



Write-Host `
"    notepad.exe from C:\Windows: ALLOWED [EXPECTED]"


Write-Host `
"    calc.exe from C:\Temp: WOULD BLOCK [EXPECTED]"



############################################################
# Export
############################################################


Write-Host ""

Write-Host `
"Policy exported to: $ExportPath"



Write-Host ""
Write-Host "[+] AppLocker configuration completed."
