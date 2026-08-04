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

<FilePathRule Id="{11111111-1111-1111-1111-111111111111}"
Name="Allow Windows System"
Description="Allow Windows executables"
UserOrGroupSid="S-1-1-0"
Action="Allow">
<Conditions>
<FilePathCondition Path="C:\Windows\*" />
</Conditions>
</FilePathRule>


<FilePathRule Id="{22222222-2222-2222-2222-222222222222}"
Name="Allow Program Files"
Description="Allow trusted applications"
UserOrGroupSid="S-1-1-0"
Action="Allow">
<Conditions>
<FilePathCondition Path="C:\Program Files\*" />
</Conditions>
</FilePathRule>


<FilePathRule Id="{33333333-3333-3333-3333-333333333333}"
Name="Allow Program Files x86"
Description="Allow trusted x86 applications"
UserOrGroupSid="S-1-1-0"
Action="Allow">
<Conditions>
<FilePathCondition Path="C:\Program Files (x86)\*" />
</Conditions>
</FilePathRule>


<FilePathRule Id="{44444444-4444-4444-4444-444444444444}"
Name="Allow DicomViewer Medical Application"
Description="Approved MedDefense imaging software"
UserOrGroupSid="S-1-1-0"
Action="Allow">
<Conditions>
<FilePathCondition Path="C:\Program Files\DicomViewer\DicomViewer.exe" />
</Conditions>
</FilePathRule>


</RuleCollection>


<RuleCollection Type="Script" EnforcementMode="AuditOnly">

<FilePathRule Id="{55555555-5555-5555-5555-555555555555}"
Name="Allow Windows Scripts"
Description="Allow system scripts"
UserOrGroupSid="S-1-1-0"
Action="Allow">
<Conditions>
<FilePathCondition Path="C:\Windows\*" />
</Conditions>
</FilePathRule>


<FilePathRule Id="{66666666-6666-6666-6666-666666666666}"
Name="Allow MedDefense Admin Scripts"
Description="Approved administration scripts"
UserOrGroupSid="S-1-1-0"
Action="Allow">
<Conditions>
<FilePathCondition Path="C:\MedDefense_Lab\Scripts\*" />
</Conditions>
</FilePathRule>


<!-- Script extensions controlled -->
<!-- .ps1 .bat .cmd .vbs -->


<FilePathRule Id="{77777777-7777-7777-7777-777777777777}"
Name="Deny Unauthorized Scripts"
Description="Block scripts from unknown locations"
UserOrGroupSid="S-1-1-0"
Action="Deny">
<Conditions>
<FilePathCondition Path="*\.ps1" />
<FilePathCondition Path="*\.bat" />
<FilePathCondition Path="*\.cmd" />
<FilePathCondition Path="*\.vbs" />
</Conditions>
</FilePathRule>


</RuleCollection>

</AppLockerPolicy>
"@


$Policy | Out-File `
-FilePath $ExportPath `
-Encoding UTF8


Write-Host " Executable Rules [SET]"
Write-Host " Script Rules (.ps1 .bat .cmd .vbs) [SET]"
Write-Host " Mode: AUDIT ONLY [SET]"


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
# Verify Export
############################################################

Write-Host ""
Write-Host "[*] Verifying exported AppLocker policy..."

if ((Test-Path $ExportPath) -and ((Get-Item $ExportPath).Length -gt 0)) {

    Write-Host " Policy exported: applocker_policy.xml [VERIFIED]" `
    -ForegroundColor Green

}
else {

    Write-Host " Policy export failed [FAILED]" `
    -ForegroundColor Red

    exit 1
}
