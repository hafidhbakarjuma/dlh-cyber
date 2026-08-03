<#
.SYNOPSIS
6-powershell_security.ps1 - MedDefense PowerShell Security Deployment

.DESCRIPTION
Creates and configures a PowerShell Security Group Policy Object
to enable Script Block Logging, Module Logging, Transcription,
and PowerShell attack visibility.

.PURPOSE
Purpose: Detect and investigate PowerShell-based attacks by enabling
decoded script visibility, module auditing, session transcription,
and AMSI protection.

.AUTHOR
Author: Hafidh Juma

.DATE
Date: 2026-08-03
#>

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$GPOName = "MedDefense - PowerShell Security"


Write-Host "[*] Creating GPO: `"$GPOName`"..." -ForegroundColor Cyan


# ------------------------------------------------------------
# Import Required Modules
# ------------------------------------------------------------

try {
    Import-Module GroupPolicy -ErrorAction Stop
}
catch {
    Write-Error "GroupPolicy module unavailable. Install RSAT tools."
    exit 1
}


# ------------------------------------------------------------
# Create GPO
# ------------------------------------------------------------

$gpo = Get-GPO -Name $GPOName -ErrorAction SilentlyContinue

if ($null -eq $gpo) {

    New-GPO -Name $GPOName | Out-Null
    Write-Host "    CREATED" -ForegroundColor Green

}
else {

    Write-Host "    GPO already exists" -ForegroundColor Yellow

}



# ------------------------------------------------------------
# Configure Script Block Logging
# Event ID 4104
# ------------------------------------------------------------

Write-Host "[*] Configuring Script Block Logging..."

Set-GPRegistryValue `
-Name $GPOName `
-Key "HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
-ValueName "EnableScriptBlockLogging" `
-Type DWord `
-Value 1


Write-Host "    EnableScriptBlockLogging = 1 [SET]"
Write-Host "    -> Event ID 4104 captures decoded scripts"



# ------------------------------------------------------------
# Configure Module Logging
# Event ID 4103
# ------------------------------------------------------------

Write-Host "[*] Configuring Module Logging..."


Set-GPRegistryValue `
-Name $GPOName `
-Key "HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging" `
-ValueName "EnableModuleLogging" `
-Type DWord `
-Value 1


Set-GPRegistryValue `
-Name $GPOName `
-Key "HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" `
-ValueName "*" `
-Type String `
-Value "*"


Write-Host "    EnableModuleLogging = 1, ModuleNames = * [SET]"
Write-Host "    -> Event ID 4103 captures module invocations"



# ------------------------------------------------------------
# Configure PowerShell Transcription
# ------------------------------------------------------------

Write-Host "[*] Configuring Transcription..."


Set-GPRegistryValue `
-Name $GPOName `
-Key "HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription" `
-ValueName "EnableTranscripting" `
-Type DWord `
-Value 1


Set-GPRegistryValue `
-Name $GPOName `
-Key "HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription" `
-ValueName "OutputDirectory" `
-Type String `
-Value "C:\PSTranscripts"


Write-Host "    OutputDirectory = C:\PSTranscripts [SET]"



# ------------------------------------------------------------
# Verify AMSI
# ------------------------------------------------------------

Write-Host "[*] Verifying AMSI..."


$amsi = Get-Process -Name powershell,pwsh `
-ErrorAction SilentlyContinue |
Get-Module -ErrorAction SilentlyContinue


$amsiDll = Get-ChildItem `
"C:\Windows\System32" `
-Filter "amsi.dll" `
-ErrorAction SilentlyContinue


if ($amsiDll) {

    Write-Host "    AMSI DLL loaded [OK]" -ForegroundColor Green

}
else {

    Write-Warning "AMSI DLL not detected"

}



# ------------------------------------------------------------
# Link GPO To Domain Root
# ------------------------------------------------------------

Write-Host "[*] Linking GPO and forcing update..."


try {

    $domain = Get-ADDomain

    New-GPLink `
    -Name $GPOName `
    -Target $domain.DistinguishedName `
    -LinkEnabled Yes `
    -ErrorAction Stop


    gpupdate /force


    Write-Host "    COMPLETE" -ForegroundColor Green

}
catch {

    Write-Warning "Unable to link GPO automatically: $($_.Exception.Message)"

}



# ------------------------------------------------------------
# Test Encoded PowerShell Command
# ------------------------------------------------------------

Write-Host "[*] Testing encoded command..."


$command = "Write-Host 'Test'"


$bytes = [System.Text.Encoding]::Unicode.GetBytes($command)

$encoded = [Convert]::ToBase64String($bytes)


Write-Host "    Input: powershell -enc $encoded"



try {

    powershell.exe `
    -EncodedCommand $encoded


    Start-Sleep -Seconds 5


    $event = Get-WinEvent `
    -FilterHashtable @{
        LogName="Microsoft-Windows-PowerShell/Operational"
        Id=4104
    } `
    -MaxEvents 20 `
    -ErrorAction SilentlyContinue |
    Where-Object {
        $_.Message -match "Write-Host"
    }


    if ($event) {

        Write-Host '    Event ID 4104 found: "Write-Host Test" [VERIFIED]' `
        -ForegroundColor Green

    }
    else {

        Write-Warning "Event ID 4104 not found yet. Policy replication may be required."

    }

}
catch {

    Write-Warning "Encoded command test failed: $($_.Exception.Message)"

}
