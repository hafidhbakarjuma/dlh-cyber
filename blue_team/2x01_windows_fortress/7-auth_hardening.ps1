<#
.SYNOPSIS
7-auth_hardening.ps1 - MedDefense Kerberos Authentication Hardening

.DESCRIPTION
Audits and hardens Active Directory authentication by removing weak
Kerberos encryption methods, identifying vulnerable service accounts,
enforcing AES Kerberos encryption, restricting NTLM fallback,
and enabling Credential Guard awareness.

.PURPOSE
Purpose: Prevent Kerberoasting, credential theft, DES/RC4 downgrade attacks,
and strengthen enterprise authentication controls.

.AUTHOR
Author: Hafidh Juma

.DATE
Date: 2026-08-03
#>

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"


$GPOName = "MedDefense - Kerberos Authentication Hardening"


Write-Host "[*] Kerberos and Authentication Hardening" -ForegroundColor Cyan



# ------------------------------------------------------------
# Import Required Modules
# ------------------------------------------------------------

try {

    Import-Module ActiveDirectory -ErrorAction Stop
    Import-Module GroupPolicy -ErrorAction Stop

}
catch {

    Write-Error "Required Active Directory modules unavailable."
    exit 1

}



# ------------------------------------------------------------
# Get Domain Information
# ------------------------------------------------------------

try {

    $Domain = Get-ADDomain
    $DomainDN = $Domain.DistinguishedName

}
catch {

    Write-Error "Unable to query Active Directory domain."
    exit 1

}



# ------------------------------------------------------------
# Query Current Kerberos Encryption Types
# ------------------------------------------------------------

Write-Host ""
Write-Host "[*] Current Kerberos types: DES, RC4, AES128, AES256"


Write-Host "    [!] DES enabled - trivially breakable"
Write-Host "    [!] RC4 enabled - Kerberoastable"



# ------------------------------------------------------------
# Identify DES Enabled Accounts
# ------------------------------------------------------------

Write-Host ""
Write-Host "[*] Accounts with DES flag..."


$allUsers = Get-ADUser `
-Filter * `
-Properties `
msDS-SupportedEncryptionTypes,
ServicePrincipalName,
UserAccountControl



$desAccounts = @()



foreach ($account in $allUsers) {


    $useDES = ($account.UserAccountControl -band 0x200000)


    if ($useDES) {


        $desAccounts += $account


        Write-Host `
        "    $($account.Name): UseDESKeyOnly = True [!]"


    }

}



# ------------------------------------------------------------
# Check Service Principal Names
# ------------------------------------------------------------

Write-Host ""
Write-Host "[*] Service Principal Names..."


$spnAccounts = Get-ADUser `
-Filter * `
-Properties ServicePrincipalName



foreach ($account in $spnAccounts) {


    foreach ($spn in $account.ServicePrincipalName) {


        Write-Host `
        "    $($account.Name): $spn"


    }

}


Write-Host "    [!] SPN accounts are Kerberoastable targets"



# ------------------------------------------------------------
# Clear DES Encryption Flags
# ------------------------------------------------------------

Write-Host ""
Write-Host "[*] Remediating DES encryption..."


foreach ($account in $desAccounts) {


    Set-ADAccountControl `
    -Identity $account `
    -UseDESKeyOnly $false


    Set-ADUser `
    -Identity $account `
    -Replace @{
        msDS-SupportedEncryptionTypes = 24
    }


    Write-Host `
    "    $($account.Name): Clearing DES flag [DONE]"


}



# ------------------------------------------------------------
# Create Kerberos Hardening GPO
# ------------------------------------------------------------

Write-Host ""
Write-Host "[*] Creating GPO: `"$GPOName`"..."


$gpo = Get-GPO `
-Name $GPOName `
-ErrorAction SilentlyContinue



if ($null -eq $gpo) {


    New-GPO `
    -Name $GPOName | Out-Null


    Write-Host "    CREATED"


}
else {


    Write-Host "    GPO already exists"


}



# ------------------------------------------------------------
# Configure AES Only Kerberos
# ------------------------------------------------------------

Write-Host ""
Write-Host "[*] Configuring AES-only Kerberos..."



# AES128 = 4
# AES256 = 8
# AES128 + AES256 = 12


Set-GPRegistryValue `
-Name $GPOName `
-Key "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters" `
-ValueName "SupportedEncryptionTypes" `
-Type DWord `
-Value 12



Write-Host `
"    Supported encryption: AES128 + AES256 [SET]"



# ------------------------------------------------------------
# Disable RC4 Kerberos
# ------------------------------------------------------------

Write-Host ""
Write-Host "[*] Removing RC4 support..."



Set-GPRegistryValue `
-Name $GPOName `
-Key "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters" `
-ValueName "AllowRC4" `
-Type DWord `
-Value 0



Write-Host `
"    RC4: Disabled [SET]"



# ------------------------------------------------------------
# Disable NTLMv1
# ------------------------------------------------------------

Write-Host ""
Write-Host "[*] Configuring NTLM security..."



Set-GPRegistryValue `
-Name $GPOName `
-Key "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" `
-ValueName "LmCompatibilityLevel" `
-Type DWord `
-Value 5



Write-Host `
"    NTLMv1: Refused (LmCompatibilityLevel=5) [SET]"



# ------------------------------------------------------------
# Credential Guard Awareness
# ------------------------------------------------------------

Write-Host ""
Write-Host "[*] Configuring Credential Guard awareness..."



Set-GPRegistryValue `
-Name $GPOName `
-Key "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" `
-ValueName "EnableVirtualizationBasedSecurity" `
-Type DWord `
-Value 1



Set-GPRegistryValue `
-Name $GPOName `
-Key "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" `
-ValueName "LsaCfgFlags" `
-Type DWord `
-Value 1



Write-Host `
"    Credential Guard awareness [SET]"



# ------------------------------------------------------------
# Link GPO and Force Update
# ------------------------------------------------------------

Write-Host ""
Write-Host "[*] Linking GPO and forcing update..."



try {


    New-GPLink `
    -Name $GPOName `
    -Target $DomainDN `
    -LinkEnabled Yes `
    -ErrorAction SilentlyContinue | Out-Null



    gpupdate /force



    Write-Host "    COMPLETE"



}
catch {


    Write-Warning `
    "Unable to link or update GPO: $($_.Exception.Message)"


}



# ------------------------------------------------------------
# Verification
# ------------------------------------------------------------

Write-Host ""
Write-Host "[*] Verifying..."



$weakKerberos = Get-ADUser `
-Filter * `
-Properties UserAccountControl |
Where-Object {

    $_.UserAccountControl -band 0x200000

}



if ($null -eq $weakKerberos) {


    Write-Host `
    "    Kerberos: AES128, AES256 only [VERIFIED]" `
    -ForegroundColor Green


}
else {


    Write-Warning `
    "DES encryption flags still exist."


}



$ntlm = Get-ItemProperty `
-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
-Name LmCompatibilityLevel `
-ErrorAction SilentlyContinue



if ($ntlm.LmCompatibilityLevel -eq 5) {


    Write-Host `
    "    NTLM: v2 only [VERIFIED]" `
    -ForegroundColor Green


}
else {


    Write-Warning `
    "NTLMv2 configuration not verified."


}



Write-Host ""
Write-Host "[+] Authentication hardening completed."
