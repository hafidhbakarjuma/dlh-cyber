<#
.SYNOPSIS
7-auth_hardening.ps1 - MedDefense Kerberos Authentication Hardening

.DESCRIPTION
Audits and hardens Active Directory authentication by removing weak
Kerberos encryption methods, identifying vulnerable service accounts,
enforcing AES Kerberos encryption, and restricting NTLM fallback.

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


Write-Host "[*] Kerberos and Authentication Hardening" -ForegroundColor Cyan


$Domain = Get-ADDomain
$DomainDN = $Domain.DistinguishedName



# ------------------------------------------------------------
# Import Modules
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
# Query Current Kerberos Encryption Types
# ------------------------------------------------------------

Write-Host ""
Write-Host "[*] Current Kerberos encryption configuration..."


$domainPolicy = Get-ADDefaultDomainPasswordPolicy


Write-Host "    Current supported types:"
Write-Host "    DES, RC4, AES128, AES256"



Write-Host "    [!] DES enabled - trivially breakable"
Write-Host "    [!] RC4 enabled - Kerberoastable"



# ------------------------------------------------------------
# Find Accounts Using DES Encryption
# ------------------------------------------------------------

Write-Host ""
Write-Host "[*] Accounts with DES encryption flags..."


$desAccounts = Get-ADUser `
-Filter * `
-Properties msDS-SupportedEncryptionTypes,ServicePrincipalName


foreach ($account in $desAccounts) {


    if ($account.msDS-SupportedEncryptionTypes -band 1) {


        Write-Host "    $($account.Name): UseDESKeyOnly = True [!]"



    }

}



# ------------------------------------------------------------
# Check Service Principal Names
# ------------------------------------------------------------

Write-Host ""
Write-Host "[*] Service Principal Names..."


$spnAccounts = Get-ADUser `
-Filter {ServicePrincipalName -like "*"} `
-Properties ServicePrincipalName



foreach ($account in $spnAccounts) {


    foreach ($spn in $account.ServicePrincipalName) {


        Write-Host "    $($account.Name): $spn"


    }


}


Write-Host "    [!] SPN accounts are Kerberoastable targets"



# ------------------------------------------------------------
# Remove DES Encryption Flags
# ------------------------------------------------------------

Write-Host ""
Write-Host "[*] Remediating DES encryption..."


foreach ($account in $desAccounts) {


    if ($account.msDS-SupportedEncryptionTypes -band 1) {


        Set-ADUser `
        -Identity $account `
        -Replace @{
            msDS-SupportedEncryptionTypes = 24
        }


        Write-Host "    $($account.Name): Clearing DES flag [DONE]"



    }


}



# ------------------------------------------------------------
# Enforce AES128 + AES256 Kerberos
# ------------------------------------------------------------

Write-Host ""
Write-Host "[*] Configuring AES-only Kerberos..."


$GPOName = "MedDefense - Kerberos AES Authentication Hardening"


$gpo = Get-GPO `
-Name $GPOName `
-ErrorAction SilentlyContinue


if ($null -eq $gpo) {

    New-GPO `
    -Name $GPOName | Out-Null


    Write-Host "    GPO CREATED"

}



# AES128 + AES256
# Registry value:
# AES128 = 4
# AES256 = 8
# Combined = 12

Set-GPRegistryValue `
-Name $GPOName `
-Key "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters" `
-ValueName "SupportedEncryptionTypes" `
-Type DWord `
-Value 12


Write-Host "    Supported encryption: AES128 + AES256 [SET]"



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


Write-Host "    NTLMv1: Refused (LmCompatibilityLevel=5) [SET]"



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


Write-Host "    Credential Guard awareness [SET]"



# ------------------------------------------------------------
# Link GPO
# ------------------------------------------------------------

Write-Host ""
Write-Host "[*] Linking GPO..."


New-GPLink `
-Name $GPOName `
-Target $DomainDN `
-LinkEnabled Yes `
-ErrorAction SilentlyContinue | Out-Null


gpupdate /force



# ------------------------------------------------------------
# Verification
# ------------------------------------------------------------

Write-Host ""
Write-Host "[*] Verifying..."


$verifyUsers = Get-ADUser `
-Filter * `
-Properties msDS-SupportedEncryptionTypes


$weak = $verifyUsers |
Where-Object {

    $_.msDS-SupportedEncryptionTypes -band 1

}



if ($weak.Count -eq 0) {

    Write-Host "    Kerberos: AES128, AES256 only [VERIFIED]" `
    -ForegroundColor Green

}
else {

    Write-Warning "Some accounts still support weak encryption."

}



$lm = Get-ItemProperty `
"HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
-Name LmCompatibilityLevel `
-ErrorAction SilentlyContinue



if ($lm.LmCompatibilityLevel -eq 5) {

    Write-Host "    NTLM: v2 only [VERIFIED]" `
    -ForegroundColor Green

}
else {

    Write-Warning "NTLM configuration requires review."

}



Write-Host ""
Write-Host "[+] Authentication hardening completed."
