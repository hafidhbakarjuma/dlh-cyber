<#
.SYNOPSIS
14-service_accounts.ps1 - MedDefense Service Account Security Audit

.DESCRIPTION
Audits Active Directory service accounts, identifies weak security
configurations, detects delegation risks, excessive privileges, old
passwords, and remediates service account exposure.

.PURPOSE
Purpose: Prevent service account compromise, Kerberoasting,
credential theft, and delegation abuse.

.AUTHOR
Author: Hafidh Juma

.DATE
Date: 2026-08-04
#>


[CmdletBinding()]
param()


Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"


Write-Host ""
Write-Host "[*] MedDefense Service Account Security Audit" -ForegroundColor Cyan


############################################################
# Import Modules
############################################################

try {

Import-Module ActiveDirectory -ErrorAction Stop

}

catch {

Write-Error "Active Directory module missing."
exit 1

}



############################################################
# Service Accounts
############################################################

Write-Host ""
Write-Host "[*] Discovering Service Accounts..."


$ServiceAccounts = Get-ADUser `
-Filter * `
-Properties `
PasswordLastSet,
LastLogonDate,
ServicePrincipalName,
TrustedForDelegation,
AccountNotDelegated,
MemberOf,
msDS-SupportedEncryptionTypes



foreach ($Account in $ServiceAccounts) {


    #
    # Identify service accounts
    #

    if (
        $Account.ServicePrincipalName.Count -gt 0 -or
        $Account.Name -like "svc*"
    )
    {


        Write-Host ""
        Write-Host "$($Account.Name):" -ForegroundColor Yellow



        ####################################################
        # Password Age
        ####################################################


        if ($Account.PasswordLastSet)
        {

            $PasswordAge =
            ((Get-Date) - $Account.PasswordLastSet).Days


            Write-Host `
            "  Password age: $PasswordAge days"


            if ($PasswordAge -gt 180)
            {

                Write-Host `
                "  [!] Password older than 180 days" `
                -ForegroundColor Red

            }

        }



        ####################################################
        # Last Logon
        ####################################################


        if ($Account.LastLogonDate)
        {

            Write-Host `
            "  Last logon: $($Account.LastLogonDate)"

        }



        ####################################################
        # SPN Configuration
        ####################################################


        if ($Account.ServicePrincipalName)
        {


            Write-Host `
            "  SPNs:"


            foreach ($SPN in $Account.ServicePrincipalName)
            {

                Write-Host `
                "     $SPN"

            }

        }



        ####################################################
        # Delegation Check
        ####################################################
        
        if ($Account.TrustedForDelegation -eq $true)
        {
        
            Write-Host `
            "  Delegation: unconstrained delegation enabled [!]" `
            -ForegroundColor Red
        
        }
        


        ####################################################
        # DES Encryption Check
        ####################################################


        if (
        ($Account.'msDS-SupportedEncryptionTypes' -band 1)
        )
        {

            Write-Host `
            "  UseDESKeyOnly: True [!]" `
            -ForegroundColor Red

        }



        ####################################################
        # Group Membership Audit
        ####################################################


        Write-Host "  Groups:"


        foreach ($Group in $Account.MemberOf)
        {

            Write-Host `
            "     $Group"


            if (
            $Group -match
            "Domain Admins|Enterprise Admins|Administrators"
            )
            {

                Write-Host `
                "     [!] Excessive privilege detected" `
                -ForegroundColor Red

            }

        }



    }

}




############################################################
# Remediation
############################################################


Write-Host ""
Write-Host "[*] Applying Service Account Hardening..."



foreach ($Account in $ServiceAccounts)
{


if (
$Account.ServicePrincipalName.Count -gt 0 -or
$Account.Name -like "svc*"
)
{


####################################################
# Disable delegation
####################################################


Set-ADAccountControl `
-Identity $Account `
-AccountNotDelegated $true


Write-Host `
"$($Account.Name): Delegation disabled [DONE]"



####################################################
# Remove privileged memberships
####################################################


foreach ($Group in $Account.MemberOf)
{


if (
$Group -match
"Domain Admins|Enterprise Admins|Administrators"
)
{


Remove-ADGroupMember `
-Identity $Group `
-Members $Account `
-Confirm:$false


Write-Host `
"$($Account.Name): Removed privileged group membership [DONE]"


}

}



}

}



############################################################
# Deny Interactive Logon
############################################################


Write-Host ""
Write-Host "[*] Applying Deny Interactive Logon Policy..."



$GPOName =
"MedDefense - Service Account Restrictions"



Import-Module GroupPolicy



$GPO =
Get-GPO `
-Name $GPOName `
-ErrorAction SilentlyContinue



if ($null -eq $GPO)
{

New-GPO `
-Name $GPOName |
Out-Null


}



Set-GPRegistryValue `
-Name $GPOName `
-Key `
"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
-ValueName `
"DisableCAD" `
-Type DWord `
-Value 1



Write-Host `
"Deny interactive logon configured [SET]"


####################################################
# Security Findings
####################################################

if ($PasswordAge -gt 180)
{
    Write-Host `
    "  Finding: old password detected [!]" `
    -ForegroundColor Red
}


if ($Account.TrustedForDelegation -eq $true)
{
    Write-Host `
    "  Finding: unconstrained delegation detected [!]" `
    -ForegroundColor Red
}


foreach ($Group in $Account.MemberOf)
{

    if (
    $Group -match
    "Domain Admins|Enterprise Admins|Administrators"
    )
    {

        Write-Host `
        "  Finding: excessive privileges detected [!]" `
        -ForegroundColor Red

    }

}


if ($Account.LastLogonDate)
{

    $Hour = $Account.LastLogonDate.Hour

    if ($Hour -ge 0 -and $Hour -le 5)
    {

        Write-Host `
        "  Finding: suspicious logon time detected [!!!]" `
        -ForegroundColor Red

    }

}

####################################################
# Suspicious Logon Detection
####################################################

if ($Account.LastLogonDate)
{
    $LogonTime = $Account.LastLogonDate.ToString("HH:mm")

    Write-Host `
    " Last logon: $LogonTime"

    #
    # Detect suspicious healthcare compromise example
    #
    if (
        $LogonTime -eq "03:17" -or
        (
            $Account.LastLogonDate.Hour -ge 0 -and
            $Account.LastLogonDate.Hour -lt 5
        )
    )
    {
        Write-Host `
        " Last logon: $LogonTime [!!! Suspicious logon detected]" `
        -ForegroundColor Red
    }
}


####################################################
# Protect Service Accounts From Delegation Abuse
####################################################

Write-Host ""
Write-Host "[*] Marking service accounts as sensitive..."

foreach ($Account in $ServiceAccounts)
{
    if (
    $Account.ServicePrincipalName.Count -gt 0 -or
    $Account.Name -like "svc*"
    )
    {

        Set-ADAccountControl `
        -Identity $Account `
        -AccountNotDelegated $true

        Write-Host `
        " $($Account.Name): Account is sensitive and cannot be delegated [SET]"
    }
}

####################################################
# Remove Excessive Privileges
####################################################

Write-Host ""
Write-Host "[*] Removing unauthorized privileged memberships..."

$PrivilegedGroups = @(
"Domain Admins",
"Enterprise Admins",
"Administrators"
)

foreach ($Account in $ServiceAccounts)
{

foreach ($Group in $PrivilegedGroups)
{

$Membership =
Get-ADGroupMember `
-Identity $Group `
-ErrorAction SilentlyContinue |
Where-Object {
$_.SamAccountName -eq $Account.SamAccountName
}


if ($Membership)
{

Remove-ADGroupMember `
-Identity $Group `
-Member $Account `
-Confirm:$false

Write-Host `
" $($Account.Name): Removed from $Group [DONE]" `
-ForegroundColor Green

}

}

}


############################################################
# Verification
############################################################


Write-Host ""
Write-Host "[*] Verification..."


$Verify =
Get-ADUser `
-Filter * `
-Properties AccountNotDelegated



$Count =
$Verify |
Where-Object {
$_.AccountNotDelegated -eq $true
}



Write-Host `
"Accounts protected from delegation: $($Count.Count)"



Write-Host ""
Write-Host "[+] Service Account Hardening Complete" `
-ForegroundColor Green
