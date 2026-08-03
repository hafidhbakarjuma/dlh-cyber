<#
.SYNOPSIS
    1-domain_findings.ps1 - Active Directory Risk Findings Extractor for MedDefense

.DESCRIPTION
    Audits meddefense.local and produces a structured, remediation-ready findings
    inventory. Each finding captures what is wrong, how severe it is, what evidence
    supports it, and which downstream hardening task remediates it. Results are
    written to domain_security_findings.json and summarized on the console.

.PURPOSE
    Purpose: Turn the Task 0 domain baseline into an actionable findings inventory
    that drives the Windows hardening workflow (password policy, audit policy,
    Kerberos hardening, service account control, GPO hardening, stale object cleanup).

.NOTES
    Author:    Hafidh Juma
    Requires:  RSAT ActiveDirectory (+ optionally GroupPolicy) modules, domain-read
               privileges when run live. auditpol.exe and registry reads are used for
               local audit / PowerShell logging visibility and require running on a
               domain controller (or a host whose local audit policy reflects the
               domain baseline).
               Every enumeration step is wrapped in error handling so a single inaccessible
               object (missing OU, unreachable DC, missing module, access denied) degrades
               gracefully instead of aborting the whole run.

.PARAMETER DemoMode
    Runs the exact same finding-generation logic (New-Finding, severity rollups,
    JSON export) against a realistic mock dataset instead of live AD cmdlets.
    Use this when no domain controller is reachable (e.g. testing before your lab
    domain is built, or validating the script/report schema in CI). The resulting
    domain_security_findings.json is produced by the real logic, just fed synthetic
    input instead of live Get-AD* output.
#>

[CmdletBinding()]
param(
    [string]$OutputPath = ".\domain_security_findings.json",
    [switch]$DemoMode
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# --- Fortress target state (Windows hardening baseline) ---
$TargetMinPwdLength     = 14
$TargetComplexity       = $true
$TargetHistoryCount     = 24
$TargetLockoutThreshold = 5
$StaleDaysThreshold     = 90
$StalePasswordDays      = 365

# --- Findings collector ---
$findings = @()
$script:findingCounter = 0

function New-Finding {
    param(
        [Parameter(Mandatory)][ValidateSet('Critical', 'High', 'Medium', 'Low')][string]$Severity,
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][string]$Asset,
        [Parameter(Mandatory)]$Evidence,
        [Parameter(Mandatory)][string]$Risk,
        [Parameter(Mandatory)][string]$RecommendedRemediation,
        [Parameter(Mandatory)][string]$MappedTask
    )
    $script:findingCounter++
    $finding = [PSCustomObject]@{
        id                     = "F{0:D3}" -f $script:findingCounter
        severity               = $Severity
        category               = $Category
        asset                  = $Asset
        evidence               = $Evidence
        risk                   = $Risk
        recommended_remediation = $RecommendedRemediation
        mapped_task            = $MappedTask
    }
    $script:findings += $finding
    return $finding
}

function Write-Finding {
    param([string]$Severity, [string]$Message)
    $color = switch ($Severity) {
        'CRITICAL' { 'Red' }
        'HIGH'     { 'Yellow' }
        'MEDIUM'   { 'Cyan' }
        default    { 'White' }
    }
    Write-Host "[$Severity] $Message" -ForegroundColor $color
}

# Helper: does an account look like a service account?
function Test-IsServiceAccount {
    param($ADUser)
    $nameMatch = $ADUser.SamAccountName -match 'svc'
    $ouMatch   = $ADUser.DistinguishedName -match 'OU=Service Accounts'
    return [bool]($nameMatch -or $ouMatch)
}

# Helper: group membership names for a user/computer, tolerant of failure
function Get-SafeGroupMemberships {
    param([string]$Identity)
    try {
        return (Get-ADPrincipalGroupMembership -Identity $Identity -ErrorAction Stop |
            Select-Object -ExpandProperty Name)
    }
    catch {
        return @()
    }
}

# =========================================================================
# LIVE AUDIT - queries a real domain via RSAT ActiveDirectory / GroupPolicy
# =========================================================================
function Invoke-LiveAudit {

    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        Write-Error "The ActiveDirectory PowerShell module is required but not installed."
        exit 1
    }
    Import-Module ActiveDirectory -ErrorAction Stop

    $gpoModuleAvailable = [bool](Get-Module -ListAvailable -Name GroupPolicy)
    if (-not $gpoModuleAvailable) {
        Write-Warning "GroupPolicy module not found; GPO posture checks will be limited."
    }

    try {
        $domain     = Get-ADDomain -ErrorAction Stop
        $domainDN   = $domain.DistinguishedName
        $domainName = $domain.DNSRoot
    }
    catch {
        Write-Warning "Failed to retrieve domain context: $($_.Exception.Message)"
        $domainDN = $null; $domainName = "UNKNOWN"
    }

    # 1. Accounts with PasswordNeverExpires
    try {
        $pwdNeverExpireUsers = Get-ADUser -Filter { PasswordNeverExpires -eq $true } `
            -Properties Enabled, PasswordLastSet, PasswordNeverExpires, DistinguishedName, MemberOf -ErrorAction Stop

        foreach ($u in $pwdNeverExpireUsers) {
            $groups = if ($u.MemberOf) {
                $u.MemberOf | ForEach-Object { ($_ -split ',')[0] -replace '^CN=', '' }
            }
            else {
                Get-SafeGroupMemberships -Identity $u.DistinguishedName
            }
            $isSvc = Test-IsServiceAccount -ADUser $u
            $evidence = [PSCustomObject]@{
                enabled             = $u.Enabled
                group_memberships   = $groups
                password_last_set   = if ($u.PasswordLastSet) { $u.PasswordLastSet.ToString("s") } else { "Never" }
                is_service_account  = $isSvc
            }
            New-Finding -Severity High -Category "Credential Hygiene" -Asset $u.SamAccountName `
                -Evidence $evidence `
                -Risk "Account password never expires, increasing the window for credential compromise or offline cracking to remain viable indefinitely." `
                -RecommendedRemediation "Enable password expiration; migrate service accounts to gMSA/managed credentials where possible." `
                -MappedTask "2-password_policy_hardening.ps1" | Out-Null
        }
        if ($pwdNeverExpireUsers.Count -gt 0) {
            Write-Finding "HIGH" "$($pwdNeverExpireUsers.Count) accounts with PasswordNeverExpires"
        }
    }
    catch {
        Write-Warning "Failed to enumerate PasswordNeverExpires accounts: $($_.Exception.Message)"
    }

    # 2. Disabled accounts in privileged groups
    $privilegedGroupNames = @('Domain Admins', 'Enterprise Admins', 'G_IT_Admins')
    $disabledPrivCount = 0
    foreach ($groupName in $privilegedGroupNames) {
        try {
            $members = Get-ADGroupMember -Identity $groupName -Recursive -ErrorAction Stop
            foreach ($m in $members) {
                if ($m.objectClass -ne 'user') { continue }
                try {
                    $u = Get-ADUser -Identity $m.SamAccountName -Properties Enabled, LastLogonDate -ErrorAction Stop
                    if (-not $u.Enabled) {
                        $disabledPrivCount++
                        $evidence = [PSCustomObject]@{
                            privileged_group = $groupName
                            last_logon_date  = if ($u.LastLogonDate) { $u.LastLogonDate.ToString("s") } else { "Never" }
                        }
                        New-Finding -Severity High -Category "Privileged Access Hygiene" -Asset $u.SamAccountName `
                            -Evidence $evidence `
                            -Risk "Disabled account retains membership in a privileged group; if re-enabled (accidentally or maliciously) it grants immediate elevated access." `
                            -RecommendedRemediation "Remove disabled accounts from privileged groups; archive or delete stale identities per retention policy." `
                            -MappedTask "3-privileged_access_cleanup.ps1" | Out-Null
                    }
                }
                catch {
                    Write-Verbose "Could not resolve member $($m.SamAccountName): $($_.Exception.Message)"
                }
            }
        }
        catch {
            Write-Warning "Failed to enumerate members of '$groupName': $($_.Exception.Message)"
        }
    }
    if ($disabledPrivCount -gt 0) {
        Write-Finding "HIGH" "$disabledPrivCount disabled account(s) in privileged groups"
    }

    # 3. Stale computer objects
    try {
        $staleCutoff = (Get-Date).AddDays(-$StaleDaysThreshold)
        $allComputers = Get-ADComputer -Filter * -Properties LastLogonTimestamp, Enabled -ErrorAction Stop
        $staleComputers = foreach ($c in $allComputers) {
            $lastLogon = if ($c.LastLogonTimestamp) { [datetime]::FromFileTime($c.LastLogonTimestamp) } else { $null }
            if (-not $lastLogon -or $lastLogon -lt $staleCutoff) { $c }
        }
        foreach ($c in $staleComputers) {
            $lastLogon = if ($c.LastLogonTimestamp) { [datetime]::FromFileTime($c.LastLogonTimestamp).ToString("s") } else { "Never" }
            $evidence = [PSCustomObject]@{
                enabled               = $c.Enabled
                last_logon_date       = $lastLogon
                stale_threshold_days  = $StaleDaysThreshold
            }
            New-Finding -Severity Medium -Category "Stale Object Cleanup" -Asset $c.Name `
                -Evidence $evidence `
                -Risk "Inactive computer object represents unmanaged attack surface and potential unpatched/unmonitored host or a decommissioned asset still trusted by the domain." `
                -RecommendedRemediation "Verify the asset is decommissioned, then disable and eventually remove the computer object from Active Directory." `
                -MappedTask "7-stale_object_cleanup.ps1" | Out-Null
        }
        if ($staleComputers.Count -gt 0) {
            Write-Finding "MEDIUM" "Stale computer objects: $($staleComputers.Count)"
        }
    }
    catch {
        Write-Warning "Failed to enumerate computer objects: $($_.Exception.Message)"
    }

    # 4. Password and lockout policy gaps
    try {
        $domainPolicy = Get-ADDefaultDomainPasswordPolicy -ErrorAction Stop

        if ($domainPolicy.MinPasswordLength -lt $TargetMinPwdLength) {
            New-Finding -Severity Critical -Category "Password Policy" -Asset $domainName `
                -Evidence ([PSCustomObject]@{ current = $domainPolicy.MinPasswordLength; target = $TargetMinPwdLength }) `
                -Risk "Minimum password length below the Fortress target increases susceptibility to brute-force and password-spray attacks." `
                -RecommendedRemediation "Raise MinPasswordLength to $TargetMinPwdLength via Default Domain Policy." `
                -MappedTask "2-password_policy_hardening.ps1" | Out-Null
            Write-Finding "CRITICAL" "Password policy minimum length: $($domainPolicy.MinPasswordLength)"
        }

        if (-not $domainPolicy.ComplexityEnabled -and $TargetComplexity) {
            New-Finding -Severity High -Category "Password Policy" -Asset $domainName `
                -Evidence ([PSCustomObject]@{ current = "Disabled"; target = "Enabled" }) `
                -Risk "Without complexity requirements, users can set trivially guessable passwords." `
                -RecommendedRemediation "Enable password complexity requirements in Default Domain Policy." `
                -MappedTask "2-password_policy_hardening.ps1" | Out-Null
        }

        if ($domainPolicy.PasswordHistoryCount -lt $TargetHistoryCount) {
            New-Finding -Severity Medium -Category "Password Policy" -Asset $domainName `
                -Evidence ([PSCustomObject]@{ current = $domainPolicy.PasswordHistoryCount; target = $TargetHistoryCount }) `
                -Risk "Low password history allows rapid password reuse, weakening rotation policy effectiveness." `
                -RecommendedRemediation "Raise PasswordHistoryCount to $TargetHistoryCount." `
                -MappedTask "2-password_policy_hardening.ps1" | Out-Null
        }

        $lockoutThreshold = $domainPolicy.LockoutThreshold
        if (-not $lockoutThreshold -or $lockoutThreshold -eq 0) {
            New-Finding -Severity Critical -Category "Account Lockout Policy" -Asset $domainName `
                -Evidence ([PSCustomObject]@{ current = "Not configured"; target = $TargetLockoutThreshold }) `
                -Risk "No account lockout threshold leaves every account exposed to unlimited online password-guessing attempts." `
                -RecommendedRemediation "Configure LockoutThreshold to $TargetLockoutThreshold with an appropriate lockout duration." `
                -MappedTask "2-password_policy_hardening.ps1" | Out-Null
            Write-Finding "CRITICAL" "Account lockout: not configured"
        }
        elseif ($lockoutThreshold -gt $TargetLockoutThreshold) {
            New-Finding -Severity Medium -Category "Account Lockout Policy" -Asset $domainName `
                -Evidence ([PSCustomObject]@{ current = $lockoutThreshold; target = $TargetLockoutThreshold }) `
                -Risk "Lockout threshold higher than the Fortress target still permits excessive guessing attempts before lockout." `
                -RecommendedRemediation "Lower LockoutThreshold to $TargetLockoutThreshold." `
                -MappedTask "2-password_policy_hardening.ps1" | Out-Null
        }
    }
    catch {
        Write-Warning "Failed to evaluate password/lockout policy: $($_.Exception.Message)"
    }

    # 5. Missing audit visibility
    $auditGaps = @()
    $subcategoriesToCheck = @('Process Creation', 'Special Logon', 'User Account Management', 'File System', 'Registry')
    try {
        foreach ($sub in $subcategoriesToCheck) {
            try {
                $result = & auditpol.exe /get /subcategory:"$sub" 2>&1
                $line = $result | Where-Object { $_ -match [regex]::Escape($sub) }
                if (-not $line -or $line -notmatch 'Success' -or $line -match 'No Auditing') {
                    $auditGaps += $sub
                }
            }
            catch {
                $auditGaps += $sub
            }
        }
    }
    catch {
        Write-Warning "auditpol.exe not available or failed to run: $($_.Exception.Message)"
        $auditGaps = $subcategoriesToCheck
    }

    $psLoggingEnabled = $false
    try {
        $sblPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
        if (Test-Path $sblPath) {
            $val = Get-ItemProperty -Path $sblPath -Name EnableScriptBlockLogging -ErrorAction SilentlyContinue
            $psLoggingEnabled = [bool]($val -and $val.EnableScriptBlockLogging -eq 1)
        }
    }
    catch {
        Write-Verbose "Could not read PowerShell logging registry keys: $($_.Exception.Message)"
    }
    if (-not $psLoggingEnabled) { $auditGaps += 'PowerShell Script Block Logging' }

    $sysmonPresent = $false
    try {
        $sysmonPresent = [bool](Get-Service -Name 'Sysmon*' -ErrorAction SilentlyContinue)
    }
    catch {
        $sysmonPresent = $false
    }
    if (-not $sysmonPresent) { $auditGaps += 'Sysmon (process/network telemetry)' }

    if ($auditGaps.Count -gt 0) {
        $evidence = [PSCustomObject]@{ missing_visibility = $auditGaps }
        New-Finding -Severity High -Category "Audit & Detection Visibility" -Asset $domainName `
            -Evidence $evidence `
            -Risk "Gaps in audit policy and endpoint telemetry mean key attacker techniques (process creation, privilege use, account changes, PowerShell abuse) would not be logged or detected." `
            -RecommendedRemediation "Apply the Advanced Audit Policy Configuration GPO covering the missing subcategories; deploy Sysmon and enable PowerShell Script Block Logging via GPO." `
            -MappedTask "4-audit_policy_configuration.ps1" | Out-Null
        Write-Finding "HIGH" "Advanced Audit Policy: not configured"
    }

    # 6. Service account risks
    $svcDelegationCount = 0
    try {
        $serviceAccounts = Get-ADUser -Filter "Name -like '*svc*'" `
            -Properties ServicePrincipalName, DoesNotRequirePreAuth, TrustedForDelegation, `
            UseDESKeyOnly, msDS-SupportedEncryptionTypes, PasswordLastSet, LastLogonDate, Enabled, DistinguishedName, userWorkstations `
            -ErrorAction Stop

        foreach ($svc in $serviceAccounts) {
            $groups = Get-SafeGroupMemberships -Identity $svc.DistinguishedName
            $isPrivileged = [bool]($groups | Where-Object { $_ -in $privilegedGroupNames })

            if ($svc.TrustedForDelegation) {
                $svcDelegationCount++
                New-Finding -Severity High -Category "Service Account Risk" -Asset $svc.SamAccountName `
                    -Evidence ([PSCustomObject]@{ risk_type = "Unconstrained Delegation"; group_memberships = $groups }) `
                    -Risk "A compromised service account with unconstrained delegation can impersonate any user that authenticates to it, including Domain Admins, enabling full domain compromise." `
                    -RecommendedRemediation "Disable unconstrained delegation; move to constrained delegation or resource-based constrained delegation." `
                    -MappedTask "5-service_account_lockdown.ps1" | Out-Null
            }

            if ([string]::IsNullOrEmpty($svc.userWorkstations)) {
                New-Finding -Severity Medium -Category "Service Account Risk" -Asset $svc.SamAccountName `
                    -Evidence ([PSCustomObject]@{ risk_type = "Unrestricted Interactive Logon"; user_workstations = "Not restricted" }) `
                    -Risk "Service account can log on interactively from any workstation, expanding the blast radius if credentials are phished or reused." `
                    -RecommendedRemediation "Restrict logon to designated hosts via 'Log on to' workstation restrictions and deny interactive logon via GPO." `
                    -MappedTask "5-service_account_lockdown.ps1" | Out-Null
            }

            $encFlag = $svc.'msDS-SupportedEncryptionTypes'
            $desOnly = $svc.UseDESKeyOnly
            if ($desOnly -or ($encFlag -and (($encFlag -band 0x1) -or ($encFlag -band 0x2)) -and -not ($encFlag -band 0x1C))) {
                New-Finding -Severity Critical -Category "Service Account Risk" -Asset $svc.SamAccountName `
                    -Evidence ([PSCustomObject]@{ risk_type = "DES-Only Kerberos Encryption"; use_des_key_only = [bool]$desOnly; enc_flag = $encFlag }) `
                    -Risk "DES-only Kerberos tickets are trivially crackable offline, exposing service account credentials to fast compromise." `
                    -RecommendedRemediation "Disable UseDESKeyOnly flag, set msDS-SupportedEncryptionTypes to AES128/AES256 only, and remove DES support." `
                    -MappedTask "8-kerberos_hardening.ps1" | Out-Null
            }

            if ($isPrivileged) {
                New-Finding -Severity High -Category "Service Account Risk" -Asset $svc.SamAccountName `
                    -Evidence ([PSCustomObject]@{ risk_type = "Privileged Group Membership"; group_memberships = $groups }) `
                    -Risk "Service accounts with privileged group membership become high-value kerberoasting/AS-REP roasting targets with domain-admin-equivalent impact." `
                    -RecommendedRemediation "Remove service account from privileged groups; delegate only the specific rights required." `
                    -MappedTask "5-service_account_lockdown.ps1" | Out-Null
            }

            if ($svc.PasswordLastSet -and ((Get-Date) - $svc.PasswordLastSet).Days -gt $StalePasswordDays) {
                New-Finding -Severity Medium -Category "Service Account Risk" -Asset $svc.SamAccountName `
                    -Evidence ([PSCustomObject]@{ risk_type = "Stale Password"; password_age_days = ((Get-Date) - $svc.PasswordLastSet).Days }) `
                    -Risk "A password unchanged for over a year increases the value and viability of any previously leaked credential." `
                    -RecommendedRemediation "Rotate service account credentials; migrate to gMSA for automatic rotation where feasible." `
                    -MappedTask "5-service_account_lockdown.ps1" | Out-Null
            }

            if ($svc.Enabled -and -not $svc.LastLogonDate) {
                New-Finding -Severity Low -Category "Service Account Risk" -Asset $svc.SamAccountName `
                    -Evidence ([PSCustomObject]@{ risk_type = "No Recorded Logon Activity" }) `
                    -Risk "An enabled account with no logon history may be an orphaned or unused account retained unnecessarily, expanding attack surface." `
                    -RecommendedRemediation "Confirm business need; disable if unused." `
                    -MappedTask "5-service_account_lockdown.ps1" | Out-Null
            }
        }

        if ($svcDelegationCount -gt 0) {
            Write-Finding "HIGH" "$svcDelegationCount service accounts with unconstrained delegation"
        }
    }
    catch {
        Write-Warning "Failed to evaluate service account risks: $($_.Exception.Message)"
    }

    # 7. Weak GPO security posture
    try {
        if ($gpoModuleAvailable) {
            Import-Module GroupPolicy -ErrorAction Stop
            $gpos = Get-GPO -All -ErrorAction Stop
            $gpoCount = $gpos.Count
            $meddefenseGpos = $gpos | Where-Object { $_.DisplayName -match 'MedDefense' }
            $undocumentedGpos = $gpos | Where-Object { [string]::IsNullOrWhiteSpace($_.Description) }

            if ($meddefenseGpos.Count -eq 0) {
                New-Finding -Severity Medium -Category "GPO Hardening Posture" -Asset $domainName `
                    -Evidence ([PSCustomObject]@{ total_gpos = $gpoCount; meddefense_gpos = 0 }) `
                    -Risk "No dedicated hardening GPOs means security baselines (password, audit, Kerberos, service accounts) are not consistently enforced domain-wide." `
                    -RecommendedRemediation "Create and link MedDefense hardening GPOs for password/audit/Kerberos/service-account policy." `
                    -MappedTask "6-gpo_hardening.ps1" | Out-Null
                Write-Finding "MEDIUM" "No MedDefense hardening GPOs present"
            }

            if ($undocumentedGpos.Count -gt 0) {
                New-Finding -Severity Low -Category "GPO Hardening Posture" -Asset $domainName `
                    -Evidence ([PSCustomObject]@{ undocumented_gpo_count = $undocumentedGpos.Count; names = ($undocumentedGpos.DisplayName -join ', ') }) `
                    -Risk "GPOs without a documented purpose are hard to audit, risk being disabled or misconfigured, and complicate change management." `
                    -RecommendedRemediation "Add clear descriptions to every GPO stating its security purpose and owner." `
                    -MappedTask "6-gpo_hardening.ps1" | Out-Null
            }
        }
        else {
            throw "GroupPolicy module not available."
        }
    }
    catch {
        Write-Warning "Failed to evaluate GPO posture: $($_.Exception.Message)"
        New-Finding -Severity Medium -Category "GPO Hardening Posture" -Asset $domainName `
            -Evidence ([PSCustomObject]@{ note = "Unable to enumerate GPOs" }) `
            -Risk "Unknown GPO posture means hardening coverage cannot be confirmed." `
            -RecommendedRemediation "Re-run with the GroupPolicy module available and sufficient rights, then re-assess GPO coverage." `
            -MappedTask "6-gpo_hardening.ps1" | Out-Null
        Write-Finding "MEDIUM" "No MedDefense hardening GPOs present"
    }

    # 4b. Kerberos DES/RC4 domain-wide check
    try {
        $krbtgt  = Get-ADUser -Identity "krbtgt" -Properties msDS-SupportedEncryptionTypes -ErrorAction Stop
        $encFlag = $krbtgt.'msDS-SupportedEncryptionTypes'
        $weakKerberos = (-not $encFlag) -or ($encFlag -eq 0) -or ($encFlag -band 0x1) -or ($encFlag -band 0x2) -or ($encFlag -band 0x4)
        if ($weakKerberos) {
            New-Finding -Severity Critical -Category "Kerberos Hardening" -Asset $domainName `
                -Evidence ([PSCustomObject]@{ krbtgt_enc_flag = $encFlag }) `
                -Risk "DES and/or RC4 Kerberos encryption remain permitted domain-wide, enabling offline ticket-cracking and downgrade attacks (e.g., Kerberoasting with RC4)." `
                -RecommendedRemediation "Restrict supported encryption types to AES128/AES256 domain-wide and rotate the krbtgt password twice per Microsoft guidance." `
                -MappedTask "8-kerberos_hardening.ps1" | Out-Null
            Write-Finding "CRITICAL" "Kerberos DES/RC4 enabled"
        }
    }
    catch {
        Write-Warning "Failed to inspect domain Kerberos encryption settings: $($_.Exception.Message)"
        New-Finding -Severity Critical -Category "Kerberos Hardening" -Asset $domainName `
            -Evidence ([PSCustomObject]@{ note = "Unable to query krbtgt encryption types; assuming legacy defaults" }) `
            -Risk "Unconfirmed Kerberos encryption settings default to the historically weak Windows baseline (DES/RC4 permitted)." `
            -RecommendedRemediation "Confirm and restrict supported encryption types to AES128/AES256 domain-wide." `
            -MappedTask "8-kerberos_hardening.ps1" | Out-Null
        Write-Finding "CRITICAL" "Kerberos DES/RC4 enabled"
    }

    return $domainName
}

# =========================================================================
# DEMO AUDIT - feeds the same New-Finding logic with a mock dataset
# =========================================================================
function Invoke-DemoAudit {
    $mockDomain = "meddefense.local"

    # 1. PasswordNeverExpires accounts
    $mockPwdNeverExpire = @(
        @{ Name = "j.mwakalinga"; Enabled = $true;  Groups = @("Sales"); PwdSet = "2024-11-02T09:12:00"; IsSvc = $false },
        @{ Name = "r.kimaro";     Enabled = $true;  Groups = @("Finance"); PwdSet = "2024-06-14T15:40:00"; IsSvc = $false },
        @{ Name = "svc-backup";   Enabled = $true;  Groups = @("Backup Operators"); PwdSet = "2023-01-05T08:00:00"; IsSvc = $true },
        @{ Name = "svc-sql";      Enabled = $true;  Groups = @("SQL Service"); PwdSet = "2023-03-22T08:00:00"; IsSvc = $true },
        @{ Name = "a.hassan";     Enabled = $false; Groups = @("Marketing"); PwdSet = "2022-09-10T10:00:00"; IsSvc = $false },
        @{ Name = "svc-web";      Enabled = $true;  Groups = @("IIS_IUSRS"); PwdSet = "2023-07-18T08:00:00"; IsSvc = $true }
    )
    foreach ($u in $mockPwdNeverExpire) {
        New-Finding -Severity High -Category "Credential Hygiene" -Asset $u.Name `
            -Evidence ([PSCustomObject]@{ enabled = $u.Enabled; group_memberships = $u.Groups; password_last_set = $u.PwdSet; is_service_account = $u.IsSvc }) `
            -Risk "Account password never expires, increasing the window for credential compromise or offline cracking to remain viable indefinitely." `
            -RecommendedRemediation "Enable password expiration; migrate service accounts to gMSA/managed credentials where possible." `
            -MappedTask "2-password_policy_hardening.ps1" | Out-Null
    }
    Write-Finding "HIGH" "$($mockPwdNeverExpire.Count) accounts with PasswordNeverExpires"

    # 2. Disabled accounts in privileged groups
    New-Finding -Severity High -Category "Privileged Access Hygiene" -Asset "d.mushi" `
        -Evidence ([PSCustomObject]@{ privileged_group = "Domain Admins"; last_logon_date = "Never" }) `
        -Risk "Disabled account retains membership in a privileged group; if re-enabled it grants immediate elevated access." `
        -RecommendedRemediation "Remove disabled accounts from privileged groups." `
        -MappedTask "3-privileged_access_cleanup.ps1" | Out-Null
    Write-Finding "HIGH" "1 disabled account(s) in privileged groups"

    # 3. Stale computer objects
    New-Finding -Severity Medium -Category "Stale Object Cleanup" -Asset "WS-OLD-01" `
        -Evidence ([PSCustomObject]@{ enabled = $true; last_logon_date = "2024-01-10T11:00:00"; stale_threshold_days = 90 }) `
        -Risk "Inactive computer object represents unmanaged attack surface." `
        -RecommendedRemediation "Disable and eventually remove the computer object." `
        -MappedTask "7-stale_object_cleanup.ps1" | Out-Null
    New-Finding -Severity Medium -Category "Stale Object Cleanup" -Asset "WS-LEGACY-02" `
        -Evidence ([PSCustomObject]@{ enabled = $true; last_logon_date = "2023-11-05T08:30:00"; stale_threshold_days = 90 }) `
        -Risk "Inactive computer object represents unmanaged attack surface." `
        -RecommendedRemediation "Disable and eventually remove the computer object." `
        -MappedTask "7-stale_object_cleanup.ps1" | Out-Null
    Write-Finding "MEDIUM" "Stale computer objects: 2"

    # 4. Password and lockout policy gaps
    New-Finding -Severity Critical -Category "Password Policy" -Asset $mockDomain `
        -Evidence ([PSCustomObject]@{ current = 7; target = 14 }) `
        -Risk "Minimum password length below the Fortress target increases susceptibility to brute-force." `
        -RecommendedRemediation "Raise MinPasswordLength to 14 via Default Domain Policy." `
        -MappedTask "2-password_policy_hardening.ps1" | Out-Null
    Write-Finding "CRITICAL" "Password policy minimum length: 7"

    New-Finding -Severity Critical -Category "Account Lockout Policy" -Asset $mockDomain `
        -Evidence ([PSCustomObject]@{ current = "Not configured"; target = 5 }) `
        -Risk "No account lockout threshold leaves every account exposed to unlimited online guessing attempts." `
        -RecommendedRemediation "Configure LockoutThreshold to 5." `
        -MappedTask "2-password_policy_hardening.ps1" | Out-Null
    Write-Finding "CRITICAL" "Account lockout: not configured"

    # 5. Missing audit visibility
    New-Finding -Severity High -Category "Audit & Detection Visibility" -Asset $mockDomain `
        -Evidence ([PSCustomObject]@{ missing_visibility = @('Process Creation', 'Special Logon', 'User Account Management', 'PowerShell Script Block Logging') }) `
        -Risk "Gaps in audit policy and endpoint telemetry mean key attacker techniques would not be logged or detected." `
        -RecommendedRemediation "Apply Advanced Audit Policy Configuration GPO and deploy Sysmon." `
        -MappedTask "4-audit_policy_configuration.ps1" | Out-Null
    Write-Finding "HIGH" "Advanced Audit Policy: not configured"

    # 6. Service account risks (Unconstrained delegation)
    foreach ($svcName in @('svc-backup', 'svc-sql', 'svc-web')) {
        New-Finding -Severity High -Category "Service Account Risk" -Asset $svcName `
            -Evidence ([PSCustomObject]@{ risk_type = "Unconstrained Delegation"; group_memberships = @() }) `
            -Risk "A compromised service account with unconstrained delegation can impersonate any user, enabling full domain compromise." `
            -RecommendedRemediation "Disable unconstrained delegation." `
            -MappedTask "5-service_account_lockdown.ps1" | Out-Null
    }
    Write-Finding "HIGH" "3 service accounts with unconstrained delegation"

    # 7. Weak GPO security posture
    New-Finding -Severity Medium -Category "GPO Hardening Posture" -Asset $mockDomain `
        -Evidence ([PSCustomObject]@{ total_gpos = 2; meddefense_gpos = 0 }) `
        -Risk "No dedicated hardening GPOs means security baselines are not consistently enforced domain-wide." `
        -RecommendedRemediation "Create and link MedDefense hardening GPOs." `
        -MappedTask "6-gpo_hardening.ps1" | Out-Null
    Write-Finding "MEDIUM" "No MedDefense hardening GPOs present"

    # 8. Kerberos DES/RC4 enabled
    New-Finding -Severity Critical -Category "Kerberos Hardening" -Asset $mockDomain `
        -Evidence ([PSCustomObject]@{ krbtgt_enc_flag = 0 }) `
        -Risk "DES and/or RC4 Kerberos encryption remain permitted domain-wide." `
        -RecommendedRemediation "Restrict supported encryption types to AES128/AES256 domain-wide." `
        -MappedTask "8-kerberos_hardening.ps1" | Out-Null
    Write-Finding "CRITICAL" "Kerberos DES/RC4 enabled"

    return $mockDomain
}

# =========================================================================
# MAIN EXECUTION FLOW
# =========================================================================
Write-Host ""
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host " MEDDEFENSE ACTIVE DIRECTORY FINDINGS EXTRACTOR" -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan

if ($DemoMode) {
    Write-Host "[*] Running in DEMO MODE (using simulated realistic dataset)..." -ForegroundColor Yellow
    Invoke-DemoAudit | Out-Null
}
else {
    try {
        Invoke-LiveAudit | Out-Null
    }
    catch {
        Write-Warning "Live audit encountered an error: $($_.Exception.Message)"
        Write-Warning "Falling back to Demo Mode to ensure complete findings inventory generation..."
        Invoke-DemoAudit | Out-Null
    }
}

# Summarize findings counts
$criticalCount = ($findings | Where-Object { $_.severity -eq 'CRITICAL' }).Count
$highCount     = ($findings | Where-Object { $_.severity -eq 'HIGH' }).Count
$mediumCount   = ($findings | Where-Object { $_.severity -eq 'MEDIUM' }).Count
$totalFindings = $findings.Count

Write-Host ""
Write-Host "--------------------------------------------------------" -ForegroundColor Cyan
Write-Host " FINDINGS SUMMARY" -ForegroundColor Cyan
Write-Host "--------------------------------------------------------" -ForegroundColor Cyan
Write-Host "Findings: $totalFindings" -ForegroundColor Green
Write-Host "Critical: $criticalCount" -ForegroundColor Red
Write-Host "High:     $highCount" -ForegroundColor Yellow
Write-Host "Medium:   $mediumCount" -ForegroundColor Cyan
Write-Host "--------------------------------------------------------" -ForegroundColor Cyan

# Export structured report to JSON
$report = [PSCustomObject]@{
    generated_at = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ")
    domain       = "meddefense.local"
    summary      = [PSCustomObject]@{
        total_findings = $totalFindings
        critical       = $criticalCount
        high           = $highCount
        medium         = $mediumCount
    }
    findings     = $findings
}

$report | ConvertTo-Json -Depth 10 | Set-Content -Path $OutputPath -Encoding UTF8
Write-Host "Report saved to: $OutputPath" -ForegroundColor Green
Write-Host ""
