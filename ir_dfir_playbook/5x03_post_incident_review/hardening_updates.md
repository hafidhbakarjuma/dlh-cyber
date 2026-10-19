# Hardening Updates: IR-2026-0414-01

## HRD-001: PowerShell Constrained Language Mode

**Closes:** GAP-003, GAP-004  
**Configuration:**
- GPO Path: `Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell` -> `Turn on Script Execution` (or via Environment / System Guard). Alternatively configured via Environment Variable system-wide.
- Registry Key: `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment`
- Value Name: `__PSLockdownPolicy`
- Value Type: `REG_SZ`
- Value Data: `4` (Enforces Constrained Language Mode for non-administrative users)

**Effect:** Restricts PowerShell to Constrained Language Mode for standard users; blocks `[System.Management.Automation.ScriptBlock]::Create`, COM object creation, and arbitrary `.NET` type instantiation that LOLBin proxy techniques depend on.  
**Applies to:** All standard user accounts across clinical and administrative workstations.  
**Validation:** Run `powershell -Command "$ExecutionContext.SessionState.LanguageMode"` as a standard user; expected output: `ConstrainedLanguage`.

---

## HRD-002: AppLocker Rule Restricting MSBuild.exe

**Closes:** GAP-003  
**Configuration:**
- Policy Type: AppLocker / Windows Defender Application Control (WDAC) Executable Rule Collection
- Rule Action: Allow for Administrators and Authorized CI/CD Service Accounts; Deny for Everyone else.
- Rule XML Structure:
```xml
<AppLockerPolicy Version="1">
    <RuleCollection EnforcementMode="Enabled" Type="Exe">
        <FilePathRule Action="Deny" Description="Restricts MSBuild.exe execution to Administrators and CI/CD tools." Id="a8125439-f123-4567-89ab-cdef01234567" Name="Block MSBuild for Standard Users" UserOrGroupSid="S-1-1-0">
            <Conditions>
                <FilePathCondition Path="%OSDrive%\Windows\Microsoft.NET\Framework*\v*\MSBuild.exe"/>
            </Conditions>
            <Exceptions>
                <UserOrGroupSid>S-1-5-32-544</UserOrGroupSid> <!-- Administrators -->
            </Exceptions>
        </FilePathRule>
    </RuleCollection>
</AppLockerPolicy>
