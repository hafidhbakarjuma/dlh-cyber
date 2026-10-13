# Eradication Checklist: IR-2026-0414-01

## Overview

This checklist defines the step-by-step eradication actions required to eliminate adversary access, execution, credentials, and persistence across process, network, credential, and host configuration surfaces.

**Important:** Run commands only on authorized incident-response systems. Validate target identifiers and preserve required evidence before terminating processes, disabling accounts, deleting persistence, or changing firewall policy. Commands and expected results must be verified in the actual environment before sign-off.

## 1. Process Surface Eradication

### Step 1.1: Terminate Malicious Execution Chain

- **Target processes:** `msbuild.exe` (PID `4812`) and parent `powershell.exe` (PID `3304`).
- **Execution command (PowerShell, elevated where required):**

  ```powershell
  Stop-Process -Id 4812, 3304 -Force
  ```

- **Verification command:**

  ```powershell
  Get-CimInstance Win32_Process |
      Where-Object {
          $_.ProcessId -in 4812, 3304 -or
          ($_.ExecutablePath -like 'C:\Users\dmarsh\AppData\Local\Temp\*')
      } |
      Select-Object ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine
  ```

- **Expected verification output:** No results for the specified PIDs or suspicious execution from the identified temporary directory. Investigate any new process using the same suspicious path or command line.
- **Rollback plan:** Process termination is not reversible. If a legitimate process was stopped, restart it through the approved service or user-session procedure only after the host is confirmed clean.

## 2. Credential Surface Eradication

### Step 2.1: Revoke Active User Sessions and Refresh Tokens

- **Target account:** `dmarsh` (Daniel Marsh)
- **Execution commands (Microsoft Graph PowerShell and Active Directory PowerShell):**

  ```powershell
  # Revoke Microsoft Entra ID sign-in sessions / refresh tokens
  Revoke-MgUserSignInSession -UserId "dmarsh@contoso-health.org"

  # Temporarily disable the on-premises Active Directory account
  Set-ADUser -Identity "dmarsh" -Enabled $false
  ```

  If the environment uses Microsoft Entra ID, disable the cloud account separately where authorized:

  ```powershell
  Update-MgUser -UserId "dmarsh@contoso-health.org" -AccountEnabled:$false
  ```

  Perform a password reset through the organization's approved identity procedure. Require a password change at the next sign-in after the account is safely re-enabled, if appropriate.

- **Verification commands:**

  ```powershell
  Get-ADUser -Identity "dmarsh" -Properties Enabled, PasswordLastSet |
      Select-Object Name, Enabled, PasswordLastSet

  Get-MgUser -UserId "dmarsh@contoso-health.org" `
      -Property AccountEnabled, RefreshTokensValidFromDateTime |
      Select-Object AccountEnabled, RefreshTokensValidFromDateTime
  ```

- **Expected verification output:** The on-premises account is disabled (`Enabled: False`); the Entra ID account is disabled (`AccountEnabled: False`) if cloud-account disabling was performed; and the token-valid-from timestamp reflects the session-revocation operation. Confirm the actual returned values rather than assuming success.
- **Rollback plan:** Re-enable accounts only after credential reset, identity verification with Daniel Marsh through an approved out-of-band channel, and incident-lead authorization. Review sign-in logs and revoke sessions again if compromise is still suspected.

## 3. Network Surface Eradication

### Step 3.1: Perimeter Firewall and Proxy Block

- **Target artifact:** Suspected command-and-control (C2) IP address `185.220.101.47`.
- **Execution action:** Add a deny rule through the organization's approved firewall management interface (for example, Palo Alto Networks or Fortinet). Use a unique rule name such as `BLOCK_C2_IR-2026-0414-01`, restrict the scope appropriately, enable logging, and commit/publish the change according to local procedures.

  **Note:** Firewall CLI syntax differs by vendor and version. The following is a conceptual example, not a universal copy-and-paste command:

  ```text
  Rule name: BLOCK_C2_IR-2026-0414-01
  Destination: 185.220.101.47
  Action: Deny / Drop
  Logging: Enabled
  ```

- **Verification commands:** Verify the rule is installed and logging as expected in the firewall management interface. From an authorized test host, confirm that a connection attempt is blocked and correlate the test timestamp with firewall logs. For example:

  ```bash
  curl -k -sS -o /dev/null -w '%{http_code}\n' --connect-timeout 5 --max-time 8 https://185.220.101.47
  ```

- **Expected verification output:** A blocked connection may result in a timeout, connection failure, or a vendor-specific deny log. A `000` curl status means curl did not receive an HTTP response; by itself, it does **not** prove that the firewall rule caused the failure. Confirm using firewall logs and policy inspection.
- **Rollback plan:** Remove or disable the rule only with incident-lead/network-owner approval if the IP is confirmed to be legitimate shared infrastructure or the block causes an approved operational impact. Document the evidence and compensating controls.

## 4. Persistence Surface Eradication

### Step 4.1: Scheduled Tasks Audit and Removal

- **Target artifacts:** Tasks created or modified around `02:40Z`–`03:00Z`, especially under `\Microsoft\Windows\` or the task root. Validate the timeline against event logs and task action paths.
- **Execution command (for the confirmed malicious task only):**

  ```powershell
  Unregister-ScheduledTask -TaskName "Updater_WST_031" -Confirm:$false
  ```

  If the task is not in the root task folder, specify its verified task path with `-TaskPath`.

- **Verification command:**

  ```powershell
  Get-ScheduledTask |
      Where-Object {
          $_.TaskName -eq "Updater_WST_031" -or
          $_.TaskName -like "*Update*"
      } |
      Select-Object TaskName, TaskPath, State

  Get-ScheduledTask |
      ForEach-Object {
          $task = $_
          foreach ($action in $task.Actions) {
              [pscustomobject]@{
                  TaskName  = $task.TaskName
                  TaskPath  = $task.TaskPath
                  Execute   = $action.Execute
                  Arguments = $action.Arguments
              }
          }
      } |
      Where-Object {
          $_.Execute -match 'AppData\\Local\\Temp|powershell|msbuild|wscript|cscript'
      } |
      Format-Table -AutoSize
  ```

- **Expected verification output:** The confirmed malicious task `Updater_WST_031` is absent. Any remaining unusual tasks or actions referencing suspicious binaries, script hosts, or temporary directories are investigated before sign-off.
- **Rollback plan:** Restore a task only if investigation determines it was legitimate and the task definition has been preserved. Do not restore a confirmed malicious task.

### Step 4.2: Registry Run Keys and WMI Event Consumer Audit

- **Target locations:**
  - `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
  - `HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
  - WMI permanent event subscriptions in `root\subscription`
- **Execution command (only after confirming the value is malicious and preserving its details):**

  ```powershell
  Remove-ItemProperty `
      -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" `
      -Name "WinHealthUpdate" `
      -ErrorAction SilentlyContinue
  ```

- **Verification commands:**

  ```powershell
  Get-ItemProperty `
      -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"

  Get-CimInstance -Namespace root\subscription -ClassName __EventFilter
  Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer
  Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding
  ```

- **Expected verification output:** No suspicious Run-key values remain, and WMI event filters, consumers, and bindings have been reviewed. No unknown WMI consumers remain without an explanation. Do not assume every WMI consumer is malicious; validate ownership and behavior.
- **Rollback plan:** Restore a removed registry value only if it is confirmed legitimate and its original data has been preserved. Recreate WMI subscriptions only from a verified, approved definition.

## 5. Summary Verification Sign-off

Complete the status and evidence fields only after the commands and independent checks have been performed. Do not mark a row `PASSED` solely because an execution command returned without an obvious error.

| Surface | Eradication action | Verification status | Verified by | Evidence / timestamp (UTC) |
|---|---|---|---|---|
| Process | Terminated confirmed malicious `msbuild.exe` (PID `4812`) and `powershell.exe` (PID `3304`); checked for related execution | Pending verification | On-call SOC analyst | |
| Credential | Revoked Entra ID sessions/tokens and disabled the account in the applicable identity systems | Pending verification | On-call SOC analyst / IAM | |
| Network | Applied and verified perimeter block for `185.220.101.47`; reviewed deny logs | Pending verification | On-call SOC analyst / Network team | |
| Persistence | Removed confirmed malicious scheduled task `Updater_WST_031`; audited Run keys and WMI subscriptions | Pending verification | On-call SOC analyst / Endpoint team | |

## 6. Final Eradication Gate

Before closing eradication, confirm all of the following:

- [ ] Evidence was preserved before destructive changes where feasible.
- [ ] The malicious process chain and related execution artifacts are no longer present.
- [ ] The affected identity's sessions/tokens were revoked and credentials were reset according to policy.
- [ ] The network block is active and supported by firewall policy/log evidence.
- [ ] Scheduled tasks, registry Run keys, and WMI persistence surfaces were reviewed.
- [ ] Relevant endpoint, identity, and network logs were checked for signs of re-entry.
- [ ] All changes, command outputs, timestamps, exceptions, and approvers were recorded.
- [ ] The incident lead approved the transition to recovery and heightened monitoring.

**Incident ID:** `IR-2026-0414-01`  
**Eradication owner:** ____________________  
**Incident lead:** ____________________  
**Completion time (UTC):** ____________________  
**Final status:** Pending verification / Passed / Failed
