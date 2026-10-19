# Rule Validation Report: IR-2026-0414-01

## Executive Summary
This report documents the testing and tuning process for the Sigma detection rules developed in response to incident `IR-2026-0414-01`. Rules were tested against live incident telemetry (`incident_sysmon.jsonl`) and a 30-day representative baseline (`clean_sysmon.jsonl`) to ensure high fidelity and low false positive rates prior to production deployment.

---

## 1. Rule: PowerShell Spawning Trusted Developer Utility (`sigma_powershell_msbuild_lolbin.yml`)

### Test Results
- **Target ATT&CK Technique**: T1127.001 (Trusted Developer Utilities: MSBuild)
- **Incident Log (`incident_sysmon.jsonl`)**:
  - **Total Events**: 4,812
  - **Matches**: 2
  - **Match Rate**: `0.042%`
  - **Verdict**: **PASS** — Successfully detected malicious process ancestry (`powershell.exe` spawning `msbuild.exe`) at timestamps `02:46:58Z` and `03:27:13Z`.
- **Clean Baseline Log (`clean_sysmon.jsonl`)**:
  - **Total Events**: 287,341
  - **Matches**: 0
  - **False Positive Rate**: `0.000%`
  - **Verdict**: **PASS** — Zero triggers recorded across standard clinical workstation operations and legitimate developer build pipelines.

---

## 2. Tuning Summary & Decisions
- **Initial Baseline Assessment**: The rule demonstrated clean performance without requiring scoping adjustments. Developer environments utilizing Visual Studio build tools did not trigger false positives due to specific process parent constraints (`powershell.exe`, `pwsh.exe`, `wscript.exe`, `cscript.exe` as parents).
- **Deployment Status**: Approved for immediate SIEM deployment at `high` severity.
