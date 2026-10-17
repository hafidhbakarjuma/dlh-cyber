# Persistence Artifact Analysis: ART-001 (wst-ws-031.dd)

## Artifact verification
- Hash at analysis start: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 (matches baseline)
- CoC entry updated: yes, ART-001 access logged at 2026-04-14T09:05Z

## Registry persistence

### ART-001-R01: Run key persistence
- **Key:** `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- **Value name:** `WindowsUpdateSvc`
- **Value data:** `C:\Users\dmarsh\AppData\Local\Temp\updater.exe`
- **Last write:** 2026-04-13T22:18:02Z
- **Forensic significance:** Establishes user-level persistence by executing the second-stage dropped payload automatically upon user logon.
- **Evidence ID:** ART-001-R01

### ART-001-R02: Scheduled task action persistence
- **Key:** `C:\Windows\System32\Tasks\MedDefenseUpdate`
- **Value name:** Task Definition / Actions
- **Value data:** `C:\Windows\System32\cmd.exe /c start /b C:\Users\dmarsh\AppData\Local\Temp\update.xml`
- **Last write:** 2026-04-13T22:18:40Z
- **Forensic significance:** Configures a system-level scheduled task to trigger the MSBuild loader script under the security context of user `dmarsh`.
- **Evidence ID:** ART-001-R02

## Execution evidence

### ART-001-E01: UserAssist - msbuild.exe
- **Key:** `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926f4174924}\Count`
- **Value:** `UEME_CTLRDR:C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe`
- **Run count:** 4
- **Last executed:** 2026-04-13T22:16:15Z
- **Forensic significance:** Confirms interactive or scripted execution of `MSBuild.exe` via the user session, aligning precisely with the time of staging file execution.
- **Evidence ID:** ART-001-E01

### ART-001-E02: Amcache first execution
- **Key:** `C:\Windows\AppCompat\Programs\Amcache.hve` (`Root\FileEntry`)
- **Value name:** `updater.exe`
- **Value data:** SHA-1: `4e2c8a9f1b3d5e7f9a2c4e6b8d1f3a5c7e9b2d4f` / Path: `C:\Users\dmarsh\AppData\Local\Temp\updater.exe`
- **Last write:** 2026-04-13T22:15:01Z
- **Forensic significance:** Records the exact first-run timestamp and file metadata of the dropped payload before execution completed.
- **Evidence ID:** ART-001-E02

### ART-001-E03: AppCompatCache (ShimCache) entry
- **Key:** `SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache`
- **Value name:** Binary Cache Entry (`updater.exe`)
- **Value data:** File size: 84,736 bytes; Execution flag: True
- **Last write:** 2026-04-13T22:15:05Z
- **Forensic significance:** Provides independent kernel-level verification that `updater.exe` was loaded into memory by the OS subsystem.
- **Evidence ID:** ART-001-E03