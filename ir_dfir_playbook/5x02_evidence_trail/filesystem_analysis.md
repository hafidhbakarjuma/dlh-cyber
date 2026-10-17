# Filesystem Analysis: ART-001 (wst-ws-031.dd)

## Artifact verification
- Hash at analysis start: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 (matches baseline)
- Mounted read-only: yes
- CoC entry updated: yes, ART-001 access logged at 2026-04-14T10:15Z

## Partition layout
```
$ mmls wst-ws-031.dd
DOS Partition Table
Offset Sector: 0
Units are in 512-byte sectors

      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)
001:  -------   0000000000   0000002047   0000002048   Unallocated
002:  000:000   0000002048   0125827071   0125825024   NTFS / exFAT (0x07)
```
Offset used for NTFS analysis: 2048

## Filesystem metadata
```
$ fsstat -o 2048 wst-ws-031.dd
FILE SYSTEM INFORMATION
------------------------------------------------------------
File System Type: NTFS
Volume Name: Windows
Volume Serial Number: 4C90B31A90B2E15F
Version: Windows NTFS
Volume Size: 62912512 sectors
Cluster Size: 4096 bytes
Group Size: 32 clusters
Total Clusters: 7864064
Free Clusters: 1245892
------------------------------------------------------------
```

## Key findings

### ART-001-F01: Malicious MSBuild staging file
- Path: `C:\Users\dmarsh\AppData\Local\Temp\update.xml`
- Created: 2026-04-13T22:14:32Z
- Modified: 2026-04-13T22:14:32Z
- Accessed: 2026-04-13T22:14:35Z
- Size: 4192 bytes
- SHA-256: 7b9f8e2a1c4d6b3e5f7a9c2d4e6f8a1b3c5d7e9f2a4b6c8d1e3f5a7b9c1d3e5f
- Significance: MSBuild inline task XML; contains Base64-encoded C# shellcode loader; correlates with `msbuild.exe` execution observed in process memory and SIEM logs.

### ART-001-F02: Second-stage dropped payload
- Path: `C:\Users\dmarsh\AppData\Local\Temp\updater.exe`
- Created: 2026-04-13T22:15:01Z
- Modified: 2026-04-13T22:15:01Z
- Accessed: 2026-04-13T22:15:10Z
- Size: 84736 bytes
- SHA-256: 4e2c8a9f1b3d5e7f9a2c4e6b8d1f3a5c7e9b2d4f6a8c1e3b5d7f9a2c4e6b8d1f
- Significance: Compiled executable dropped by the MSBuild staging script; establishes persistent C2 callback connection.

### ART-001-F03: Scheduled task persistence
- Path: `C:\Windows\System32\Tasks\MedDefenseUpdate`
- Created: 2026-04-13T22:18:40Z
- Modified: 2026-04-13T22:18:40Z
- Accessed: 2026-04-13T22:18:40Z
- Size: 1256 bytes
- SHA-256: 9f1b3d5e7f9a2c4e6b8d1f3a5c7e9b2d4f6a8c1e3b5d7f9a2c4e6b8d1f4b6c8d
- Significance: XML scheduled task configured to execute `updater.exe` upon system startup and user logon under the context of user `dmarsh`.