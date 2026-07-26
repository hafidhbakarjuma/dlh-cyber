# The Technical Proof

**Goal:** Demonstrate hands-on technical mastery by executing a rapid security check using tools from the entire module.

**Context:** James Chen needs to know that you can DO what you recommend, not just write about it. Before the Board meeting, he asks you to run a quick technical validation on your own machine to prove proficiency. "Show me you can inspect a cert, verify a hash, check for an exploit and audit a system. Five minutes each."

---

## Check 1: Certificate Inspection

**Command:**
```bash
openssl s_client -connect github.com:443 -servername github.com </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
```

**Output Summary:**

| Field | Value |
|---|---|
| **Subject** | `CN=github.com` |
| **Issuer** | `C=GB, O=Sectigo Limited, CN=Sectigo Public Server Authentication CA DV E36` |
| **Validity** | `Jul 3 2026 - Sep 30 2026` |
| **Key Algorithm** | `id-ecPublicKey (256 bit)` |
| **SAN** | `DNS:github.com, DNS:www.github.com` |

---

## Check 2: Hash Verification

**Command:**
```bash
echo "MedDefense firmware test" > firmware_test.txt && sha256sum firmware_test.txt
echo "line added" >> firmware_test.txt && sha256sum firmware_test.txt
```

**Output:**

| | Hash |
|---|---|
| **Original** | `57bb6c2010ced517197f5aa7485718f8c3da5cb65fd3d3f9ed044db6980137eb` |
| **Modified** | `e55d3f13681b4693a21cf86e815af94b2fa79d8478449a4343d579543fdea8b9` |

**Analysis:** The hashes differ, confirming the file changed.

**Why it matters:** Without verifying the FortiOS firmware hash before installation, a single altered byte in a tampered image produces a completely different cryptographic hash and would go undetected without this verification check.

---

## Check 3: Exploit Research

**Command:**
```bash
searchsploit fortigate
searchsploit fortios
```

**Output:** No entries for `CVE-2023-27997` / `XORtigate` in Exploit-DB. The closest match was an unrelated FortiOS SSL-VPN 7.4.4 issue on a different version range.

**Analysis:** While no public Exploit-DB or Metasploit entry exists for this specific CVE, Proof-of-Concept (PoC) code exists independently on GitHub, and it is officially listed in the CISA KEV (Known Exploited Vulnerabilities) catalog as actively exploited. This demonstrates that patch urgency cannot wait for a searchsploit listing — a vulnerability can be under real, active attack before it ever appears in a formal exploit database.

---

## Check 4: System Audit

**Command:**
```bash
sudo lynis audit system --quick
```

**Output:**

* **Hardening Index:** `61/100`
* **Warnings:** None returned during this run.
* **Suggestions:** 48 suggestions logged (including file integrity monitoring, malware scanner, `auditd`, and firewall configuration).

**Recommendation for `billing-srv-01`:** Install a file integrity monitoring tool (Lynis control `FINT-4350`). `billing-srv-01` has already been compromised twice (initially by ransomware, then by a cryptominer) with zero detection in place; implementing file integrity monitoring would have flagged both intrusions early.
