# MedDefense Health Systems
## Root Cause Analysis — billing-srv-01 Performance Incident

**Prepared by:** Junior Security Analyst
**Prepared for:** James Chen, Deputy CISO
**Source:** billing-srv-01 Diagnostics Report (ticket #4471), Marcus Webb's notes

---

## 1. Process Identification: What Is "kworker" Actually Doing?

Real Linux kernel worker threads appear in `top` as `[kworker/0:1]` — in square brackets, owned by root, with no executable path, since they run in kernel space. The process on billing-srv-01 matches none of that: it runs as **www-data**, and `/proc/8834/exe` resolves to **/var/www/html/.cache/kworker** — a web directory, not a system path. The name "kworker" is a deliberate disguise intended to blend into a process list at a glance.

The `stratum+tcp://` protocol is the key indicator: this is the mining protocol used by cryptocurrency mining pools. Combined with the connection to `pool.monero.org` and the recovered `config.json` showing a wallet address and multiple backup mining pools, this process is **cryptojacking malware** (XMRig-style) — unauthorized software silently mining Monero using MedDefense's compute resources, with proceeds flowing to the attacker's wallet. The three established connections on ports 4443/8080/3333 are the miner submitting proof-of-work shares, not legitimate billing-application traffic.

---

## 2. The Real Compromise: Two Pillars Violated Before Availability

CPU saturation (Availability impact) is the *last* effect in this chain, not the first. Two other CIA pillars were compromised earlier and are the actual root cause.

| Pillar | Explanation |
|---|---|
| **Confidentiality** | For a www-data process to write an executable into `/var/www/html/.cache/` and run it, an attacker first needed unauthorized code execution on the server — almost certainly via the Apache 2.4.29 vulnerability flagged in Marcus's notes. The moment that foothold exists, confidentiality is already broken: an unauthorized party has access to a server that also runs MySQL hosting billing data. Unauthorized presence itself is the violation, independent of confirmed exfiltration. |
| **Integrity** | The attacker then wrote unauthorized files to disk (the kworker binary and config.json, both dated 14 days ago, owned by www-data) and caused an unauthorized process to execute. This is a direct modification of the system's expected state without authorization. |

Only after both had already occurred did the miner begin consuming ~94% CPU and degrade Availability. The sysadmin's ticket describes only the third and final pillar to fail, treating it as the whole story.

---

## 3. Why the Sysadmin's Hardware Upgrade Fails to Resolve the Issue

Upgrading to 16GB RAM / 8 vCPUs does not address the actual problem. It does not remove the planted binary, does not revoke the attacker's access, and does not patch the vulnerability that allowed entry in the first place. The likely outcome is worse than doing nothing: a more powerful server gives the miner more headroom to consume before degradation becomes noticeable again, potentially making the compromise **quieter** rather than resolved. The attacker retains an active foothold and could deploy a different payload at any time — including another ransomware run, given this server's history. This is a case of fixing the symptom (resource exhaustion) while leaving the root cause (an exploitable, unpatched entry point) fully intact.

---

## 4. Connection to the January Ransomware Incident

The same server suffered two distinct malware families — ransomware in January, a cryptominer now — with Marcus explicitly noting the same Apache version and suspected same RCE vector in both cases. This is a strong indicator that the January rebuild restored the server without ever closing the vulnerability that allowed the original attacker in. A rebuild that reinstates the same vulnerable software simply recreates the same open door for a second actor — or the same one — to walk through again.

The question this raises is not "how do we clean up the miner," but: **did the January incident response ever identify and confirm the initial access vector, or was the server simply restored from an image/backup and declared resolved without a root-cause verification step?** If the latter, it signals a deeper gap in MedDefense's incident response process — treating "restored and running" as equivalent to "actually secured" — a gap that will keep producing repeat compromises on this server, and potentially others rebuilt the same way, until addressed directly.

---

*This analysis addresses root cause only; remediation recommendations and control gap prioritization are addressed in subsequent deliverables.*
