# 11. The False Positives Analysis

This report documents findings identified by the automated scanner that require manual validation to avoid unnecessary remediation efforts or the misallocation of security resources.

---

## Finding 1: OpenSSH Outdated Version
* **Finding ID:** Finding 020
* **Reported Vulnerability:** OpenSSH 8.9p1 PKCS#11 vulnerability (CVE-2023-38408).
* **Why It Is a False Positive:** As noted by the scan auditor, this vulnerability requires specific environmental conditions—specifically, that `ssh-agent` forwarding is active and connected to an attacker-controlled host. This configuration is not present in the target's server environment.
* **Validation Method:** Run `ps aux | grep ssh` to check for active `ssh-agent` processes and review `sshd_config` to ensure `AllowAgentForwarding` is disabled.
* **Risk of Acting on This FP:** Wasted administrative time on an emergency patching/upgrade cycle for a system that is not actually at risk.
* **Risk of Not Validating:** If this were a true positive, failing to patch could lead to remote code execution if a user were tricked into forwarding their agent to a malicious system.

---

## Finding 2: Apache Tomcat Ghostcat (AJP) - Initial Scanner State
* **Finding ID:** Finding 017
* **Reported Vulnerability:** Information disclosure regarding Tomcat version; suspicion of active AJP connector (Ghostcat).
* **Why It Is a False Positive:** While the scanner correctly identified the Tomcat version, the scanner initially claimed it could not verify if the AJP connector was active. Without manual verification (as performed in Finding 031), treating the *entire* finding as an active "Ghostcat" exploit would be premature, as the vulnerability only exists if the AJP port is open and reachable.
* **Validation Method:** Execute `netstat -tulpn | grep 8009` or `ss -tulpn | grep 8009` to verify if the AJP connector is bound to a network interface.
* **Risk of Acting on This FP:** Unnecessary configuration changes to application servers that might break legitimate traffic if AJP is required for load balancing.
* **Risk of Not Validating:** If the AJP connector *is* active and we dismiss it, an attacker could read arbitrary files (including database credentials) from the EHR server.

---

## Analysis: The Importance of Validation

### Reasonable False Positive Rate
In a scan report of 31 findings, a reasonable false positive rate for an automated scanner is typically **5–10%**. Automated tools are designed to be "noisy" to ensure they do not miss potential threats, but this trade-off inherently generates false alerts based on banner grabbing or version signatures that may not account for local patches or specific hardened configurations.

### Why Manual Validation is Essential
Manual validation is essential before committing remediation resources for three key reasons:
1. **Resource Optimization:** Security teams have limited bandwidth. Wasting time on non-existent vulnerabilities diverts attention from genuine, high-risk threats.
2. **System Stability:** Automated remediation (like force-upgrading a library or disabling a service) can cause unexpected downtime or break critical business dependencies. Verification ensures that fixes are applied safely.
3. **Contextual Accuracy:** Automated scanners often lack "business context." They cannot distinguish between a vulnerable service that is isolated behind a firewall and one that is exposed to the internet. Validation ensures the response is proportional to the actual risk to the business.
