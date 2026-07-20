# The Self-Audit: MedDefense Security Assessment

## Part 1: Install and Run
Lynis 3.1.6 was utilized for the system audit on the Kali machine. The audit was executed via `sudo lynis audit system`, performing 269 distinct security tests.

## Part 2: Analyze Results

### 1. Hardening Index
**60 / 100**

### 2. Warnings
*The following are categorized as WARNINGS based on the Lynis audit output. These tests returned states that constitute an insecure configuration in a production medical environment.*

1.  **[WARNING] Permissions for /etc/sudoers.d:** Lynis identifies that the directory holding sudo privilege files is not tightly restricted. Loose permissions here could let a non-privileged user tamper with sudo rules. **Remediation:** `chmod 750 /etc/sudoers.d` and confirm `root:root` ownership.
2.  **[WARNING] Permissions of home directories:** Lynis flags home directories that are too permissive. These often contain SSH keys and shell history; if readable by other local users, this leads to privilege escalation. **Remediation:** `chmod 700` on each user's home directory.
3.  **[WARNING] No active firewall [FIRE-4590]:** Lynis reports the host-based firewall is NOT ACTIVE and no iptables module is loaded. On a machine running an exposed web server, this is a critical exposure to network-based attacks. **Remediation:** Enable `ufw` or `iptables` and define a default-deny policy.
4.  **[WARNING] auditd not enabled [ACCT-9628]:** No audit logging framework is running. This prevents OS-level file access and change auditing, which is a requirement for HIPAA compliance. **Remediation:** Install and enable `auditd`.
5.  **[WARNING] No malware scanner installed [HRDN-7230]:** No tool like `rkhunter` or `OSSEC` is present. Without this, rootkits or malware can persist undetected. **Remediation:** Install and configure `rkhunter`.

### 3. Top 5 Suggestions
*   **Install fail2ban [DEB-0880]**: Automatically bans hosts after repeated authentication failures, mitigating brute-force attacks.
*   **Install a PAM password-strength module (pam_cracklib/pam_passwdqc) [AUTH-9262]**: Currently no enforcement of password complexity at the PAM layer.
*   **Configure password aging (min/max) in /etc/login.defs [AUTH-9286]**: Passwords currently never expire or rotate.
*   **Set a GRUB bootloader password [BOOT-5122]**: Without one, anyone with physical/console access can boot into single-user mode with no authentication.
*   **Install Apache mod_security / mod_evasive [HTTP-6643 / HTTP-6640]**: The running Apache instance has no web application firewall or anti-brute-force module loaded.

### 4. Category Breakdown
*   **Strongest categories**: Users/Groups/Authentication (mostly OK — unique UIDs, password file consistency) and Memory/Processes.
*   **Weakest categories**:
    *   **Kernel Hardening**: Over a dozen sysctl values marked different from the hardened baseline.
    *   **Security frameworks**: Both AppArmor and SELinux are present but DISABLED.
    *   **Software: firewalls**: No active host firewall.
    *   **Software: file integrity / malware**: No integrity-checking tool, no malware scanner.
    *   **Accounting**: `auditd` not installed, `sysstat` disabled.

## Part 3: MedDefense Projection — billing-srv-01
*The following projections are based on the known state of billing-srv-01 (Ubuntu 18.04, Apache 2.4.29) and identified registry gaps.*

1.  **SSH password authentication enabled**: Lynis would flag `AUTH-9208` (SSH password authentication enabled), a critical risk for a server previously targeted by ransomware[cite: 1, 2].
2.  **Large volume of outdated packages**: As an EOL system, Lynis would flag `HTTP-6622` for the outdated Apache version (2.4.29) and missing security patches[cite: 1, 3].
3.  **Insecure MySQL binding**: Lynis would flag `DB-5560`, noting that the database is exposed to every network interface (`0.0.0.0`) instead of being restricted to `localhost`[cite: 1].
4.  **Missing Mandatory Access Control (MAC)**: Lynis would trigger `MAC-6010` for AppArmor or SELinux being inactive, leaving the host without file-access containment[cite: 1].
5.  **Persisting indicators of prior compromise**: Lynis's file integrity checks (`FILE-6310`) would likely detect anomalous binary signatures or unexpected scheduled tasks in `/etc/cron.d/`, common artifacts of the prior cryptominer infection[cite: 1].
