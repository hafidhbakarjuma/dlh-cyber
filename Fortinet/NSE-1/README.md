# NSE 1: Information Security Awareness

NSE 1 is the entry level of the Fortinet certification path. It explains the basic ideas of cybersecurity: what threats exist, how they work, and what protects against them. It is not about Fortinet products, so it works as a general foundation.

## Module by Module

### 1. Introduction to Cybersecurity
Why security matters and the core goals of the CIA triad:
- **Confidentiality:** only the right people see the data
- **Integrity:** data is not changed
- **Availability:** systems work when needed

Also covers basic terms like threat, vulnerability and risk.

### 2. The Threat Landscape
Who attacks (cybercriminals, hacktivists, nation-states, insiders), why they do it, and the typical stages of an attack. It shows how attacks are organized, not just what tools they use.

### 3. Social Engineering
Attacks that trick people instead of breaking technology: phishing, spear phishing, vishing, pretexting, baiting. The main defense is awareness and training, since people are often the weakest link.

### 4. Malware
Types of malicious software: viruses, worms, trojans, ransomware, spyware, rootkits and botnets. Covers how they spread and how they are detected and stopped.

### 5. Cryptography and the Public Key Infrastructure
How data is protected with encryption:
- **Symmetric** (one shared key) vs **asymmetric** (public/private key pair)
- **Hashing** to check integrity
- **Digital signatures and certificates** to prove identity
- **PKI**, the system of certificate authorities that makes certificates trusted

### 6. Secure Network
How networks are protected: firewalls, IDS/IPS, segmentation, VPNs and secure wireless. This is the module closest to FortiGate work.

### 7. Authentication and Access Control
Proving who you are and controlling what you can do: passwords, multi-factor authentication, single sign-on, and models like least privilege and role-based access.

### 8. Endpoint Security
Protecting laptops, servers and phones with antivirus/EDR, patching, hardening and device control.

### 9. Secure Data and Applications
Protecting data (encryption at rest and in transit, backups, data loss prevention) and applications (secure coding ideas, web application firewalls, common web attacks).

### 10. Cloud Security and Virtualization
How virtual machines and cloud services work and how to secure them, including the shared responsibility model between the provider and the customer.

## How It Fits Together

The course tells one story:

**Why security matters (1) → who attacks you (2) → how they attack (3, 4) → the tools that protect you (5 to 10).**

Modules 5 to 10 come back in later Fortinet courses and in real work:
- Certificates in SSL inspection and VPNs
- Segmentation in firewall zones
- Authentication in VPN logins

## Summary Table

| Module | Title | Main idea |
|---|---|---|
| 1 | Introduction to Cybersecurity | CIA triad, threat, vulnerability, risk |
| 2 | The Threat Landscape | Attackers, motives, attack stages |
| 3 | Social Engineering | Phishing and tricking people |
| 4 | Malware | Types of malicious software |
| 5 | Cryptography and PKI | Encryption, hashing, certificates |
| 6 | Secure Network | Firewalls, IPS, segmentation, VPN |
| 7 | Authentication and Access Control | MFA, SSO, least privilege |
| 8 | Endpoint Security | Antivirus/EDR, patching, hardening |
| 9 | Secure Data and Applications | Data protection, WAF, web attacks |
| 10 | Cloud Security and Virtualization | Virtual machines, shared responsibility |

## Where It Leads

NSE 1 → NSE 2 and NSE 3 (Fortinet products and Security Fabric) → FCP FortiGate Administrator (formerly NSE 4), the hands-on firewall exam.
