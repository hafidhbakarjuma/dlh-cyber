# NSE 2: Introduction to Next Generation Firewall

**Status:** ✅ Completed (9 lessons + final exam)
**Date:** November 2026
**Exam:** 20 questions, passing score 80%

NSE 1 explained the basics of cybersecurity. NSE 2 moves to the main defensive tool: the **Next-Generation Firewall (NGFW)**. It shows what a modern firewall does beyond simple port blocking, and how the pieces fit together on a FortiGate.

## Lesson by Lesson

| Lesson | Title | Status |
|---|---|---|
| 01 | What is Next Generation Firewall | ✅ Done |
| 02 | How Firewall Policies Work | ✅ Done |
| 03 | User Authentication with a Next-Generation Firewall | ✅ Done |
| 04 | How Next-Generation Firewalls Block Malware | ✅ Done |
| 05 | Controlling Web Access with Web Filtering | ✅ Done |
| 06 | Intrusion Prevention System and Application Control on FortiGate | ✅ Done |
| 07 | Connecting Multiple Locations Securely | ✅ Done |
| 08 | SD-WAN | ✅ Done |
| 09 | SASE | ✅ Done |
| Exam | Introduction to Next Generation Firewall Exam | ✅ Done |

## What Each Lesson Covers

### 01. What is Next Generation Firewall
How an NGFW differs from a traditional firewall. A traditional firewall decides by IP address, port and protocol. An NGFW also understands **applications, users and content**, and adds features such as IPS, antivirus and web filtering in one device.

### 02. How Firewall Policies Work
How a firewall decides to allow or deny traffic:
- Policies are checked **from top to bottom**, and the first match wins
- A policy matches on source, destination, service, schedule and action
- An implicit deny at the end blocks anything not allowed
- NAT and security profiles are applied through policies

### 03. User Authentication with a Next-Generation Firewall
Identifying **who** is using the network, not only which IP address. Covers local users, directory services (such as LDAP and Active Directory), and single sign-on, so policies can be based on users and groups.

### 04. How Next-Generation Firewalls Block Malware
How the firewall detects and stops malicious files: antivirus scanning, sandboxing of unknown files, and threat intelligence updates. Includes the role of **SSL inspection**, since much malware travels inside encrypted traffic.

### 05. Controlling Web Access with Web Filtering
Allowing or blocking websites by category (social media, gambling, malware sites), by URL or by reputation. Used to reduce risk and enforce company policy.

### 06. Intrusion Prevention System and Application Control on FortiGate
- **IPS:** detects and blocks known attack patterns and exploits in network traffic
- **Application control:** identifies and controls applications (such as streaming, file sharing or messaging) even when they use common ports

### 07. Connecting Multiple Locations Securely
Using **VPNs** to link branches, remote workers and data centers over the internet:
- **Site-to-site IPsec VPN** connects two locations
- **Remote access VPN** connects individual users
- Traffic is encrypted, which ties back to cryptography in NSE 1

### 08. SD-WAN
Software-defined WAN: using several internet or WAN links together, and sending each application over the best link based on quality (latency, loss, jitter). It improves performance and keeps traffic flowing if a link fails.

### 09. SASE
Secure Access Service Edge: delivering security and networking from the cloud for users who work anywhere. It combines functions such as secure web gateway, ZTNA and firewall-as-a-service, so security follows the user instead of the office.

## Key Takeaways

- A modern firewall is **application-, user- and content-aware**, not just port-based
- **Policy order matters.** The first matching policy decides the outcome
- Security profiles (antivirus, web filter, IPS, application control) add layers on top of policies
- **SSL inspection** is needed to see inside encrypted traffic
- VPN, SD-WAN and SASE extend protection beyond a single office

## How It Connects to My Path

| Step | Course | Status |
|---|---|---|
| 1 | NSE 1: Information Security Awareness | ✅ Completed |
| 2 | NSE 2: Introduction to Next Generation Firewall | ✅ Completed |
| 3 | NSE 3 | 🔜 Next |
| 4 | FCP: FortiGate Administrator (formerly NSE 4) | 🎯 Goal |

NSE 2 is the theory behind the FortiGate lab work: policies, security profiles, VPN and logging.

## Next Steps

- Build the FortiGate lab: zones, policies, NAT and security profiles
- Test IPS and web filtering and keep logs as evidence
- Set up a site-to-site IPsec VPN
- Continue with NSE 3 and prepare for FCP FortiGate Administrator
