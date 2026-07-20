# MedDefense Vulnerability Remediation Matrix

**Total Estimated Remediation Cost**: $108,500 / $120,000 Budget

## Immediate Horizon

| ID | Description | Action | Owner | Cost |
| :--- | :--- | :--- | :--- | :--- |
| 001 | FortiGate 100F RCE | Firmware Patch | IT | $5,000 |
| 002 | DC-01 EternalBlue | KB Patch | IT | $1,000 |
| 003 | EHR-SRV-01 Ghostcat | Patch Tomcat | IT/Vendor | $25,000 |
| 004 | WS-RAD-01 Windows XP | Network Isolation | Security | $500 |
| 019 | DC-02 PrintNightmare | KB Patch | IT | $1,000 |
| 031 | EHR-SRV-01 Ghostcat | Patch Tomcat | IT/Vendor | $25,000 |

## Short-term Horizon

| ID | Description | Action | Owner | Cost |
| :--- | :--- | :--- | :--- | :--- |
| 006 | IoT Gateway hard-coded creds | Credential Update | IT | $5,000 |
| 021 | NAS-Mgmt-01 default creds | Password Reset | IT | $1,000 |
| 024 | BD-Alaris-03 Auth Bypass | Segmentation | Security | $5,000 |

## Medium-term Horizon

| ID | Description | Action | Owner | Cost |
| :--- | :--- | :--- | :--- | :--- |
| 008 | BD-Alaris-01 Firmware | Vendor Exception/Segment | Clinical | $10,000 |
| 009 | BD-Alaris-02 Firmware | Vendor Exception/Segment | Clinical | $10,000 |
| 010 | Philips HL7 Unauth | Network ACL | Security | $2,000 |
| 016 | Philips Web Unauth | Network ACL | Security | $2,000 |
| 011 | Billing-Srv-01 HTTP | HTTPS Config | IT | $2,000 |
| 022 | NAS-Mgmt-01 HTTP | HTTPS Config | IT | $2,000 |
| 025 | NAS-Mgmt-01 Password Policy | Policy Update | IT | $500 |
| 020 | File-Srv-01 SMB Signing | Policy Change | IT | $500 |

## Long-term Horizon

| ID | Description | Action | Owner | Cost |
| :--- | :--- | :--- | :--- | :--- |
| 005 | Portal-Web-01 Headers | Code Change | IT | $5,000 |
| 007 | Portal-Web-01 TLS 1.0 | Cipher Update | IT | $2,000 |
| 013 | EHR-SRV-01 Info Disc | Hardening | IT | $1,000 |
| 014 | Portal-Web-01 Banner Disc | Hardening | IT | $1,000 |
| 017 | EHR-SRV-01 Dir Listing | Hardening | IT | $1,000 |
| 028 | VPN Session Timeout | Config Update | IT | $500 |
| 030 | Email-Srv-01 SPF | DNS Update | IT | $500 |
