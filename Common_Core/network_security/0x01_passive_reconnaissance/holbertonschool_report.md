# Passive Reconnaissance Report - holbertonschool.com

**Date:** May 25, 2026  
**Target:** `holbertonschool.com`  
**Tool Used:** Shodan  
**Objective:** Passive reconnaissance (IP ranges, technologies, subdomains)

## Executive Summary

Passive reconnaissance on `holbertonschool.com` reveals that the domain is primarily hosted on **Amazon Web Services (AWS)** in the Paris region (`eu-west-3`). Two main public IP addresses were identified, both running **Nginx** web servers. A notable subdomain `yriry2.holbertonschool.com` hosts the **Holberton School Level2 Forum**. The infrastructure uses Let's Encrypt certificates and standard security headers.

## 1. Collected IP Addresses & Ranges

### Discovered IPs:
| IP Address          | Hostname                                              | Location          | ASN / Provider                  |
|---------------------|-------------------------------------------------------|-------------------|---------------------------------|
| 52.47.143.83        | ec2-52-47-143-83.eu-west-3.compute.amazonaws.com     | Paris, France     | Amazon Data Services France    |
| 35.180.27.154       | ec2-35-180-27-154.eu-west-3.compute.amazonaws.com    | Paris, France     | Amazon Data Services France    |

### Associated IP Ranges (AWS eu-west-3)
Since both IPs belong to AWS Paris region, the following broader ranges are relevant:

- `35.180.0.0/16`
- `52.47.0.0/16`
- `13.37.0.0/16` (common in eu-west-3)
- `18.100.0.0/16` (common in eu-west-3)

These ranges are part of Amazon EC2 public IP space for the Paris availability zone.

## 2. Discovered Subdomains

- `holbertonschool.com` (main domain)
- `yriry2.holbertonschool.com` → **Holberton School Level2 Forum**

## 3. Technologies & Frameworks Detected

### Web Servers
- **Nginx**
  - Version: `1.21.6`
  - Version: `1.18.0 (Ubuntu)`

### SSL/TLS
- **Let's Encrypt** (Authority)
- Supported protocols: **TLSv1.2**, **TLSv1.3**
- Certificate CN: `yriry2.holbertonschool.com`

### Security Headers
- `X-Frame-Options: SAMEORIGIN`
- `X-Content-Type-Options: nosniff`
- `X-XSS-Protection: 0`
- `X-Download-Options: noopen`

### Platform / Application
- **Holberton School Level2 Forum** (Custom forum platform)
- HTTP Redirection (301 Moved Permanently) heavily used

### Infrastructure
- **Cloud Provider:** Amazon Web Services (AWS)
- **Region:** eu-west-3 (Paris)
- **Service Type:** EC2 instances

## 4. Observations & Notes

- The main domain uses redirects to route traffic to subdomains or HTTPS.
- The forum subdomain (`yriry2.holbertonschool.com`) appears to be the most active service discovered.
- No other frameworks (React, Django, Laravel, etc.) were explicitly fingerprinted in the Shodan banners, but the stack is clearly **Nginx + AWS**.
- Use of Let's Encrypt suggests frequent certificate renewal and modern DevOps practices.

## 5. Recommendations for Further Passive Reconnaissance

- Use `crt.sh`, `Amass`, or `Subfinder` for more subdomains.
- Query DNS records (`TXT`, `MX`, `NS`) for the domain.
- Search Shodan with more specific filters (`hostname:holbertonschool.com`).
- Check GitHub and public repositories for exposed Holberton School projects.

---

**Report Status:** Based on available Shodan data (May 2026)
