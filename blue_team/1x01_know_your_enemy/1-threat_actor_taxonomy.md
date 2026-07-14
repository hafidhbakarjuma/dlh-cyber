# Threat Actor Taxonomy Report

---

# Executive Summary

This report classifies eight anonymized cybersecurity incidents based on observable attacker behavior rather than attribution. Each report is analyzed using the six Security+ threat actor categories:

- Nation-State
- Organized Crime
- Hacktivist
- Insider Threat
- Unskilled Attacker
- Shadow IT

Each classification evaluates the actor's operational characteristics, likely motivation, sophistication, available resources, and confidence level.

---

# Report A

### Actor Type
**Nation-State**

### Internal / External
**External**

The attackers compromised the organization remotely through a zero-day VPN vulnerability and remained inside the network for over a year.

### Resources
**High**

The operation involved custom malware, stolen code-signing certificates, encrypted DNS command-and-control, and exploitation of a zero-day vulnerability.

### Sophistication
**High**

The attackers demonstrated advanced persistence, stealth, custom tooling, and long-term espionage capabilities that exceed criminal operations.

### Primary Motivation
**Espionage**

The attackers focused exclusively on stealing valuable pharmaceutical research worth billions rather than disrupting operations or demanding payment.

### Confidence Level
**High**

The combination of zero-day exploitation, custom malware, long dwell time, and theft of strategic intellectual property strongly indicates a nation-state Advanced Persistent Threat (APT).

---

# Report B

### Actor Type
**Organized Crime**

### Internal / External
**External**

The attack originated through phishing emails and culminated in ransomware deployment.

### Resources
**Medium to High**

The attackers used commercial malware, phishing infrastructure, ransomware, and operated a professional extortion campaign.

### Sophistication
**Medium to High**

The campaign involved social engineering, patient data theft, lateral movement, and double extortion.

### Primary Motivation
**Financial Gain**

The attackers demanded cryptocurrency while threatening to leak stolen patient data.

### Confidence Level
**High**

The ransomware deployment and double extortion model are consistent with modern organized cybercriminal groups.

---

# Report C

### Actor Type
**Hacktivist**

### Internal / External
**External**

The attackers exploited a public-facing SQL injection vulnerability.

### Resources
**Low**

Only publicly known web exploitation techniques were used.

### Sophistication
**Low**

The attackers limited their activity to website defacement and made no attempt to compromise internal systems.

### Primary Motivation
**Political / Ideological Beliefs**

The attack publicly protested the hospital's closure of a community health clinic.

### Confidence Level
**High**

The political message and absence of financial or espionage objectives strongly indicate hacktivism.

---

# Report D

### Actor Type
**Insider Threat**

### Internal / External
**Internal**

The attacker was a former IT administrator who abused privileged access before and after termination.

### Resources
**Medium**

The attacker relied primarily on legitimate administrative privileges rather than advanced hacking tools.

### Sophistication
**Medium**

The attacker planned the sabotage by creating hidden VPN access and disabling backups before deleting production data.

### Primary Motivation
**Revenge**

The destructive actions immediately followed termination from employment.

### Confidence Level
**High**

The evidence directly links the malicious activity to a disgruntled insider.

---

# Report E

### Actor Type
**Unskilled Attacker**

### Internal / External
**External**

The compromise occurred through automated exploitation of an internet-facing vulnerability.

### Resources
**Low**

The attackers used publicly available cryptocurrency mining software and automated exploit scanning.

### Sophistication
**Low**

No persistence, privilege escalation, lateral movement, or data theft occurred.

### Primary Motivation
**Financial Gain**

The objective was cryptocurrency mining rather than espionage or ransomware.

### Confidence Level
**High**

The widespread automated infections and use of commodity tools are typical of opportunistic attackers.

---

# Report F

### Actor Type
**Shadow IT**

### Internal / External
**Could be Both**

The employee unintentionally introduced an unauthorized device (internal), which was later exploited by an external attacker.

### Resources
**Low**

The employee used a personal Raspberry Pi with default credentials.

### Sophistication
**Low**

The security failure resulted from poor configuration rather than advanced attack techniques.

### Primary Motivation
**No Malicious Intent (Employee)**

The employee connected the device for a personal project. The external attacker later exploited the exposed system for unauthorized access.

### Confidence Level
**High**

The defining issue is unauthorized technology introduced by an employee, which matches the Shadow IT category.

---

# Report G

### Actor Type
**Most Likely: Insider Threat**

### Internal / External
**Could Be Either**

The legitimate physician account was used, but there is no evidence the physician performed the activity.

### Resources
**Medium**

The attacker possessed valid credentials and carefully selected valuable patient records while avoiding immediate detection.

### Sophistication
**Medium**

The activity was deliberate and focused but did not involve advanced malware or destructive actions.

### Primary Motivation
**Data Theft / Financial Gain**

The records focused on patients with high-value insurance plans, suggesting future fraud or resale.

### Confidence Level
**Medium**

The evidence does not conclusively identify the attacker.

### Why Multiple Actor Types Could Fit

This incident is intentionally ambiguous because several explanations remain possible.

#### Possibility 1 – Insider Threat

A hospital employee with access to the physician's credentials may have intentionally stolen patient records for financial gain.

**Supporting evidence**

- Legitimate credentials were used.
- Access patterns suggest knowledge of hospital systems.
- Patient selection appears deliberate.

---

#### Possibility 2 – Organized Crime

External attackers may have stolen the physician's credentials through phishing, malware, or credential theft before using them to collect valuable medical information.

**Supporting evidence**

- Physician was overseas.
- Consistent remote IP address.
- High-value insurance records indicate financial motivation.

---

#### Evidence Needed to Distinguish

Investigators would need:

- Authentication logs (MFA usage)
- VPN connection history
- Endpoint forensic evidence
- Browser and malware analysis
- Credential theft indicators
- Insider access logs
- Network traffic analysis
- Dark web intelligence regarding stolen credentials

---

# Report H

### Actor Type
**Organized Crime**

### Internal / External
**External**

The attackers exploited a vulnerable public API through the Tor network.

### Resources
**Medium**

The attackers possessed enough capability to discover and exploit API authentication weaknesses.

### Sophistication
**Medium**

The attackers combined data theft with extortion but did not use advanced persistence techniques.

### Primary Motivation
**Blackmail / Financial Gain**

The attackers demanded cryptocurrency in exchange for withholding both vulnerability information and stolen patient records.

### Confidence Level
**High**

The cryptocurrency demand and extortion strategy closely resemble financially motivated cybercriminal activity.

---

# Overall Classification Summary

| Report | Actor Type | Internal / External | Resources | Sophistication | Primary Motivation | Confidence |
|---------|------------|--------------------|-----------|----------------|-------------------|------------|
| A | Nation-State | External | High | High | Espionage | High |
| B | Organized Crime | External | Medium-High | Medium-High | Financial Gain | High |
| C | Hacktivist | External | Low | Low | Political / Ideological Beliefs | High |
| D | Insider Threat | Internal | Medium | Medium | Revenge | High |
| E | Unskilled Attacker | External | Low | Low | Financial Gain | High |
| F | Shadow IT | Could Be Both | Low | Low | No Malicious Intent (Employee) | High |
| G | Insider Threat *(Most Likely)* | Could Be Either | Medium | Medium | Data Theft / Financial Gain | Medium |
| H | Organized Crime | External | Medium | Medium | Blackmail / Financial Gain | High |

---

# Key Findings

- Nation-state actors target valuable intellectual property using advanced espionage techniques.
- Organized cybercriminal groups focus on ransomware, extortion, and financial profit.
- Hacktivists seek publicity and ideological impact rather than monetary gain.
- Insider threats remain dangerous because trusted users already possess legitimate access.
- Opportunistic attackers exploit known vulnerabilities using automated tools and publicly available malware.
- Shadow IT significantly increases organizational risk by introducing unmanaged and insecure devices.
- Report G demonstrates why threat actor attribution often requires additional forensic evidence beyond observable behavior alone.
