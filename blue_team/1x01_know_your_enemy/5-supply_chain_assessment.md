# The Supply Chain Question — MedDefense Third-Party Risk Analysis

## Project Goal

Analyze third-party risk exposure across the MedDefense vendor ecosystem. The objective is to identify vendor access levels, understand possible compromise paths, evaluate existing protections, and determine the highest-risk supply chain relationships.

Third-party vendors introduce additional attack surfaces because they may have access to MedDefense systems, networks, applications, or sensitive healthcare data. A compromise of a trusted vendor can become a direct compromise of MedDefense.

---

# Vendor 1: MedTech Solutions

## Service

Electronic Health Record (EHR) maintenance provider.

MedTech Solutions provides technical support and maintenance for MedDefense's EHR environment under an annual contract with a 4-hour response SLA.

## Access Type

**Network Access + Application Access**

## Access Scope

MedTech Solutions has direct maintenance access to:

- EHR application servers.
- EHR database systems.
- Clinical systems supporting patient records.
- Potentially administrative interfaces used for troubleshooting.

Data accessible may include:

- Patient medical records.
- Clinical information.
- Healthcare documentation.

## Compromise Scenario

If MedTech Solutions is breached, attackers could use stolen vendor credentials or remote access tools to enter MedDefense's environment.

Possible attack path:

1. Attacker compromises MedTech employee account.
2. Uses vendor remote access connection.
3. Connects directly to EHR infrastructure.
4. Steals patient records or deploys ransomware.
5. Moves laterally through the flat network.

Because the vendor has privileged access to critical healthcare systems, compromise could directly affect patient care.

## Existing Controls

- Firewall protection.
- Authentication controls.
- Limited access through vendor maintenance channels.

Related MedDefense gaps:

**G-005 — No network segmentation exists at Central.**

A compromised vendor account could move across the internal network because critical systems share the same network segment.

**GAP-005 — No centralized log correlation or automated alerting exists.**

Vendor activity may not be detected quickly.

## Risk Assessment

**Critical Risk**

Justification:

MedTech has direct access to the organization's most critical system: the EHR environment. A compromise could expose patient records, disrupt clinical operations, or introduce ransomware.

---

# Vendor 2: Microsoft

## Service

Microsoft Office 365 E3 platform.

Provides:

- Email.
- SharePoint.
- OneDrive.
- Collaboration services.
- Identity services if Entra ID is used.

## Access Type

**Application Access + Data Access + Identity Access**

## Access Scope

Microsoft services may contain:

- Employee email.
- Documents.
- Internal communications.
- SharePoint files.
- OneDrive data.
- User identity information.

If Entra ID is used:

- User authentication.
- Account permissions.
- Identity management.

## Compromise Scenario

If Microsoft accounts or tenant configuration are compromised:

1. Attacker gains access through stolen credentials.
2. Reads confidential emails and documents.
3. Uses compromised accounts for phishing.
4. Accesses cloud files containing sensitive information.
5. Attempts privilege escalation.

## Existing Controls

- User authentication.
- Microsoft security features.
- Account permissions.

Related MedDefense gaps:

**GAP-003 — Secondary domain controller has no backup and no dedicated hardening.**

Weak identity protection increases the impact of compromised accounts.

**GAP-012 — Security awareness training has low completion and no phishing simulation program.**

Users remain vulnerable to credential theft.

## Risk Assessment

**High Risk**

Justification:

Microsoft hosts large amounts of sensitive business data and may control authentication. A compromise could expose confidential information and provide attackers with trusted accounts.

---

# Vendor 3: Sophos

## Service

Endpoint protection platform.

Sophos provides antivirus and endpoint security agents installed on managed endpoints.

## Access Type

**Endpoint Management Access**

## Access Scope

Sophos can:

- Push security updates.
- Configure endpoint policies.
- Detect malware.
- Manage endpoint protection settings.

Affected assets:

- Employee workstations.
- Managed endpoints.

## Compromise Scenario

If Sophos infrastructure or update mechanisms are compromised:

1. Attacker abuses trusted software updates.
2. Malicious code is distributed to MedDefense endpoints.
3. Malware executes with security software privileges.
4. Attack spreads through the environment.

## Existing Controls

- Sophos endpoint agents.
- Endpoint security configuration.

Related MedDefense gaps:

**GAP-004 — Antivirus/endpoint protection does not cover Linux servers or Windows servers.**

Critical servers remain outside endpoint protection coverage.

**G-004 — Logging exists but nothing aggregates, correlates, or actively alerts.**

Malicious endpoint activity may not be detected quickly.

## Risk Assessment

**High Risk**

Justification:

Sophos has trusted administrative capability over many endpoints. A vendor compromise could provide attackers with a powerful distribution mechanism.

---

# Vendor 4: Siemens

## Service

MRI scanner manufacturer.

Provides:

- MRI workstation maintenance.
- Firmware updates.
- Hardware support.

## Access Type

**Physical Access + Medical Device Access**

## Access Scope

Siemens technicians may access:

- MRI workstation.
- Medical imaging systems.
- Device firmware.
- Scanner configuration.

Potential data exposure:

- Medical imaging data.
- Patient information processed by the scanner.

## Compromise Scenario

If Siemens maintenance systems are compromised:

1. Attacker compromises technician credentials.
2. Uses maintenance access to MRI workstation.
3. Installs malware or modifies firmware.
4. Disrupts imaging services or accesses patient data.

## Existing Controls

- Vendor maintenance procedures.
- Physical access restrictions.

Related MedDefense gaps:

**GAP-002 — PACS imaging server has no preventive or corrective control.**

Imaging systems lack strong protection.

**GAP-001 — Medical IoT devices have no control coverage of any kind.**

Medical devices lack monitoring and security controls.

## Risk Assessment

**Critical Risk**

Justification:

MRI systems support patient diagnosis. A compromise could impact healthcare operations and patient safety.

---

# Vendor 5: Greenfield Building Management

## Service

HQ building management.

Provides:

- Building network infrastructure management.
- Office networking services.

## Access Type

**Network Access + Physical Access**

## Access Scope

Greenfield manages:

- Building network infrastructure.
- Network connectivity supporting MedDefense VLAN.
- Physical building access.

Potential exposure:

- Internal network connectivity.
- Office systems.
- Physical access areas.

## Compromise Scenario

If Greenfield is breached:

1. Attackers compromise building network infrastructure.
2. Access MedDefense VLAN.
3. Scan internal systems.
4. Attempt lateral movement.
5. Target employee devices or sensitive systems.

## Existing Controls

- VLAN separation.
- Firewall controls.

Related MedDefense gaps:

**G-005 — No network segmentation exists at Central.**

Insufficient segmentation increases the impact of third-party network compromise.

**GAP-007 — Undocumented devices exist on sensitive network segments.**

Limited visibility increases detection difficulty.

## Risk Assessment

**High Risk**

Justification:

A compromised building management provider could provide attackers with network access or physical access to MedDefense resources.

---

# Supply Chain Risk Summary

The vendor compromise that would cause the most damage to MedDefense is **MedTech Solutions** because it has direct maintenance access to the EHR environment, which contains the organization's most sensitive healthcare data and supports critical clinical operations. A compromised MedTech account could allow attackers to bypass normal defenses, access patient records, deploy ransomware, or disrupt healthcare services.

The first control MedDefense should implement to reduce supply chain risk across all vendors is a **formal third-party access management program**. This should include vendor inventory, risk assessments, least-privilege access, MFA requirements, access reviews, vendor activity monitoring, and immediate removal of unnecessary vendor access.

This directly addresses existing gaps:

- **G-002:** Lack of administrative detection and review processes.
- **G-004 / GAP-005:** Weak monitoring and lack of centralized logging.
- **G-005:** Flat network architecture increasing vendor compromise impact.

MedDefense currently trusts vendors with significant access but lacks sufficient visibility and control over what those vendors can reach.
