# MedDefense Kill Chains

## Five Critical Attack Paths from Initial Access to Final Impact

Date: July 14, 2026

References:
- Task 9: Vector-to-Asset Matrix
- Task 6: Threat Actor Matrix
- Project 1x00: Asset Registry
- Project 1x00: Gap Analysis


# Kill Chain #1: Ransomware Attack Through Phishing to EHR Encryption

## Threat Actor:
Ransomware Groups (Organized Crime / RaaS)

Reference:
Task 6 Threat Actor Matrix - High capability financially motivated attackers targeting healthcare organizations.

## Target Asset:
EHR Database (ehr-db-01)

## Expected Impact:
A successful ransomware attack could interrupt healthcare operations, prevent clinicians from accessing patient records, and expose sensitive patient information.

CIA Impact:
- Confidentiality: Patient data stolen and potentially leaked.
- Integrity: Systems and records modified or encrypted.
- Availability: EHR services unavailable.


## Step 1 - Initial Access:

**Vector:** Phishing / Spear Phishing

**Surface:** Human

**Detail:**
The attacker sends a targeted phishing email to a MedDefense employee. The employee enters credentials into a fake login page, allowing the attacker to obtain valid user access.


## Step 2 - Establish Foothold:

**Action:**
The attacker uses stolen credentials to access internal resources and installs malware to maintain persistence.

**MedDefense Weakness:**
- Weak MFA implementation.
- Limited endpoint monitoring.
- Security awareness training gaps.


## Step 3 - Lateral Movement / Escalation:

**Action:**
The attacker moves through the internal network, discovers critical servers, and reaches the EHR database.

**MedDefense Weakness:**
- Flat network architecture.
- Lack of internal segmentation.
- Excessive internal access permissions.


## Step 4 - Objective Execution:

**Action:**
The attacker encrypts EHR systems and steals patient information for double extortion.

**Data/System Affected:**
- ehr-db-01
- Patient medical records
- Clinical applications


## Step 5 - Impact:

**Business Impact:**
- Clinical operations disrupted.
- Doctors cannot access patient history.
- Procedures may be delayed.
- Recovery costs increase.
- Regulatory investigation may occur.

**CIA Pillars:**
- Confidentiality: Patient records exposed.
- Integrity: Data modified or encrypted.
- Availability: Healthcare systems unavailable.


## Gaps Exploited:

- GAP-001: Flat Network Architecture
- GAP-002: Weak Identity and Access Management
- GAP-005: Limited Monitoring
- GAP-009: Security Awareness Weakness


## Break Points:

- Step 1:
  MFA and phishing-resistant authentication could prevent stolen credentials from being used.

- Step 3:
  Network segmentation could prevent attackers from moving from user systems to EHR servers.

- Step 4:
  Immutable backups could reduce ransomware impact and speed recovery.



# Kill Chain #2: VPN Compromise to Medical IoT Disruption

## Threat Actor:
Ransomware Groups / Opportunistic Attackers

Reference:
Task 6 Threat Actor Matrix - Attackers targeting healthcare availability and operational disruption.

## Target Asset:
Medical IoT Devices (BD Alaris Pumps, Patient Monitoring Systems)

## Expected Impact:
Compromise of medical devices could disrupt patient care and create safety risks.

CIA Impact:
- Integrity: Device settings modified.
- Availability: Medical services interrupted.


## Step 1 - Initial Access:

**Vector:** VPN Exploit

**Surface:** External

**Detail:**
The attacker obtains VPN credentials through phishing or credential attacks. Because MFA protection is insufficient, the attacker successfully connects remotely.


## Step 2 - Establish Foothold:

**Action:**
The attacker creates a remote session and performs internal reconnaissance.

**MedDefense Weakness:**
- VPN access provides broad internal access.
- Limited monitoring of remote connections.


## Step 3 - Lateral Movement / Escalation:

**Action:**
The attacker scans the flat network and discovers medical IoT management interfaces.

**MedDefense Weakness:**
- No IoT network isolation.
- Flat network allows device discovery.


## Step 4 - Objective Execution:

**Action:**
The attacker accesses medical device interfaces using weak or default credentials.

**Data/System Affected:**
- BD Alaris infusion pumps
- Patient monitoring systems


## Step 5 - Impact:

**Business Impact:**
- Clinical disruption.
- Medical device downtime.
- Patient safety risks.
- Regulatory reporting requirements.

**CIA Pillars:**
- Integrity: Device settings changed.
- Availability: Devices unavailable.


## Gaps Exploited:

- GAP-001: Flat Network
- GAP-002: Weak Authentication
- GAP-007: Medical Device Security Weakness


## Break Points:

- Step 1:
  MFA on VPN prevents unauthorized remote access.

- Step 3:
  IoT network segmentation prevents attackers reaching medical devices.

- Step 4:
  Removing default credentials blocks unauthorized device control.



# Kill Chain #3: Supply Chain Compromise to EHR Data Theft

## Threat Actor:
Nation-State APT / Organized Crime

Reference:
Task 6 Threat Actor Matrix - Advanced attackers using trusted third parties.

## Target Asset:
EHR System and Patient Database

## Expected Impact:
Long-term unauthorized access, patient data theft, and loss of trust in vendors.


## Step 1 - Initial Access:

**Vector:** Supply Chain Compromise

**Surface:** External

**Detail:**
An attacker compromises a trusted vendor account that has access to MedDefense systems.


## Step 2 - Establish Foothold:

**Action:**
The attacker uses vendor access to maintain persistence.

**MedDefense Weakness:**
- Weak third-party access controls.
- Limited vendor monitoring.


## Step 3 - Lateral Movement / Escalation:

**Action:**
The attacker moves from vendor-connected systems toward internal databases.

**MedDefense Weakness:**
- Flat network.
- Poor vendor segmentation.


## Step 4 - Objective Execution:

**Action:**
The attacker accesses patient records and extracts sensitive healthcare information.

**Data/System Affected:**
- EHR database
- Patient records


## Step 5 - Impact:

**Business Impact:**
- Privacy breach.
- Regulatory penalties.
- Patient trust damage.
- Vendor relationship impact.

**CIA Pillars:**
- Confidentiality: Patient data exposed.
- Integrity: Systems may be altered.


## Gaps Exploited:

- GAP-001: Network Segmentation Weakness
- GAP-006: Third-Party Risk Weakness
- GAP-005: Monitoring Gap


## Break Points:

- Step 1:
  Vendor MFA and access reviews reduce stolen credential risk.

- Step 3:
  Vendor network segmentation prevents movement into critical systems.

- Step 4:
  Data monitoring detects unusual database access.



# Kill Chain #4: Vulnerable Software Exploit to Billing System Compromise

## Threat Actor:
Nation-State APT / Opportunistic Attackers

Reference:
Task 6 Threat Actor Matrix - Attackers exploiting vulnerable services.

## Target Asset:
Billing Server (billing-srv-01)

## Expected Impact:
Financial loss, operational disruption, and possible movement toward critical systems.


## Step 1 - Initial Access:

**Vector:** Vulnerable Software Exploit

**Surface:** External/Internal

**Detail:**
The attacker exploits outdated Apache software and unsupported operating systems identified during assessment.


## Step 2 - Establish Foothold:

**Action:**
The attacker installs malware and maintains access.

**MedDefense Weakness:**
- Outdated software.
- Weak patch management.


## Step 3 - Lateral Movement / Escalation:

**Action:**
The attacker uses the compromised billing server to reach other systems.

**MedDefense Weakness:**
- Flat network.
- Excessive internal connectivity.


## Step 4 - Objective Execution:

**Action:**
The attacker steals financial information or uses the server as a pivot point.

**Data/System Affected:**
- billing-srv-01
- Financial records


## Step 5 - Impact:

**Business Impact:**
- Financial losses.
- Billing disruption.
- Recovery expenses.

**CIA Pillars:**
- Confidentiality.
- Integrity.
- Availability.


## Gaps Exploited:

- GAP-001: Flat Network
- GAP-004: Patch Management Weakness
- GAP-005: Monitoring Gap


## Break Points:

- Step 1:
  Regular patching removes known vulnerabilities.

- Step 3:
  Segmentation prevents server-to-server movement.



# Kill Chain #5: Negligent Insider Leading to Malware Infection

## Threat Actor:
Insider (Negligent)

Reference:
Task 6 Threat Actor Matrix - Users creating risk through mistakes.

## Target Asset:
Active Directory and Internal Systems

## Expected Impact:
A user mistake could allow malware infection and lead to wider compromise.


## Step 1 - Initial Access:

**Vector:** Insider (Negligent)

**Surface:** Human / Internal

**Detail:**
An employee connects an unmanaged device or opens a malicious attachment, allowing malware into the environment.


## Step 2 - Establish Foothold:

**Action:**
Malware executes and attempts persistence.

**MedDefense Weakness:**
- Lack of endpoint control.
- Limited user awareness.


## Step 3 - Lateral Movement / Escalation:

**Action:**
The malware spreads through the flat network.

**MedDefense Weakness:**
- No segmentation.
- Weak monitoring.


## Step 4 - Objective Execution:

**Action:**
Attackers deploy ransomware or steal credentials.

**Data/System Affected:**
- Active Directory
- User systems
- Shared resources


## Step 5 - Impact:

**Business Impact:**
- Operational disruption.
- Recovery costs.
- Employee productivity loss.

**CIA Pillars:**
- Confidentiality.
- Integrity.
- Availability.


## Gaps Exploited:

- GAP-001: Flat Network
- GAP-005: Monitoring Weakness
- GAP-009: Security Awareness Gap


## Break Points:

- Step 1:
  Security awareness training and email filtering reduce risk.

- Step 3:
  Network segmentation limits malware spread.

- Step 4:
  Endpoint detection can stop ransomware execution.
