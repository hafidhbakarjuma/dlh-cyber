# Tabletop Exercise: Nexus Supply Chain Compromise

**Date:** 2026-10-25  
**Classification:** Internal - Exercise Use Only  
**Facilitator:** Incident Response Lead  
**Scenario Version:** 1.0  

---

## Organization background

MedDefense operates three primary healthcare sites: Main Hospital, West Campus Specialty Center, and South Campus Outpatient Clinic. Across these facilities, the organization manages approximately 3,500 patient appointments weekly. MedDefense relies heavily on third-party SaaS integrations for clinical workflows while maintaining strict compliance with the HIPAA Privacy and Security Rules, the HIPAA Breach Notification Rule, and Business Associate Agreements (BAAs).

## Vendor background

Nexus Patient Scheduling is a third-party SaaS vendor used by MedDefense for automated appointment management, patient demographic ingest, and physician roster management across all three sites. Nexus integrates directly with MedDefense's EHR (Epic) via a certified HL7 FHIR API integration layer.

Under the executed BAA, Nexus is classified as a Business Associate with direct access to Protected Health Information (PHI), including patient demographics, visit notes, contact details, and appointment schedules. MedDefense maintains a standard Service Level Agreement (SLA) with Nexus that includes availability terms and an emergency breach notification requirement within 24 hours of security event discovery.

## Opening situation

Three days ago, Nexus Patient Scheduling's build infrastructure was compromised by an advanced threat actor with access to their internal development environment. A signed malicious software update (v4.2.1) was distributed automatically through Nexus's standard update channel. The backdoor has been running undetected on MedDefense's Nexus agent hosts across all three sites since deployment.

Today, 45 minutes ago, the MedDefense SOC flagged unusual outbound network traffic originating from the West Campus scheduling agent server to an unknown external IP address.

## Known facts at exercise start

* **Traffic Alert:** High-severity SOC alert indicating periodic outbound network connections from the West Campus scheduling host to `193.42.100.77` (an IP associated with bulletproof hosting infrastructure) occurring on a 4-hour cycle.
* **Agent Infrastructure:** The primary scheduling agent hosts across Main Hospital (`NEXUS-SRV-01`), West Campus (`NEXUS-SRV-02`), and South Campus (`NEXUS-SRV-03`) are all actively running Nexus agent version 4.2.1.
* **System Status:** Nexus Patient Scheduling is currently online, and patient appointments are actively processing across all sites.
* **Current Telemetry:** EDR logs confirm periodic outbound C2 connections at four-hour intervals from the West Campus host. No lateral movement or secondary credential abuse within MedDefense has been detected yet.

---

## Strategic Tension Points & Organizational Ambiguities

1. **Vendor Update Trust:** The v4.2.1 update carries a valid cryptographic signature from Nexus's official code-signing certificate authority. Does a valid vendor signature make the update package trustworthy, or does it indicate a compromised build pipeline?
2. **Patient Safety vs. System Containment:** Taking the Nexus FHIR API service offline stops potential network beaconing and data exfiltration, but halts automated appointment processing for 3,500 weekly patients—potentially corrupting patient appointment records or causing missed clinical procedures.
3. **HIPAA Breach Notification Clock:** Nexus is a Business Associate handling PHI. If data exfiltration occurs through the Nexus integration, does MedDefense's direct 60-day HIPAA breach notification clock start immediately upon discovery, or does MedDefense wait for Nexus to complete its investigation and issue a formal breach report?
