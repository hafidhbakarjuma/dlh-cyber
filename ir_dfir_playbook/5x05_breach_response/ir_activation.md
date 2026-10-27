# IR Activation: IR-2026-0420-01

- **Incident ID:** IR-2026-0420-01
- **Declared At:** 2026-04-20T19:52Z
- **Declared By:** On-call IR Analyst
- **Initial Severity:** SEV1
- **Reasoning:** Confirmed persistent Cobalt Strike beaconing active for 72 hours, unauthorized lateral movement across clinical workstations via extracted NTLM hashes, access to 1,847 patient files and lab results on the clinical documentation file server, and ransomware staging scripts placed on system directories across multiple hosts. This represents an active, severe threat to patient safety, clinical operations, and regulatory compliance (HIPAA).
- **Playbook Activated:** Comprehensive Incident Response & Ransomware Playbook (IR-PL-02 / APT & Extortion Response)
- **Notifications:**
  - 19:52Z: Mike Torres (IT Infrastructure Lead) notified and emergency bridge established.
  - 19:54Z: CISO and Legal Counsel notified regarding potential PHI access and regulatory breach scope.
  - 19:56Z: Core Incident Response and Forensics team mobilized.
- **First Communication:** Executive status update (`executive_status_update`) sent to Dr. Morales (Chief Medical Officer / Executive Leadership) at 20:05Z.
