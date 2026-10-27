# HIPAA Breach Risk Assessment: IR-2026-0420-01

- **Assessment Date:** 2026-04-20
- **Conducted By:** On-Call IR Analyst
- **Reviewed By:** Helena Reyes, General Counsel (Pending)
- **PHI Involved:** 1,847 patient files (1,120 clinical progress notes and 482 lab results / 245 diagnostic records) accessed from `FILE-SVR-01`.

---

## Factor 1: Nature and Extent of PHI Involved
- **Evidence:** Forensic findings from `fileserver_access.evtx` (Finding FS-001) confirm that an unauthorized session authenticated using compromised credentials (`coord_user`) read 1,847 sensitive patient records consisting of clinical progress notes and laboratory results.
- **Conclusion:** The data includes direct Protected Health Information (PHI) identifiers and clinical care details, representing highly sensitive medical records.
- **Confidence:** Confirmed

## Factor 2: Unauthorized Person Who Used the PHI or To Whom the Disclosure Was Made
- **Evidence:** Analysis of proxy logs (`proxy_72h.jsonl`, Finding PRX-002) and memory artifacts (`cs-ws-101.mem`, Finding MEM-003) establish that the access was performed by an automated remote-access tool (Cobalt Strike beacon) controlled by an external threat actor operating from IP `45.152.66.114`.
- **Conclusion:** The recipient is an external, unidentified malicious actor, meaning the data was exposed to an unauthorized third party with intent to extort or publish.
- **Confidence:** Confirmed

## Factor 3: Whether the PHI Was Actually Acquired or Viewed
- **Evidence:** Windows Security Event Log `fileserver_access.evtx` (Finding FS-001) records 1,847 explicit object access events (`Event ID 4663` with `AccessMask: 0x1 - ReadData`) demonstrating that files were sequentially opened and read over the network share during a 27-minute window.
- **Conclusion:** Files were actively viewed and exfiltrated through established outbound C2 channels.
- **Confidence:** Confirmed

## Factor 4: Extent to Which the Risk Has Been Mitigated
- **Evidence:** Containment actions successfully severed C2 communications, isolated affected endpoints, and revoked compromised credentials (Containment Execution Record). However, egress traffic logs prior to isolation recorded large data exchanges with the external server (`proxy_72h.jsonl`), and no technical mechanism exists to recall data once viewed and exfiltrated by an external actor.
- **Conclusion:** While further unauthorized access has been completely halted, the risk of the already-accessed PHI having been exfiltrated cannot be mitigated.
- **Confidence:** Confirmed

---

## Final Determination
- **Determination:** The four-factor assessment **fails to meet** the threshold of a "low probability of compromise." Therefore, mandatory breach notification rules under HIPAA apply.
- **Authorizing Role & Timeline:** The final legal determination and notification schedule are authorized by Helena Reyes, General Counsel, in coordination with executive leadership, with statutory notifications to be prepared for release within the 60-day HIPAA window.
