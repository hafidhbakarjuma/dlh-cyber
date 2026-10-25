# Exercise Execution Record: Nexus Supply Chain Compromise Tabletop

**Simulation date:** 2026-10-25  
**Simulated by:** Tabletop Facilitator & IR Lead  

---

## Exercise Simulation Record

### INJ-00 (T+0 min)

**Inject delivered:**  
> "The SOC has flagged unusual outbound traffic from the Nexus scheduling agent host at the West Campus to 193.42.100.77, an IP associated with bulletproof hosting infrastructure. The alert fired 45 minutes ago showing periodic outbound connections on a 4-hour cycle. The Nexus system is currently operational, and patient scheduling is running normally across all three sites. No other anomalies have been detected."

**Participant responses:**
* **James Chen (SOC / IR Lead):** "Declaring a SEV-2 security incident immediately. Assigning myself as Incident Commander and initiating volatile memory and packet capture collection on the West Campus host."
* **Sarah Park (IT Director):** "Acknowledged. IT engineering is on standby, but we will hold off on host isolation until initial evidence collection is complete."
* **Dr. Patricia Morales (CEO / Executive Sponsor):** "Briefing received. Keep the incident scoped at SEV-2 for now, but provide a status update in 15 minutes."
* **Helena Reyes (Legal Counsel):** "Notified and monitoring. Standing by in case patient data exposure is indicated."
* **Marcus Webb (Third-Party Risk / Vendor Manager):** "Reviewing the Nexus SLA and BAA contacts, deferring vendor outreach until technical indicators are confirmed."
* **Robert Kim (Database Administrator):** "Verifying Epic FHIR integration bridge status; connections are functioning normally."
* **Clinical Director representative:** "Standing by; patient scheduling is operating as normal across all three sites."

**Evaluation:**
* **Criterion 1 (incident declared within 5 min):** PASS — Incident declared at SEV-2 by James Chen at T+2 minutes with explicit reasoning.
* **Criterion 2 (two roles notified):** PASS — Incident Commander, IT Director, and Legal Counsel formally notified within the inject window.
* **Criterion 3 (evidence before containment):** PASS — Host isolation deferred pending volatile memory and forensic baseline collection.

**Facilitator note:**  
*Probing question asked:* "Has anyone evaluated whether this outbound traffic originates from an authorized Nexus software process or an external binary?"  
*Finding:* The team treated the IP strictly as a network perimeter anomaly rather than examining the parent executable tree running the Nexus vendor service.

---

### INJ-01 (T+20 min)

**Inject delivered:**  
> "Nexus Security issues an urgent bulletin: their CI/CD build pipeline was breached by an APT group, resulting in a compromised, validly signed agent update (v4.2.1) pushed automatically 3 days ago. MedDefense's agent hosts across all three sites run v4.2.1. Nexus confirms the agent executes arbitrary C2 commands, but has no patch available. EDR now confirms all three site agents are actively beaconing."

**Participant responses:**
* **James Chen (SOC / IR Lead):** "Re-classifying incident to SEV-1 immediately. Applying perimeter firewall blocks on C2 IP 193.42.100.77 while preparing host isolation protocols across all three sites."
* **Sarah Park (IT Director):** "We must isolate all three agent hosts from the local network immediately to prevent potential internal lateral movement."
* **Robert Kim (Database Administrator):** "If we isolate those hosts, automated FHIR synchronization to Epic stops immediately across all campuses."
* **Marcus Webb (Third-Party Risk / Vendor Manager):** "Checking the Nexus security portal for official file hashes, but vendor support response is lagging."
* **Helena Reyes (Legal Counsel):** "Documenting that the breach stems from a compromised signed vendor update package."
* **Clinical Director representative:** "Taking Nexus offline without an immediate alternative halts automated appointment scheduling for 3,500 weekly patients!"

**Evaluation:**
* **Criterion 1 (re-classify to SEV-1):** PASS — Event re-classified to SEV-1 upon confirmation of multi-site supply chain compromise.
* **Criterion 2 (scope all three site hosts):** PASS — Identified all three agent hosts running v4.2.1 across campuses.
* **Criterion 3 (C2 firewall blocking / isolation preparation):** PASS — C2 IP blocked at perimeter firewalls immediately while host isolation strategy was initiated.

**Facilitator note:**  
*Probing question asked:* "Does the fact that v4.2.1 carries a valid cryptographic signature from Nexus make you hesitate to isolate the host binaries?"  
*Finding:* The team overcame signature trust immediately due to active EDR C2 beaconing alerts, but stalled on execution due to clinical friction.

---

### INJ-02 (T+40 min)

**Inject delivered:**  
> "Nexus Account Management is contacted. They admit they cannot confirm if customer patient databases or Epic integration credentials were compromised. Simultaneously, IR reveals the Nexus FHIR API service account holds excessive permissions in Epic, including direct write access to patient demographic and appointment tables."

**Participant responses:**
* **Marcus Webb (Third-Party Risk / Vendor Manager):** "Bypassing standard support ticketing and calling the Nexus CISO directly using emergency BAA contact paths."
* **James Chen (SOC / IR Lead):** "Direct write access to Epic is an unacceptable risk exposure. Requesting immediate revocation and rotation of all Nexus FHIR API tokens."
* **Robert Kim (Database Administrator):** "Revoking the Nexus FHIR API secret in Epic now. External API calls can no longer modify database tables."
* **Helena Reyes (Legal Counsel):** "Issuing a formal written demand to Nexus Legal for forensic attestation and breach scoping details under BAA Section 8.2."
* **Sarah Park (IT Director):** "Supporting API key revocation and enabling enhanced audit logging on all Epic service accounts."

**Evaluation:**
* **Criterion 1 (invoke emergency BAA communication):** PASS — Emergency CISO BAA contact path utilized; formal written demand issued by Legal.
* **Criterion 2 (audit Epic FHIR API permissions):** PASS — Excessive write permissions discovered and flagged immediately.
* **Criterion 3 (authorize token key rotation):** PASS — Database Administrator revoked API secrets and scheduled immediate token rotation.

**Facilitator note:**  
*Probing question asked:* "If Nexus cannot confirm blast radius, how do you verify if active Epic credentials were extracted from host memory?"  
*Finding:* The team recognized that unencrypted API keys residing in agent memory required immediate revocation in Epic regardless of vendor attestation.

---

### INJ-03 (T+60 min)

**Inject delivered:**  
> "Security recommends severing all network connections and shutting down Nexus agent hosts immediately to stop C2 traffic. The Clinical Director vehemently objects: disconnecting Nexus halts automated appointment processing for 3,500 weekly patients across 3 sites, leading to missed surgeries, lost diagnostic schedules, and severe patient safety risks."

**Participant responses:**
* **Clinical Director representative:** "I cannot accept a complete system shutdown right now. Disconnecting scheduling creates immediate patient care risks, double-bookings, and delayed procedures!"
* **Sarah Park (IT Director):** "Leaving active C2 agents running on our internal network leaves us exposed to ransomware deployment. We must isolate."
* **James Chen (SOC / IR Lead):** "We can isolate host network interfaces while enabling manual white-glove downtime procedures for clinic staff."
* **Dr. Patricia Morales (CEO / Executive Sponsor):** "As CEO, I authorize full network isolation of the three Nexus hosts. Clinical Director, activate manual paper-based scheduling downtime protocols immediately."
* **Helena Reyes (Legal Counsel):** "Decision and clinical risk trade-off formally documented under CEO authority."

**Evaluation:**
* **Criterion 1 (structured risk discussion):** PASS — Formal debate between IT/Security and Clinical Director held with documented trade-offs.
* **Criterion 2 (executive decision maker balancing safety):** PASS — CEO formally exercised override authority to disconnect systems while ordering downtime protocols.
* **Criterion 3 (manual downtime activation):** PASS — Clinical downtime manual scheduling protocol activated concurrently with agent isolation.

**Facilitator note:**  
*Probing question asked:* "Who holds ultimate legal and operational liability if a patient suffers harm due to canceled procedures versus data loss?"  
*Finding:* Highlighted a lack of pre-defined clinical thresholds for emergency IT system disconnects, requiring executive intervention.

---

### INJ-04 (T+80 min)

**Inject delivered:**  
> "Forensic triage of the Nexus database staging directory shows an unencrypted CSV export file containing 12,000 patient records (names, DOBs, SSNs, insurance details, clinical notes) created 24 hours ago. Firewall logs reveal a 1.2 GB outbound transfer from the West Campus agent host during the same timeframe."

**Participant responses:**
* **James Chen (SOC / IR Lead):** "Forensic confirmation of exfiltration: 1.2 GB outbound transfer matches the staging CSV directory size. Handing exact file manifests to Legal and Privacy."
* **Helena Reyes (Legal Counsel):** "This constitutes a confirmed HIPAA breach involving 12,000 PHI records. MedDefense's direct 60-day HHS OCR breach notification clock starts today."
* **Privacy Officer / Data Protection Lead:** "Standing up PHI scoping team to analyze the 12,000 records, map impact across campuses, and prepare breach notifications."
* **Dr. Patricia Morales (CEO / Executive Sponsor):** "Do we wait for Nexus to report this to HHS, or do we report independently?"
* **Helena Reyes (Legal Counsel):** "We do not wait for Nexus. As the Covered Entity, MedDefense holds independent regulatory reporting liability. We prepare OCR and patient notifications immediately."

**Evaluation:**
* **Criterion 1 (PHI scoping team formed):** PASS — Scoping team assigned to analyze 12,000 exfiltrated records and outbound transfer logs.
* **Criterion 2 (independent HIPAA risk assessment):** PASS — Legal counsel declared breach and initiated direct regulatory workflow without waiting for vendor.
* **Criterion 3 (60-day clock recognized):** PASS — Direct 60-day HIPAA Breach Notification Rule clock explicitly acknowledged and documented.

**Facilitator note:**  
*Probing question asked:* "Does Nexus's status as a Business Associate shield MedDefense from OCR fines if notification is delayed?"  
*Finding:* Legal counsel correctly asserted that Covered Entities maintain direct liability for timely notification regardless of BA delays.

---

### INJ-05 (T+100 min)

**Inject delivered:**  
> "A clinic nurse at the South Campus reports that three patient appointment times for today's oncology infusions were silently modified in Epic, causing double-bookings and a missed chemotherapy appointment. Forensics confirms the modifications originated from the compromised Nexus FHIR API service account 12 hours ago."

**Participant responses:**
* **Clinical Director representative:** "This is a patient safety emergency! Chemotherapy schedules are corrupted. We must stop relying on any scheduling data modified in the last 24 hours."
* **Robert Kim (Database Administrator):** "Initiating an immediate point-in-time database audit comparing current Epic scheduling tables against yesterday's pre-compromise backup baseline."
* **James Chen (SOC / IR Lead):** "FHIR API write permissions were revoked in INJ-02, preventing further external modifications. We are isolating affected records."
* **Sarah Park (IT Director):** "Deploying database integrity scripts to flag all modifications made by the Nexus API service account over the last 3 days."
* **Clinical Director representative:** "Mandating 100% verbal confirmation with patients and clinical charts before administering infusion therapy today."

**Evaluation:**
* **Criterion 1 (FHIR API write revocation confirmed):** PASS — API write tokens were revoked; confirmation provided to clinical staff.
* **Criterion 2 (point-in-time backup audit initiated):** PASS — Database Administrator initiated comparison between current tables and pre-compromise backups.
* **Criterion 3 (clinical verification protocols enacted):** PASS — Verbal verification protocol mandated for high-risk clinical appointments (oncology/surgeries).

**Facilitator note:**  
*Probing question asked:* "How do you distinguish between legitimate scheduling updates by staff and malicious edits by the C2 backdoor?"  
*Finding:* DB Administrator realized audit logs lacked detailed session attribution for service account actions, forcing a full manual audit.

---

### INJ-06 (T+120 min)

**Inject delivered:**  
> "A local investigative reporter contacts MedDefense PR, stating a source revealed patient data was stolen from MedDefense via a third-party vendor breach, and patient appointments are being canceled. The reporter gives a 30-minute deadline before publishing."

**Participant responses:**
* **Communications Director:** "Drafting a holding statement immediately: acknowledging an IT security incident involving a third-party vendor, emphasizing patient safety and care continuity."
* **Helena Reyes (Legal Counsel):** "Reviewing draft. Statement must NOT mention Nexus by name yet, nor confirm specific exfiltration numbers (12,000) until forensic verification is finalized."
* **Dr. Patricia Morales (CEO / Executive Sponsor):** "Approving the vetted holding statement. Communications Director, issue this to the reporter before the 30-minute deadline."
* **Communications Director:** "Sending statement to reporter and issuing internal broadcast message to all clinical staff with guidance on media inquiries."

**Evaluation:**
* **Criterion 1 (pre-approved holding statement released in time):** PASS — Statement drafted, legally vetted, and released within 22 minutes.
* **Criterion 2 (maintain operational transparency without unverified facts):** PASS — Statement acknowledged third-party event and patient safety without leaking vendor name or unconfirmed stats.
* **Criterion 3 (internal staff alignment):** PASS — Internal staff memo broadcasted to prevent unauthorized employee leaks to media.

**Facilitator note:**  
*Probing question asked:* "If the reporter specifically asks whether 12,000 patient SSNs were posted on the dark web, how does PR respond?"  
*Finding:* PR successfully adhered to "investigation ongoing" protocol without confirming or denying unverified leak metrics.

---

### INJ-07 (T+
