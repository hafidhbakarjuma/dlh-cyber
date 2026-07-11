# MedDefense Health Systems — The Criticality Assessment

**Prepared by:** Junior Security Analyst
**Prepared for:** James Chen, Deputy CISO
**Source:** Asset Registry (Task 7), consolidated across all prior project deliverables

---

## Asset Criticality Matrix

| Asset Category | Confidentiality | Integrity | Availability | Overall Criticality | Justification |
|---|---|---|---|---|---|
| EHR System | Critical | Critical | Critical | **Critical** | Primary clinical record for both sites; already caused a 9-hour paper fallback (Task 1). |
| PACS / Imaging | High | Critical | Critical | **Critical** | Zero backup coverage (Task 7) — loss is unrecoverable, not just delayed. |
| Billing Infrastructure | High | High | High | **High** | Compromised twice already (Task 1, 2); disrupts revenue, not patient care directly. |
| Identity / AD | High | Critical | Critical | **Critical** | Authentication root for nearly every other system; ad-dc-02 has no backup. |
| Network Core | High | Critical | Critical | **Critical** | No segmentation exists — compromise here reaches every other asset at once. |
| Medical IoT | Medium | Critical | Critical | **Critical** | Only category where compromise causes direct physical harm to a patient. |
| Backup & Storage | Medium | High | Critical | **Critical** | Co-located with production, untested DR — a single event destroys both (Task 5). |
| Clinical Endpoints | Medium | Medium | Low | **Medium** | Large attack surface, likely entry point, but individually replaceable. |
| Admin Endpoints (HQ) | Medium | Low | Low | **Medium** | Sensitive but non-clinical data; lower regulatory/safety weight. |
| Physical Security | High | High | High | **High** | Server room and network closet are unrestricted (Task 3) — bypasses all technical controls. |
| Patient-Facing Web Apps | Critical | High | Medium | **Critical** | Only category with a *confirmed, already-exploited* breach (Incident B, IDOR) — this happened, it isn't a projection. Public internet exposure means the largest, least controlled population has access to it. |
| Shadow IT / Undocumented | Critical | Critical | Medium | **Critical** | Unidentified device (UNKNOWN-01) sits on the same subnet as the domain controllers and EHR database with no owner and no known function — unverifiable risk on the most sensitive segment in the environment. |

---

## Top 5 Most Critical Assets

1. **Infusion Pumps** — Compromise = real-time physical harm to a patient; known CVE, vendor-recommended isolation never done.
2. **EHR System** — Already caused a real 9-hour outage forcing paper records hospital-wide (Task 1).
3. **Domain Controllers** — Root of authentication trust; ad-dc-02 has no backup, so recovery isn't guaranteed.
4. **PACS Server** — The only clinical system with zero backup — loss is permanent, not recoverable.
5. **billing-srv-01** — Only asset with a documented history of repeated real compromise (ransomware + cryptominer).

### Note on Ranking Methodology

This Top 5 ranks by **demonstrated impact** — every entry has either already caused real harm/disruption or has a vendor-confirmed, unmitigated vulnerability. The closest asset left off the list is **UNKNOWN-01**, the undocumented device on the server subnet. It was excluded here because its risk is *unverified* rather than *demonstrated* — it may be entirely benign. If MedDefense's risk appetite favors worst-case precaution over evidence-based ranking, UNKNOWN-01 would displace billing-srv-01 at #5, since an unknown active presence next to the domain controllers arguably represents higher uncertainty than a known, already-diagnosed, already-being-remediated billing server compromise. Both rankings are defensible; this version prioritizes what MedDefense can prove over what it can only suspect.
