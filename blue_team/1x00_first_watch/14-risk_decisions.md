# MedDefense

# Risk Treatment Decisions

---

# Executive Summary

Following the updated gap analysis and validation against real-world healthcare breaches, MedDefense must prioritize remediation efforts within a limited annual security budget of **$120,000**.

The selected treatment strategies focus on reducing the highest operational and patient safety risks while maximizing security improvements per dollar spent.

---

# Risk Treatment Decisions

---

# 1. GAP-001 — Infusion Pumps Lack Security Controls

**Risk Level:** Critical

## Treatment Strategy

**Mitigate**

### Justification

Infusion pumps directly affect patient safety. Eliminating or accepting this risk is not feasible. Implementing network isolation and access controls significantly reduces the likelihood of device compromise.

### Proposed Controls

| Control | Category | Function |
|----------|----------|----------|
| Medical device network segmentation | Technical | Preventive |
| Network Access Control (NAC) | Technical | Preventive |
| Device monitoring | Technical | Detective |

### Estimated Cost

**$25,000**

### Implementation Effort

**Long-term (>1 month)**

### Expected Risk Reduction

High.

Segmentation prevents attackers from reaching medical devices even after other systems are compromised.

### Trade-offs

Requires coordination with biomedical engineering and may temporarily disrupt device connectivity during deployment.

---

# 2. GAP-010 — Backup Infrastructure Lacks Off-site Protection

**Risk Level:** Critical

## Treatment Strategy

**Mitigate**

### Justification

Recent ransomware attacks demonstrate that online backups alone are insufficient. Immutable off-site backups dramatically improve recovery capability.

### Proposed Controls

| Control | Category | Function |
|----------|----------|----------|
| Immutable off-site backups | Technical | Corrective |
| Quarterly recovery testing | Administrative | Detective |

### Estimated Cost

**$20,000**

### Implementation Effort

**Short-term (<1 month)**

### Expected Risk Reduction

Very High.

Allows rapid recovery after ransomware without paying attackers.

### Trade-offs

Ongoing cloud storage and testing costs.

---

# 3. GAP-015 — Missing Multi-Factor Authentication

**Risk Level:** Critical

## Treatment Strategy

**Mitigate**

### Justification

Credential theft remains one of the most common healthcare attack vectors. MFA provides immediate protection with relatively low implementation cost.

### Proposed Controls

| Control | Category | Function |
|----------|----------|----------|
| MFA for VPN | Technical | Preventive |
| MFA for privileged accounts | Technical | Preventive |

### Estimated Cost

**$10,000**

### Implementation Effort

**Short-term (<1 month)**

### Expected Risk Reduction

Very High.

Prevents unauthorized access even when passwords are compromised.

### Trade-offs

Minor user inconvenience and additional support during rollout.

---

# 4. GAP-012 — Flat Internal Network

**Risk Level:** Critical

## Treatment Strategy

**Mitigate**

### Justification

Network segmentation consistently appears in real-world healthcare incidents as the most effective containment strategy.

### Proposed Controls

| Control | Category | Function |
|----------|----------|----------|
| VLAN segmentation | Technical | Preventive |
| Internal firewall rules | Technical | Preventive |
| Access control lists | Technical | Preventive |

### Estimated Cost

**$30,000**

### Implementation Effort

**Long-term (>1 month)**

### Expected Risk Reduction

Very High.

Greatly limits lateral movement after initial compromise.

### Trade-offs

Complex implementation requiring network redesign.

---

# 5. GAP-011 — Weak Patch Management

**Risk Level:** Critical

## Treatment Strategy

**Mitigate**

### Justification

Every reviewed healthcare breach exploited known vulnerabilities with available patches.

### Proposed Controls

| Control | Category | Function |
|----------|----------|----------|
| Centralized patch management | Technical | Preventive |
| Monthly vulnerability scanning | Technical | Detective |
| Patch policy | Administrative | Preventive |

### Estimated Cost

**$12,000**

### Implementation Effort

**Short-term (<1 month)**

### Expected Risk Reduction

High.

Eliminates many publicly known attack vectors.

### Trade-offs

Scheduled maintenance windows may briefly interrupt services.

---

# 6. GAP-013 — No Incident Response Plan

**Risk Level:** High

## Treatment Strategy

**Mitigate**

### Justification

Organizations without tested response plans experience significantly longer outages and higher recovery costs.

### Proposed Controls

| Control | Category | Function |
|----------|----------|----------|
| Incident Response Plan | Administrative | Corrective |
| Tabletop exercises | Administrative | Detective |

### Estimated Cost

**$8,000**

### Implementation Effort

**Short-term (<1 month)**

### Expected Risk Reduction

Medium to High.

Improves response speed and minimizes business disruption.

### Trade-offs

Requires regular staff participation and periodic updates.

---

# 7. GAP-009 — Orphaned Raspberry Pi on Network

**Risk Level:** Critical

## Treatment Strategy

**Avoid**

### Justification

The device serves no approved business purpose. Removing it completely eliminates the associated risk at virtually no cost.

### Avoidance Action

- Remove unauthorized device
- Investigate ownership
- Block unauthorized hardware through NAC

### Business Impact

No significant operational impact.

### Trade-offs

Potentially removes an undocumented device that someone was using, requiring communication with IT staff.

---

# Budget Summary

| Gap | Estimated Cost |
|------|---------------:|
| GAP-001 | $25,000 |
| GAP-010 | $20,000 |
| GAP-015 | $10,000 |
| GAP-012 | $30,000 |
| GAP-011 | $12,000 |
| GAP-013 | $8,000 |
| GAP-009 | $0 |

| **Total Planned Investment** | **$105,000** |

---

# Remaining Budget

| Available Budget | $120,000 |
|------------------|----------:|
| Planned Spending | $105,000 |
| Remaining Budget | **$15,000** |

The remaining **$15,000** should be reserved for:

- Emergency incident response
- Security awareness training improvements
- Additional vulnerability assessments
- Contingency costs during implementation

---

# Deferred Items

The following improvements should be scheduled for the next fiscal year if additional funding becomes available:

| Gap | Reason for Deferral |
|------|---------------------|
| GAP-016 – Data Loss Prevention | High implementation cost and lower immediate risk than MFA and segmentation. |
| GAP-017 – Default Credentials on Medical Devices | Can be addressed after network segmentation reduces exposure. |
| GAP-018 – DMZ Firewall Redesign | Best implemented alongside a larger network modernization project. |
| GAP-019 – Medical Device Firmware Management | Dependent on vendor support and long-term biomedical engineering planning. |

---

# Overall Recommendation

The proposed investment plan addresses the most critical attack paths observed in both the MedDefense assessment and recent healthcare breaches. By focusing on **network segmentation, medical device security, backup resilience, patch management, Multi-Factor Authentication, and incident response**, MedDefense can significantly reduce the likelihood and impact of ransomware, insider threats, and medical device compromises while remaining within the allocated **$120,000 annual security budget**.

---
