# MedDefense Health Systems
## The CVSS Deconstruction

### Objective

The Common Vulnerability Scoring System (CVSS) v3.1 provides a standardized method for measuring the severity of security vulnerabilities. Understanding how each metric contributes to the final score allows security analysts to prioritize vulnerabilities based on actual risk rather than relying only on the numerical score.

The NIST CVSS v3.1 Calculator was used throughout this exercise to analyze, construct, and compare vulnerability scores, cross-checked against the official FIRST.org CVSS v3.1 base-score formula.

**NIST Calculator:** https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator
**FIRST v3.1 Specification (equations):** https://www.first.org/cvss/v3.1/specification-document

---

## Exercise 1 – CVSS Deconstruction

**Vulnerability:** Finding 001 — CVE-2021-44790

**Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

**Base Score:** 9.8 (Critical)

### Metric Breakdown

**AV — Attack Vector**
- Selected Value: **N = Network**
- Meaning: The vulnerability can be exploited remotely over the network without physical or local access.
- Other Values: A = Adjacent Network (slightly lower), L = Local (lower), P = Physical (lowest)
- Why Network? Apache HTTP Server accepts HTTP requests over TCP port 80/443, allowing an attacker anywhere on the network — or the internet — to reach the vulnerable multipart parser.

**AC — Attack Complexity**
- Selected Value: **L = Low**
- Meaning: No special conditions are required; the attacker only needs to send a specially crafted HTTP request.
- Other Values: H = High
- Why Low? No race conditions, timing attacks, or unusual configurations are required to trigger the buffer overflow.

**PR — Privileges Required**
- Selected Value: **N = None**
- Meaning: No authentication is required before exploitation.
- Other Values: L = Low, H = High
- Why None? Any remote, unauthenticated attacker can send the malicious request directly.

**UI — User Interaction**
- Selected Value: **N = None**
- Meaning: No legitimate user needs to perform any action.
- Other Values: R = Required
- Why None? The exploit fires automatically once the malicious request reaches the server — no victim click or action is needed.

**S — Scope**
- Selected Value: **U = Unchanged**
- Meaning: The exploited vulnerability only affects resources managed by the same security authority (the Apache server itself).
- Other Values: C = Changed
- Why Unchanged? The vulnerability compromises the web server process itself rather than escalating into a separate security domain.

**C — Confidentiality**
- Selected Value: **H = High**
- Meaning: Attackers can access all confidential data on the affected component.
- Why High? Remote code execution allows attackers to read application files, credentials, and sensitive data.

**I — Integrity**
- Selected Value: **H = High**
- Meaning: Attackers can completely modify system files and application data.
- Why High? Arbitrary code execution lets an attacker alter server-side data at will.

**A — Availability**
- Selected Value: **H = High**
- Meaning: Attackers can fully disrupt services.
- Why High? Remote code execution could crash or completely take over the web server process.

### What Happens if Attack Vector Changes?

| Vector | Score |
|---|---:|
| Original — `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | 9.8 |
| Modified — `AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | 8.4 |

**Why does the score change?**
The Attack Vector constant drops from 0.85 (Network) to 0.55 (Local), which lowers the Exploitability sub-score from ~3.89 to ~2.51 while the Impact sub-score (5.89, driven entirely by the C/I/A metrics) stays fixed. Because an attacker would now need local access to the target machine before exploiting the vulnerability, the pool of potential attackers shrinks dramatically — that's reflected numerically as well as practically: the score drops a full severity consideration but stays Critical (8.4 still falls in the 7.0–8.9 "High" band's upper edge... more precisely, 8.4 is High, one full band below the original Critical 9.8).

---

## Exercise 2 – CVSS Construction

### Given Characteristics
- Exploitable only from the local network (adjacent segment)
- Complex exploitation
- Low privileges required
- No user interaction
- Scope unchanged
- High confidentiality impact
- No integrity impact
- No availability impact

### Manual CVSS Vector

`CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N`

### Calculated Result (verified against the FIRST v3.1 base-score formula)

| Component | Value |
|---|---|
| Exploitability sub-score | 1.182 |
| Impact sub-score | 3.595 |
| **Base Score** | **4.8** |
| **Severity** | **Medium** |

**Calculation walk-through:**
- ISC-Base = 1 − [(1 − 0.56) × (1 − 0) × (1 − 0)] = 0.56
- Impact = 6.42 × 0.56 = 3.595
- Exploitability = 8.22 × AV(0.62) × AC(0.44) × PR(0.62) × UI(0.85) = 1.182
- Base Score = Roundup(Impact + Exploitability) = Roundup(4.777) = **4.8**

> **Note on a prior draft:** an earlier version of this write-up reported this vector as 4.9. Re-running the official FIRST v3.1 equations (and cross-checking against the NIST calculator) confirms the correct base score is **4.8**, which still falls solidly within the Medium band (4.0–6.9), so the severity rating itself doesn't change — only the exact score does.

**Why Medium?**
The vulnerability:
- cannot be exploited from across the internet — it requires adjacent network access
- requires low-level authenticated access before exploitation
- requires difficult, non-trivial attack conditions (AC:H)
- only exposes confidential information — no data tampering or service disruption is possible

Each of these restrictions independently pulls the score down from what a Network/Low-complexity/No-privilege vulnerability with the same impact profile would score (which would land in the 7.5–8.1 range), landing this finding solidly in the Medium band instead.

---

## Exercise 3 – CVSS Comparison

### Finding A

**Finding 001 — Apache mod_lua Buffer Overflow (CVE-2021-44790)**

`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

**Score:** 9.8 (Critical)

### Finding B

**Finding 015 — Deprecated TLS Cipher Suite Enables Session Interception**

A network-facing service on the MedDefense patient portal was found to still negotiate a legacy, weak cipher suite. Exploiting this requires an attacker to actively force a cipher downgrade or perform a man-in-the-middle position on the network path (a non-trivial, multi-step attack condition), after which the encrypted session traffic — including authentication tokens and patient data in transit — can be decrypted. The weakness only exposes confidentiality; it does not let an attacker modify traffic or disrupt the service.

`CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N`

**Score:** 5.9 (Medium)

*(This replaces the BD Alaris infusion pump finding used in an earlier draft, whose real-world NVD score of 7.5 falls in the High band rather than the 5.0–7.0 Medium-to-High comparison range this exercise calls for.)*

### Side-by-Side Comparison

| Metric | Finding 001 | Finding 015 |
|---|---|---|
| Attack Vector | Network | Network |
| Attack Complexity | Low | **High** |
| Privileges Required | None | None |
| User Interaction | None | None |
| Scope | Unchanged | Unchanged |
| Confidentiality | High | High |
| Integrity | **High** | **None** |
| Availability | **High** | **None** |

### Key Differences

Attack Vector, Privileges Required, User Interaction, and Scope are identical between the two findings — both are remotely reachable, unauthenticated, and require no user action or scope change. The score gap comes from two places:

1. **Attack Complexity** — Finding 001 requires no special conditions (AC:L), while Finding 015 requires an attacker to actively achieve a cipher downgrade or MITM position first (AC:H). This alone pulls the Exploitability sub-score down.
2. **Impact breadth** — Finding 001 achieves complete compromise (Confidentiality, Integrity, *and* Availability all High) because it grants arbitrary code execution. Finding 015 only ever exposes confidentiality — an attacker can read session data but cannot modify it or take the service down.

Finding 001 allows attackers to steal sensitive data, modify system data, and disrupt services outright. Finding 015 allows only passive disclosure of intercepted session data, contingent on the attacker first achieving a privileged network position.

### Which Metrics Have the Greatest Impact?

The metrics that most significantly influence the final score, in rough order of leverage in this comparison, are:

1. **Confidentiality / Integrity / Availability (Impact metrics)** — going from one High impact to three High impacts is the single biggest driver of the gap between a Medium/High finding and a Critical one; each High impact adds roughly equally to the Impact sub-score once more than one is set to High.
2. **Attack Complexity (AC)** — moving from Low to High cuts the Exploitability sub-score by nearly half (constant drops from 0.77 to 0.44), which is exactly what separates Finding 001's 9.8 from a hypothetical AC:H version of the same vulnerability.
3. **Privileges Required (PR)** — vulnerabilities requiring no authentication score meaningfully higher than those requiring even Low privileges, though this metric didn't differ between the two findings compared here.
4. **Attack Vector (AV)** — Network-reachable findings score higher than Adjacent or Local findings (demonstrated directly in Exercise 1's AV:N → AV:L comparison, a 1.4-point drop).

While Scope and User Interaction also affect the score, in this dataset the combination of remote exploitation (AV:N), low complexity (AC:L), and full-spectrum impact (C:H/I:H/A:H) is specifically what pushes a finding into the Critical (9.0–10.0) band — remove any one of those three conditions and the score drops by a full severity band or more.

---

## Conclusion

This exercise demonstrates that a CVSS score is more than a single number — it is a structured representation of exploitability and impact. By deconstructing an existing vector, constructing a new one from defined characteristics, and comparing two different vulnerabilities metric-by-metric, it becomes clear how individual metrics influence the final severity rating. It also reinforced a practical lesson: base scores should be verified against the official FIRST v3.1 formula (or the NIST calculator) rather than estimated, since even a 0.1-point manual error (4.9 vs. the correct 4.8) can go unnoticed without recalculating from the underlying Impact and Exploitability sub-scores. Security analysts use this understanding to prioritize remediation efforts, evaluate business risk, and make informed vulnerability management decisions.
