# Intelligence Intake Summary: HEALTHBANE Campaign

## Source Breakdown

### 1. HC3 Advisory

| Field | Value |
|---|---|
| **Source Name** | `HC3_Advisory_HEALTHBANE_TLP_CLEAR.txt` |
| **Source Type** | Government advisory |
| **Date Published** | 2026-04-14 |
| **TLP Classification** | TLP:CLEAR |
| **Number of Indicators Provided** | 23 |
| **Types of Indicators** | Domains, IPs, hashes, URLs, email addresses |
| **One-line Summary** | Health Sector Cybersecurity Coordination Center (HC3) advisory detailing threat actor tactics, indicators of compromise, and mitigation strategies associated with the HEALTHBANE campaign targeting healthcare entities. |
| **Key Limitations or Caveats** | Strategic guidance advisory based on early reporting; relies heavily on telemetry shared by partner agencies and may not capture upcoming infrastructural shifts. |

### 2. Commercial Threat Feed

| Field | Value |
|---|---|
| **Source Name** | `commercial_feed_extract.json` |
| **Source Type** | Commercial feed |
| **Date Published** | 2026-04-14 |
| **TLP Classification** | TLP:CLEAR (Assumed standard commercial dissemination) |
| **Number of Indicators Provided** | 41 |
| **Types of Indicators** | Domains, IPs, URLs |
| **One-line Summary** | Automated threat intelligence feed collection containing infrastructure markers, suspected C2 domains, and phishing landing URLs associated with HEALTHBANE activity. |
| **Key Limitations or Caveats** | High volume of indicators susceptible to false positives, infrastructure aging, and parked or squatted domains mixed with malicious infrastructure. |

### 3. Researcher Blog Analysis

| Field | Value |
|---|---|
| **Source Name** | `researcher_blog_analysis.txt` |
| **Source Type** | Open-source research |
| **Date Published** | 2026-04-15 |
| **TLP Classification** | TLP:CLEAR |
| **Number of Indicators Provided** | 14 |
| **Types of Indicators** | Domains, IPs, hashes, URLs |
| **One-line Summary** | Independent security researcher breakdown of the initial infection vector, lure mechanics, and staging infrastructure used in recent healthcare-targeted campaigns. |
| **Key Limitations or Caveats** | Analysis based on limited public samples; attribution and scoping are preliminary and subject to independent validation. |

### 4. MedDefense Internal Investigation

| Field | Value |
|---|---|
| **Source Name** | `meddefens_4x00_findings.txt` |
| **Source Type** | Internal investigation |
| **Date Published** | 2026-04-14 |
| **TLP Classification** | TLP:AMBER (Internal organizational view) |
| **Number of Indicators Provided** | 11 |
| **Types of Indicators** | Domains, IPs, hashes, URLs, email addresses |
| **One-line Summary** | Internal incident response findings detailing the concrete impact, compromised endpoints, lateral movement, and telemetry gathered during the active breach. |
| **Key Limitations or Caveats** | Scope is limited strictly to internal visibility, telemetry retention limits, and localized network segments observed during the incident. |

## Consolidated View & Deduplication Metrics

| Metric | Value |
|---|---|
| Total raw indicators across all sources | 89 |
| Total unique indicators after deduplication | 64 |
| Indicators that appear in multiple sources | 25 |
| Indicators that appear in only one source | 39 |

## Source Conflicts & Discrepancies

- **Attribution Labels:** Varying nomenclature used across government reporting vs. open-source blogs regarding the exact threat actor cluster identifier.
- **Confidence Differences:** Commercial feeds present high-frequency indicators with varying confidence ratings, whereas government advisories and internal findings carry higher validation confidence.
- **Commercial-Feed Noise:** Ingestion of broad infrastructure blocks containing shared hosting or repurposed domains that require filtering to remove benign or low-fidelity artifacts.
- **Isolated Indicators:** Several endpoint hashes and internal phishing tokens appear exclusively within the MedDefense internal investigation without corroboration in external feeds.
