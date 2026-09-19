# Click Investigation — Diane Marsh / WS-NURSE-04

**Analyst:** SOC Team  
**Date:** 2026-04-17  
**Scope:** Forensic impact assessment and recommended investigative/containment workflow for Diane Marsh following her interaction with Email 2.

---

## Click Investigation — Diane Marsh / WS-NURSE-04

### Confirmed Facts
- **Target User:** Diane Marsh (`dmarsh@meddefense.com`)
- **Workstation:** `WS-NURSE-04` (IP: `10.10.2.15`)
- **Phishing Email:** Email 2 (`noreply@meddefense-portal.com`)
- **Malicious URL/Domain:** `https://meddefense-portal[.]com/verify/staff?id=dmarsh&token=a8f3e2d1` (`91.234.99.107`)
- **Click Timestamp:** 2026-04-14 15:02:33 CDT (approx. 36 hours prior to collection window baseline)
- **Email Context:** Unauthenticated phishing message demanding urgent portal re-verification within 24 hours under threat of access suspension.

### Key Unknowns
- Whether Diane Marsh entered her credentials or authentication tokens into the lookalike portal page.
- Whether any secondary payloads (such as malicious scripts or session cookies) were downloaded or executed on `WS-NURSE-04`.
- Whether the attacker successfully leveraged harvested credentials against external or internal gateways during the 36-hour post-click window.

### Endpoint Checks To Perform
*Note: Because this is an independent offline lab, the following checks represent required forensic actions if endpoint logs or physical access become available:*
- **Browser History & Cache:** Review Chrome/Edge history on `WS-NURSE-04` around 2026-04-14 15:02 CDT to verify interaction with `meddefense-portal.com` and inspect input fields.
- **Downloaded Files:** Search user profile download directories for unexpected HTML files, scripts, or binaries dropped during the session.
- **Process Execution Artifacts:** Check process creation telemetry for anomalous execution of `powershell.exe`, `cmd.exe`, or unverified executables spawned around the click timestamp.
- **Session & Cookie Storage:** Inspect browser session stores or credential manager entries for unauthorized token caching or autofill usage.

### Account Checks To Perform
*Note: Recommended identity and directory auditing steps:*
- **Authentication Logs:** Query Active Directory and Azure AD/M365 sign-in logs for successful or failed authentications originating from unusual external IP addresses or ASNs (specifically targeting `91.234.99.107` or related hosting ranges) for `dmarsh`.
- **MFA Activity:** Review multi-factor authentication prompt logs for unexpected pushes, SMS codes, or hardware token validations during or immediately after the click window.
- **Account Modifications:** Check for recent password changes, recovery phone/email updates, or newly registered MFA devices.
- **Inbox Rules & Delegation:** Inspect Exchange/M365 mailbox settings for hidden forwarding rules, auto-delete rules, or delegate permissions that attackers commonly establish for persistence and data exfiltration.

### Decision Matrix

| Outcome Level | Criteria | Required Action |
|---|---|---|
| **No Compromise Found** | User navigated to URL but immediately closed page without typing credentials; endpoint telemetry clean; authentication logs show zero anomalies. | Document incident, close ticket, deliver targeted awareness refresher. |
| **Possible Credential Exposure** | User typed credentials into the phishing portal, but attacker has not yet successfully authenticated or MFA blocked secondary access. | Immediate password reset, forced session revocation, proactive monitoring. |
| **Confirmed Compromise** | Successful external sign-in detected using harvested credentials, unauthorized inbox rules created, or malicious workstation execution verified. | Isolate workstation `WS-NURSE-04`, execute full incident response playbooks, initiate enterprise credential rotation. |

### Recommended Containment
- **Immediate Password Reset:** Force an immediate corporate password reset for Diane Marsh.
- **Session Revocation:** Terminate all active Azure AD / M365 and local session tokens to invalidate any cached or stolen session cookies.
- **User Interview:** Conduct a direct interview with Diane Marsh to ascertain exact details of the interaction (e.g., whether credentials or MFA prompts were completed).
- **Enhanced Monitoring:** Place `dmarsh@meddefense.com` and `WS-NURSE-04` on heightened monitoring for anomalous inbound/outbound traffic and sign-in spikes over the next 72 hours.

### Conclusion
Although direct endpoint telemetry is restricted in this offline batch, the confirmed click on a high-urgency lookalike credential harvesting domain (`meddefense-portal.com`) creates a substantial risk of credential exposure. Treating this event as a **Possible Credential Exposure** (or higher) and executing immediate containment measures is vital to preventing lateral movement or unauthorized data access.
