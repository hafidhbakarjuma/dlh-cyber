# Containment Execution Record: IR-2026-0420-01

## Execution Log

| UTC Timestamp | Actor | Action | Expected Outcome | Observed Outcome | Deviation Notes |
|---------------|-------|--------|------------------|------------------|-----------------|
| 2026-04-20T20:12Z | On-Call IR Analyst | Issue EDR network containment command for `WS-101`. | Host isolated from internal and external network; C2 severed; RAM preserved. | Host successfully isolated; heartbeat terminated. | None. |
| 2026-04-20T20:14Z | On-Call IR Analyst | Issue EDR network containment command for `WS-104`. | Host isolated from network; active beacon severed. | Host successfully isolated. | None. |
| 2026-04-20T20:15Z | On-Call IR Analyst | Issue EDR network containment command for `WS-107`. | Host isolated from network; active beacon severed. | Host successfully isolated. | None. |
| 2026-04-20T20:16Z | On-Call IR Analyst | Issue EDR network containment command for `WS-112`. | Host isolated from network; lateral movement path blocked. | Host successfully isolated. | None. |
| 2026-04-20T20:18Z | Network Admin | Apply perimeter firewall egress rule blocking C2 domain/IP (`*.ms-cdn-edge[.]com` / squatted CDN). | Outbound C2 traffic dropped at perimeter. | Egress traffic blocked; connection resets logged. | None. |
| 2026-04-20T20:22Z | Identity Admin | Revoke active Kerberos tickets and reset passwords for all accounts accessed during the 72-hour dwell period. | Active sessions terminated; lateral movement credentials invalidated. | All targeted user and service accounts reset successfully. | None. |
| 2026-04-20T20:25Z | On-Call IR Analyst | Verify C2 severance via proxy and firewall telemetry logs. | Zero outbound connections to C2 infrastructure across all endpoints. | Telemetry confirms all beacon traffic dropped and endpoints silenced. | None. |
| 2026-04-20T20:28Z | On-Call IR Analyst | Restrict `FILE-SVR-01` network access to authorized clinical applications only, disabling SMB access from non-essential subnets. | File server protected from further unauthorized browsing while maintaining clinical workflows. | Access restricted successfully; clinical systems verified operational. | None. |
