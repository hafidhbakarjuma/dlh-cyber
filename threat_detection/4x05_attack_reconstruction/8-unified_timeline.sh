#!/bin/bash
# ==============================================================================
# Script Name: 8-unified_timeline.sh
# Description: Unified Attack Timeline & Temporal Metrics for HEALTHBANE 4x05
# Author: Security Operations Team / MedDefense Health Systems
# ==============================================================================

set -euo pipefail

echo "================================================================"
echo "   UNIFIED ATTACK TIMELINE - HEALTHBANE vs MedDefense"
echo "   Period: 2024-02-01 (Phishing) to 2024-02-12 (Containment)"
echo "================================================================"
echo ""

echo "CHRONOLOGICAL SEQUENCE:"
echo ""
echo "  #  Timestamp            Event                    ATT&CK     Conf   Sources"
echo "  -- --------             -----                    ------     ----   -------"
echo "  01 2024-02-01T08:14:22Z Phishing emails sent     T1566.001  CONF   4x00"
echo "  02 2024-02-01T09:22:15Z Diane clicks link        T1566.001  CONF   4x00"
echo "  03 2024-02-01T09:23:40Z Credentials submitted    T1078      CONV   4x00,4x01"
echo "  04 2024-02-01T10:55:12Z First C2 beacon          T1071.001  CONV   4x01,IR-FW"
echo "  05 2024-02-01T11:00:00Z C2 channel stable        T1573.001  CONF   4x01"
echo "  06 2024-02-04T01:23:00Z Credential dump (LSASS)  T1003.001  CONV   4x04,IR-MEM"
echo "  07 2024-02-05T02:14:00Z Lateral move to DB       T1021.002  CONV   4x04,IR-FW"
echo "  08 2024-02-06T01:47:33Z Scheduled task created   T1053.005  CONV   IR-MEM,IR-DISK"
echo "  09 2024-02-06T02:12:00Z Secondary C2 active      T1071.001  PROB   IR-FW"
echo "  10 2024-02-08T02:55:00Z Lateral move to APP-02   T1021.006  PROB   4x04,IR-FW"
echo "  11 2024-02-08T03:00:00Z Event log clear (12m gap)  T1070.001  PROB   IR-DISK"
echo "  12 2024-02-09T23:41:00Z Staging tool execution   T1074.001  CONF   IR-DISK"
echo "  13 2024-02-10T14:22:00Z DB query results exported  T1005      CONF   IR-DISK"
echo "  14 2024-02-10T15:07:00Z First staging archive    T1560.001  CONF   IR-DISK"
echo "  15 2024-02-11T01:08:00Z Second staging archive   T1560.001  CONF   IR-DISK"
echo "  16 2024-02-12T01:44:00Z Last PsExec activity     T1021.002  CONF   4x04"
echo "  17 2024-02-12T09:30:00Z Hunt detection (4x04)    ---        CONF   4x04"
echo "  18 2024-02-12T11:15:00Z IR isolation of host     ---        CONF   IR"
echo ""
echo "  Total events in timeline: 18"
echo "  Events with CONVERGED evidence: 13 (72.2%)"
echo "  Events with SINGLE-SOURCE evidence: 5 (27.8%)"
echo ""

echo "TEMPORAL METRICS:"
echo "  Total dwell time:           11 days (Feb 01 phishing to Feb 12 isolation)"
echo "  Breakout time:              76 hours (Initial access Feb 01 to first lateral move Feb 05)"
echo "  Time to persistence:        5 days (Access to scheduled task on Feb 06)"
echo "  Time to data staging:       9 days (Access to first staging file on Feb 10)"
echo "  Detection to containment:   1.75 hours (Hunt detection at 09:30 to IR isolation at 11:15)"
echo "  Operational tempo:          Activity heavily clusters during off-hours (01:00 - 04:00 UTC)"
echo ""

echo "TIMELINE GAPS:"
echo "  GAP 1: Feb 01 11:00 to Feb 04 01:23 -- Dormant period with no internal endpoint telemetry."
echo "         Assessment: Attacker maintained dormant C2 beaconing while waiting for credentials/timing."
echo "  GAP 2: Feb 06 02:12 to Feb 08 02:55 -- Limited internal log visibility between lateral pivots."
echo "         Assessment: Collection limitation in SIEM pre-Feb 14."
echo ""

echo "SEQUENCING UNCERTAINTIES:"
echo "  [*] Events 10 and 11 (Secondary lateral move and Event Log clear on Feb 08) have minor clock variance."
echo "      Reason: Independent log sources (Firewall vs Security Event Log) with 4-second offset."
echo "      Impact on reconstruction: Minimal; does not alter tactical sequence of attacker actions."
echo "================================================================"
