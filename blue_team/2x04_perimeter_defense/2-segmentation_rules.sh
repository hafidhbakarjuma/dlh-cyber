#!/bin/bash
set -euo pipefail

OUTPUT_FILE="segmentation_rules.json"

# Ensure jq is installed
if ! command -v jq &> /dev/null; then
    echo "Error: Required command 'jq' is not installed." >&2
    exit 1
fi

jq -n '
{
  "zones": [
    {
      "name": "DMZ",
      "cidr": "10.0.1.0/24",
      "purpose": "Public-facing and external-facing services",
      "default_inbound": "drop",
      "default_outbound": "accept_restricted"
    },
    {
      "name": "INTERNAL",
      "cidr": "10.0.2.0/24",
      "purpose": "Clinical applications, databases, and server hosts",
      "default_inbound": "drop",
      "default_outbound": "accept_restricted"
    },
    {
      "name": "MGMT",
      "cidr": "10.0.3.0/24",
      "purpose": "Administrative management and orchestration",
      "default_inbound": "drop",
      "default_outbound": "accept_restricted"
    },
    {
      "name": "MEDDEV",
      "cidr": "10.0.4.0/24",
      "purpose": "Medical device VLAN and isolated equipment",
      "default_inbound": "drop",
      "default_outbound": "accept_restricted"
    }
  ],
  "flows": [
    {
      "src_zone": "MGMT",
      "dst_zone": "INTERNAL",
      "proto": "tcp",
      "dport": 22,
      "justification": "Administration and host management",
      "exception_for": null
    },
    {
      "src_zone": "MGMT",
      "dst_zone": "DMZ",
      "proto": "tcp",
      "dport": 22,
      "justification": "Administration and host management",
      "exception_for": null
    },
    {
      "src_zone": "MGMT",
      "dst_zone": "MEDDEV",
      "proto": "tcp",
      "dport": 22,
      "justification": "Medical device administrative access",
      "exception_for": null
    },
    {
      "src_zone": "MGMT",
      "dst_zone": "MEDDEV",
      "proto": "tcp",
      "dport": 4242,
      "justification": "Medical device DICOM gateway management",
      "exception_for": null
    },
    {
      "src_zone": "INTERNAL",
      "dst_zone": "INTERNAL",
      "proto": "tcp",
      "dport": 443,
      "justification": "Clinical workstations to internal server hosts (EHR web)",
      "exception_for": null
    },
    {
      "src_zone": "INTERNAL",
      "dst_zone": "INTERNAL",
      "proto": "tcp",
      "dport": 3306,
      "justification": "Clinical workstations to internal databases",
      "exception_for": null
    },
    {
      "src_zone": "DMZ",
      "dst_zone": "INTERNAL",
      "proto": "tcp",
      "dport": 3306,
      "justification": "DMZ application hosts to internal databases only from named application hosts",
      "exception_for": null
    },
    {
      "src_zone": "MEDDEV",
      "dst_zone": "INTERNAL",
      "proto": "tcp",
      "dport": 4242,
      "justification": "DICOM imaging to PACS",
      "exception_for": null
    },
    {
      "src_zone": "MEDDEV",
      "dst_zone": "INTERNAL",
      "proto": "tcp",
      "dport": 443,
      "justification": "EHR web integration for device display",
      "exception_for": null
    },
    {
      "src_zone": "DMZ",
      "dst_zone": "MGMT",
      "proto": "udp",
      "dport": 53,
      "justification": "DNS resolution via MGMT resolver",
      "exception_for": null
    },
    {
      "src_zone": "DMZ",
      "dst_zone": "MGMT",
      "proto": "tcp",
      "dport": 53,
      "justification": "DNS resolution via MGMT resolver",
      "exception_for": null
    },
    {
      "src_zone": "INTERNAL",
      "dst_zone": "MGMT",
      "proto": "udp",
      "dport": 53,
      "justification": "DNS resolution via MGMT resolver",
      "exception_for": null
    },
    {
      "src_zone": "INTERNAL",
      "dst_zone": "MGMT",
      "proto": "tcp",
      "dport": 53,
      "justification": "DNS resolution via MGMT resolver",
      "exception_for": null
    },
    {
      "src_zone": "MEDDEV",
      "dst_zone": "MGMT",
      "proto": "udp",
      "dport": 53,
      "justification": "DNS resolution via MGMT resolver",
      "exception_for": null
    },
    {
      "src_zone": "MEDDEV",
      "dst_zone": "MGMT",
      "proto": "tcp",
      "dport": 53,
      "justification": "DNS resolution via MGMT resolver",
      "exception_for": null
    },
    {
      "src_zone": "MGMT",
      "dst_zone": "MGMT",
      "proto": "udp",
      "dport": 53,
      "justification": "DNS resolution via MGMT resolver",
      "exception_for": null
    },
    {
      "src_zone": "MGMT",
      "dst_zone": "MGMT",
      "proto": "tcp",
      "dport": 53,
      "justification": "DNS resolution via MGMT resolver",
      "exception_for": null
    }
  ],
  "summary": {
    "total_zones": 4,
    "flow_count": 17,
    "allow_count": 17,
    "deny_count": 0,
    "cross_zone_pairs": 16
  }
}
' > "$OUTPUT_FILE"

echo "Segmentation rules successfully written to $OUTPUT_FILE"
