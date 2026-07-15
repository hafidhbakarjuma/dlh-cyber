Network Analysis — Wireshark & tshark Field Guide

What is a SOC?

A Security Operations Center (SOC) is a team responsible for monitoring, detecting, and responding to cybersecurity threats in real time. SOC analysts analyze network traffic, logs, and alerts to identify malicious activity such as:

Brute force attacks
C2 (Command & Control) beaconing
Data exfiltration
Port scanning & reconnaissance

Tools Overview

Wireshark (GUI)

Visual packet analyzer. Best for interactive investigation.

ActionHowFilter trafficType in filter bar: tcp.port == 80Follow TCP streamRight-click packet → Follow → TCP StreamFind credentialsFilter: ftp or http then follow streamView conversationsStatistics → ConversationsExport objectsFile → Export Objects → HTTP

tshark (CLI)

Command-line version of Wireshark. Best for scripting and automation.

Tips for SOC Analysts

Always follow TCP streams — raw packets hide context; streams tell the story
Check both directions — filter ip.src AND ip.dst separately
Sequence numbers reveal gaps — missing bytes in a stream indicate packet loss or intentional fragmentation
Plain-text protocols are goldmines — FTP, HTTP, Telnet carry credentials unencrypted
Beaconing = regularity — malware phones home at fixed intervals; look for repeated SYN patterns
C2 ports to watch — 4444, 1234, 8080, 9999, 31337 are common reverse shell ports
Null bytes (\x00) are separators — not always missing data; sometimes intentional delimiters
