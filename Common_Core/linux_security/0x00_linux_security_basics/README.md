# LINUX SECURITY

A collection of Bash scripts for Linux system security monitoring, auditing, and network analysis. 

All scripts must be run as a privileged user (root or sudoers).

Requirements

Linux-based OS (Kali, Ubuntu, Debian, RHEL, CentOS)

Root or sudo privileges

Tools: last, ss, ufw, iptables, netstat, lynis, tcpdump, nmap

Scripts

0. Last Logins — 0-login.sh

Displays the last 5 login sessions with full date and time.

bash

sudo last -F -5

Flag		Meaning

-F		Full date and time format

-5		Limit to last 5 sessions

1. Active Connections — 1-active-connections.sh

Displays all active TCP network socket connections using ss (iproute2).

bash

sudo ss -antp

Flag		Meaning

-a		All sockets — listening and non-listening

-n		Numerical addresses — no DNS resolution

-t		TCP sockets only

-p		PID and program name

2. Incoming Connections — 2-incoming_connections.sh

Allows only incoming TCP connections through port 80 using UFW.

bash

sudo ufw allow proto tcp to any port 80

Part		Meaning

allow		Permit incoming traffic

80		HTTP port

/tcp		TCP protocol only

3. Firewall Rules — 3-firewall_rules.sh


Lists all rules in the security table of iptables in verbose mode.

bash

sudo iptables -t security -L -v

Flag		Meaning

-t security	Target the security table

-L		List all rules in all chains

-v		Verbose — shows packet and byte counters

4. Network Services — 4-network_services.sh

Lists all services, their state, and ports for both TCP and UDP using netstat.

bash

sudo netstat -tlunp

Flag		Meaning

-t		TCP sockets

-u		UDP sockets

-l		Listening sockets only

-n		Numerical addresses

-p		PID and program name

5. Audit System — 5-audit_system.sh

Runs a full system security audit using Lynis — checks kernel, 

services, users, filesystem, firewall, and generates a hardening score.

bash

sudo lynis audit system

Part		Meaning

audit		Perform a security audit

system		Audit the entire local system

6. Capture and Analyze — 6-capture_analyze.sh

Captures and analyzes network packets on all interfaces, limited to 5 packets.

bash

sudo tcpdump -c 5 -i any

Flag		Meaning

-c 5		Stop after capturing 5 packets

-i any		Listen on all network interfaces

7. Network Scan — 7-scan.sh

Scans a subnetwork, IP, or hostname passed as an argument $1.

bash

sudo nmap $1

Usage:

bash ./7-scan.sh "DNS"

./7-scan.sh "IP"

Author

Linux Security Basics Project
