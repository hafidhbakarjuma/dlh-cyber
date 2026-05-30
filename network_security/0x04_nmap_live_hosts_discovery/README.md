# Nmap Live Host Discovery

What is Nmap?

Nmap (Network Mapper) is an open-source tool used for network exploration and security auditing. 

It works by sending crafted packets to target hosts and analyzing the responses to determine:

1. Which hosts are alive on a network

2. Which ports are open

3. What services and versions are running

4. What OS the target is running


How It Works

Attacker                Target
   |                      |
   |--- probe packet ---->|   (ICMP / TCP / UDP / ARP)
   |                      |
   |<--- response --------|   host is UP ✓  (or no reply = DOWN)

Nmap sends different types of probe packets depending on the scan method. 

The target's response (or lack of one) reveals whether it is alive and what services it exposes.

Important Flags

Flag		Meaning

-sn		Skip port scan — host discovery only

-PR		ARP ping (Layer 2, same subnet only)

-PE		ICMP Echo ping (type 8)-PPICMP Timestamp ping (type 13)

-PM		ICMP Address Mask ping (type 17)

-PS<ports>	TCP SYN ping

-PA<ports>	TCP ACK ping

-PU<ports>	UDP ping

-sU		UDP port scan

-sV		Version detection

-p<range>	Specify port range (e.g. -p200-300)

-T<0-5>		Timing template (0=slowest, 5=fastest)

sudo		Required for raw packet scans

Tasks Summary

Task 0 — ARP Scan

sudo nmap -sn -PR <subnet>

Discovers hosts using ARP requests. Works only on the same subnet. 

Reveals MAC addresses. Rarely blocked by firewalls.

Task 1 — ICMP Echo Scan

sudo nmap -sn -PE <subnet>

Sends classic ping (ICMP type 8). Works across subnets but often blocked by firewalls.

Task 2 — ICMP Timestamp Scan

sudo nmap -sn -PP <subnet>

Sends ICMP Timestamp requests (type 13). Useful alternative when Echo is blocked, 

since some firewalls forget to block type 13.

Task 3 — ICMP Address Mask Scan

sudo nmap -sn -PM <subnet>

Sends ICMP Address Mask requests (type 17). Rarely replied to on modern systems but 

effective against older or misconfigured hosts.

Task 4 — TCP SYN Ping

sudo nmap -sn -PS22,80,443 <subnet>

Sends a TCP SYN packet. A SYN/ACK or RST reply confirms the host is up. 

More reliable than ICMP since port 80/443 are rarely firewalled.

Task 5 — TCP ACK Ping

sudo nmap -sn -PA22,80,443 <subnet>

Sends an unexpected TCP ACK. Host replies with RST to reveal itself. 

Bypasses stateless firewalls but blocked by stateful ones.

Task 6 — UDP Ping Scan

sudo nmap -sn -PU53,161,162 <subnet>

Sends UDP packets to common ports (DNS=53, SNMP=161/162). 

An ICMP Port Unreachable reply means the host is up. Slower than TCP scans.

Task 7 — UDP Version Scan (Flag Hunt)

sudo nmap -sU -sV -T4 -p200-300 <target>

Scans UDP ports 200–300 with version detection. 

The flag was hidden inside a service version banner on an open UDP port.
