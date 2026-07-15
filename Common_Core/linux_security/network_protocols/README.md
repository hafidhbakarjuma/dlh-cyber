# NETWORK PROTOCOL

Network Protocols Security

# PURPOSE

This project covers practical Linux network security auditing and hardening techniques. Each script demonstrates a real-world security task that auditors and system administrators use to identify and fix vulnerabilities.

Scripts

File		Description

0-iptables.sh	Display all current iptables firewall rules with line numbers

1-firewall.sh	Set up basic iptables rules — block all incoming traffic except SSH

2-harden.sh	Find world-writable directories and fix their permissions

3-identify.sh	Run a full system audit using the Lynis security tool

4-audit.sh	Check and report active SSH configuration settings

5-sshd_config	Hardened SSH server configuration following security best practices

6-nfs.sh	Scan for NFS shares accessible by anyone on the network

7-snmp.sh	Find SNMP configurations using the insecure public community string

8-smtp.sh	Check SMTP server for missing STARTTLS encryption

9-tls_version.txt	TLS version support test results for www.google.com

10-cipher.sh	Scan SSL/TLS ciphers on a server and report weak ones using nmap

11-http_https.txt	Comparison of HTTP vs HTTPS security differences

# Requirements

# bash

sudo apt install iptables lynis nfs-common snmp nmap hping3 -y

# Usage

bash

chmod +x *.sh

sudo ./0-iptables.sh

sudo ./1-firewall.sh

sudo ./2-harden.sh

sudo ./3-identify.sh

sudo ./4-audit.sh

sudo ./6-nfs.sh <target_ip>

sudo ./7-snmp.sh

sudo ./8-smtp.sh

sudo ./10-cipher.sh <target_ip>
