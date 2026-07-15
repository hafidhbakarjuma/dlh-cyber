# PASSIVE RECONNAISSANCE

Description
This project covers passive reconnaissance techniques used in cybersecurity to 

gather information about a target without directly interacting with it.

Tasks

0. WHOIS Record Extractor

File: 0-whois.sh

Extract Registrant, Admin, and Tech information from a domain using 

whois and format the output as a CSV file.

bash./0-whois.sh holbertonschool.com

1. A Record Lookup

File: 1-a_record.sh

Retrieve the A record (IPv4 address) of a domain using nslookup with 

Google's DNS server 8.8.8.8.

bash./1-a_record.sh holbertonschool.com

2. MX Record Lookup

File: 2-mx_record.sh

Retrieve the MX (Mail Exchange) records of a domain to 

identify mail servers using nslookup.

bash./2-mx_record.sh holbertonschool.com

3. TXT Record Lookup

File: 3-txt_record.sh

Retrieve the TXT records of a domain using nslookup. 

TXT records often reveal SPF policies and third-party service integrations.

bash./3-txt_record.sh holbertonschool.com

4. All DNS Records

File: 4-dig_all.sh

Retrieve all DNS records of a domain using dig with any query type. 

Output shows only the answer section.

bash./4-dig_all.sh holbertonschool.com

5. Subdomain Enumeration

File: 5-subfinder.sh

Enumerate subdomains of a target domain using subfinder. Output is 

displayed on screen and saved in Host,IP format to a .txt file.

bash./5-subfinder.sh holbertonschool.com

6. Shodan Reconnaissance Report

File: holbertonschool_report.md

A full passive reconnaissance report on holbertonschool.com using Shodan. Includes IP ranges, subdomains, technologies, open ports, and SSL certificate information.

7-9. CTF Challenge — Hidden Flag

Target Domain: passive.hbtn

A Capture The Flag challenge where the flag is hidden inside DNS records of the 

target domain.

Steps:

bash

# Check TXT record

dig @<target IP> passive.hbtn TXT +noall +answer

# Check nameserver domains

dig @<target IP> passive.hbtn NS +noall +answer

# Check mail server domains

dig @<target IP> passive.hbtn MX +noall +answer

# Query TXT on each nameserver/mailserver found

dig @<target IP> <nameserver_domain> TXT +noall +answer

Hint: 

The flag is hidden within TXT records — check both nameserver and mail server domains, 

not just the main domain.

Key			Concepts

Concept			Description

Passive Recon		Gathering info without touching the target

WHOIS			Domain registration information

DNS Records		A, MX, TXT, NS, CNAME, SOA records

Subdomain Enumeration	Finding hidden subdomains

Shodan			Search engine for internet-connected devices

Google Dorking		Using site: and other operators to find info
