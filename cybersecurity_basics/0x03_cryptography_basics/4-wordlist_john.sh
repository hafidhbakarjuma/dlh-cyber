#!/bin/bash
john --format=Raw-MD5 --wordlist=/usr/share/wordlists/rockyou.txt "$1" && john --show --format=Raw-MD5 "$1" | awk -F: '$2!="" {print $2}' > 4-password.txt
