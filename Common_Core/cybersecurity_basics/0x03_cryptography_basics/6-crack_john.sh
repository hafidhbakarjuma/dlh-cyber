#!/bin/bash
john --format=Raw-SHA256 --wordlist=/usr/share/wordlists/rockyou.txt "$1" && john --show --format=Raw-SHA256 "$1" | awk -F: '$2!="" {print $2}' > 6-password.txt
