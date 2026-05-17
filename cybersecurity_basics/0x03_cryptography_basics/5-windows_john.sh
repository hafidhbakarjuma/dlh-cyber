#!/bin/bash
john --format=nt --wordlist=/usr/share/wordlists/rockyou.txt "$1" && john --show --format=nt "$1" | awk -F: '$2!="" {print $2}' > 5-password.txt
