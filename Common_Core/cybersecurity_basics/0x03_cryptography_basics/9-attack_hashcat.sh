#!/bin/bash
hashcat -m 0 -a 1 -o 9-password.txt --outfile-format=2 --force "$1" wordlist1.txt wordlist2.txt
