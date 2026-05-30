#!/bin/bash
sudo nmap -sn -PU22,80,443 $1
