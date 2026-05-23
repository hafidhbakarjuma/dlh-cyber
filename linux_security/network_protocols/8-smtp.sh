#!/bin/bash
grep -i "tls" /etc/potfix/main.cf 2>/dev/null || echo "STARTTLS not configures"
