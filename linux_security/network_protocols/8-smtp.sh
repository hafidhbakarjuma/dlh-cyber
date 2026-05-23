#!/bin/bash
grep -i "^smtpd_tls_security_level" /etc/potfix/main.cf 2>/dev/null || echo "STARTTLS not configures"
