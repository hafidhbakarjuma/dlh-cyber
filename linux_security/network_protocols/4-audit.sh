  GNU nano 8.7.1                                      4-audit.sh *
#!/bin/bash
grep -v "^#" /etc/ssh/sshd_config | grep -v "^$"
