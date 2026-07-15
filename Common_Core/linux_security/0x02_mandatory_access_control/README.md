# MAC (Mandotory Access Control)

Bash scripts exploring SELinux and AppArmor — two Mandatory Access Control systems in Linux.

These exercises cover checking security modes, managing ports, user mappings, and SELinux booleans.

Background

MAC (Mandatory Access Control) is a security model where the OS enforces access policy — not the user or file owner.

Even root can be restricted under MAC. 

DAC	File ownerchmod, Linux permissions

MAC	The OS/policySELinux, AppArmor

Requirements

Linux system (RHEL/CentOS/Fedora for SELinux, Ubuntu/Debian for AppArmor)

policycoreutils-python-utils installed

All scripts must be run with sudo

# Install SELinux tools

sudo apt install policycoreutils python3-semanage -y

# Install AppArmor tools

sudo apt install apparmor apparmor-utils -y

# FILE			DESCRIPTION

0-analyse_mode.sh	Display current SELinux mode

1-security_match.sh	Display AppArmor security profiles status

2-list_http.sh		List SELinux ports related to HTTP

3-add_port.sh		Add port 81 to SELinux HTTP policy

4-list_users.sh		List all SELinux user mappings

5-add_user.sh		Add a new SELinux login mapping

6-list_booleans.sh	List all SELinux booleans

7-set_sendmail.sh	Enable httpd_can_sendmail boolean permanently

# Check SELinux status

getenforce

sestatus

# Manage ports

semanage port -l                                      # list all

semanage port -a -t http_port_t -p tcp 81             # add port

semanage port -d -t http_port_t -p tcp 81             # delete port

# Manage users

semanage user -l                                      # list users

semanage login -a -s user_u username                  # add mapping

semanage login -d username                            # delete mapping

# Manage booleans

semanage boolean -l                                   # list all

setsebool -P boolean_name on                          # set permanently

getsebool boolean_name                                # check one

# Investigate denials (SOC)

ausearch -m avc -ts today                             # today's blocks

ausearch -m mac_status                                # mode changes
