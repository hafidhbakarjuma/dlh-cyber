# FILE PERMISSION

PURPOSE

Linux permissions control who can read, write, or execute files and directories.

Every file has three permission groups:

owner (u), group (g), and others (o) — each with read (r), write (w), and execute (x) bits.

Beyond basic permissions, Linux has special bits:

SUID (4000) — file runs with the owner's privileges

SGID (2000) — file runs with the group's privileges, or new files in a directory inherit the group

Sticky bit (1000) — only the file owner can delete it (used on /tmp)

Understanding permissions is essential for system administration, security hardening, and penetration testing — a misconfigured permission is one of the most common attack vectors in Linux systems.

Exercises

0. Add User — 0-add_user.sh

Creates a new user and sets their password non-interactively.

1. Add Group — 1-add_group.sh

Creates a new group, changes file group ownership, and sets rwx for the group.

2. Sudo No Password — 2-sudo_nopass.sh

Grants a user the ability to run sudo without entering a password.

3. Find SUID & SGID Files — 3-find_files.sh

Searches a directory for files with SUID or SGID set and shows full details.

4. Find SUID Files — 4-find_suid.sh

Lists all files with the SUID bit set in a given directory.

5. Find SGID Files — 5-find_sgid.sh

Lists all files with the SGID bit set in a given directory.

6. Find Recently Modified SUID/SGID — 6-check_files.sh

Finds files with SUID or SGID modified in the last 24 hours and shows full details.

7. Read-Only for Others — 7-file_read.sh

Removes execute permission from others on all files in a directory.

8. Change File Owner — 8-change_user.sh

Changes ownership of files from user2 to user3 in a directory.

9. Full Permissions on Empty Files — 9-empty_file.sh

Finds all empty files in a directory and grants full permissions (777) to everyone.

Key Commands Reference

Command		Purpose

chmod		Change file permissions

chown		Change file owner

chgrp		Change file group

find -perm	Search by permission bits

find -user	Search by owner

find -empty	Search for empty files

find -mtime	Search by modification time

sudo		Run command as root

useradd		Create a new user

addgroup	Create a new group
