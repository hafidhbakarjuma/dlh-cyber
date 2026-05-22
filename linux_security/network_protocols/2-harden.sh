#!/bin/bash
find / -type d -perm -o+w 2>/dev/null | tee /dev/stderr | xargs chmod o-w o-w 2>/dev/null
