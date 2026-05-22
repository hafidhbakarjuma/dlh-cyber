#!/bin/bash
find / -xdev -type d -perm -0002 2>/dev/null | tee /dev/stderr | xargs chmod o-w 2>/dev/null
