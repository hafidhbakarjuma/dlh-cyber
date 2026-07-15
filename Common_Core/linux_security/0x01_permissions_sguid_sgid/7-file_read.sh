#!/bin/bash
find "$1" -type f -exec chmod o-i {} \; 2>/dev/null
