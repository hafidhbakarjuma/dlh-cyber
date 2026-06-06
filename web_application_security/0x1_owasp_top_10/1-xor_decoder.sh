#!/bin/bash
INPUT="${1#\{xor\}}"
echo "$INPUT" | base64 -d | python3 -c "
import sys
data = sys.stdin.buffer.read()
print(bytes(b ^ 0x5f for b in data).decode())
"
