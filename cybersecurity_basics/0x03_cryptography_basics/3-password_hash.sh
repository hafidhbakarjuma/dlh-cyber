#!/bin/bash
salt=$(openssl rand -base64 12 | tr -dc 'a-zA-Z0-9' | head -c 16) echo -n "${salt}$1" | openssl dgst -sha512
