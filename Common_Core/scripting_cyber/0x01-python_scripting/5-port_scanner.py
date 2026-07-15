#!/usr/bin/env python3
"""Module to check if a specific port is open on a host."""

import socket

def check_port(host, port):
	"""Checks if a specific port is open on a host.

	Args:
		host (str): The hostname or IP address to check.
		port (init): The port number to check.

	Returns:
		bool: True id the port is open, False if closed or unreachable.
	"""
	try:
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock.settimeout(3)
		result = sock.connect_ex((host, port))
		sock.close()
		return result == 0
	except Exception:
		return False
