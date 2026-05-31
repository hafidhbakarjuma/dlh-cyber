#!/uusr/bin/env python3
"""DNS resolution module - resolves domain names to IPV4 addresses."""

import socket

def resolve_domain_to_ipv4(domain_name):
	"""Resolution a domain name to its IPV4 address.

	args:
		domain_name (str): The domain name to resolve.

	Returns:
		str | None: The IPV4 address if resolved successfully,
			None if the domain cannot be resolved (socket.gaierror),
			or an error message string for any other exceptions.
	"""
	try:
		return socket.gethostbyname(domain_name)
	except socket.gaierror:
		return None
	except Exception as e:
		return f"Error: {e}"
