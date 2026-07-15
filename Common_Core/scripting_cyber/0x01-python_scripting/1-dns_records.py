#!/usr/bin/env python3
"""DNS record enumaration module using dnspython library."""

import dns.resolver

def query_dns_records(domain_name):
	"""Query multiple DNS record types for a given domain.

	args:
		domain_name (str): The domain to query.

	Returns:
		dict: Keys are record types (str), Values are dns.resolver answers.
	"""

	results = {}
	record_types = ['A','AAAA', 'MX', 'NS', 'TXT', 'SOA']

	for record_type in record_types:
		try:
			answers = dns.resolver.resolve(domain_name, record_type)
			results[record_type] = answers
		except Exception:
			pass
	return results
