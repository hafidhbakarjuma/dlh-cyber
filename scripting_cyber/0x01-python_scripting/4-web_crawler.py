#!/usr/bin/env python3

"""Module to recursively crawl a webiste and disccover in ternal links."""

import requests

from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

def crawl_website(start_url, max_depth=2, visited=None):
	"""Recursively crawl a webiste and return all visited internal URLs.

	Args:
		start_url (str): The URL to start crawling from.
		max_depth (int): Maximum depth to crawl.
		visited (set): Set of already visited URLs.
	Returns:
		set: All seccussfully visited URLs from the same domain.
	"""
	if visited is None:
		visited = set()

	if max_depth == 0 or start_url in visited:
		return visited
	try:
		response = requests.get(start_url, timeout=5)
		print(f"Crawling: {start_url}")
		visited.add(start_url)

		base_domain = urlparse(start_url).netloc
		soup = BeautifulSoup(response.text, 'html.parser')

		for tag in soup.find_all('a', href=True):
			absolute_url = urljoin(start_url, tag['href'])
			parsed = urlparse(absolute_url)

		if parsed.netloc == base_domain and absolute_url not in visited:
			crawl_website(absolute_url, max_depth - 1, visited)

	except requests.exceptions.RequestException:
		pass
	return visited
