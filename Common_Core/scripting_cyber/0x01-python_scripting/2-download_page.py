#!/usr/bin/env python3
"""Module to download and format web page HTML content."""

import requests
from bs4 import BeautifulSoup

def download_page(url):
	"""Download a web page and return it's formatted HTML content.

	Args:
		url (url): The URL of the web page to download.

	Returns:
		str: Formatted HTML content if successful, error message if failed.
	"""
	try:
		response = requests.get(url)
		soup = BeautifulSoup(response.text, 'html.parser')
		return soup.prettify()
	except requests.exceptions.RequestException as e:
		return f"Error: {e}"
