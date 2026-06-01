#!/usr/bin/env python3
"""Module to rective HTTP response hearders from a webiste."""

import requests

def get_http_headers(url):
	"""Retrieve HTTP response hearders from a website.

	Args:
		url (str): The URL of the webiste.

	Returns:
		dict: {'status_code': int, 'hearders': dict} if successful, None if Failed.
	"""
	try:
		response = requests.get(url)
		return {
		 'status_code':  response.status_code,
		 'headers': dict(response.headers)
		}

	except requests.exceptions.RequestException:
		return None
