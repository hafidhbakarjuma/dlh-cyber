#!/usr/bin/env python3
"""Module to recursively crawl a website and discover internal links."""
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse


def crawl_website(start_url, max_depth=2):
    """Recursively crawl a website and return all visited internal URLs."""
    visited = set()

    def crawl(url, depth):
        if depth == 0 or url in visited:
            return
        try:
            response = requests.get(url, timeout=5)
            print(f"Crawling: {url}")
            visited.add(url)

            base_domain = urlparse(start_url).netloc
            soup = BeautifulSoup(response.text, 'html.parser')

            for tag in soup.find_all('a', href=True):
                absolute_url = urljoin(url, tag['href'])
                parsed = urlparse(absolute_url)

                if parsed.netloc == base_domain and absolute_url not in visited:
                    crawl(absolute_url, depth - 1)

        except requests.exceptions.RequestException:
            pass

    crawl(start_url, max_depth)
    return visited
