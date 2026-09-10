"""Crawler — recovered from legacy crawler.py.

BFS web crawler with form extraction, auth injection, endpoint discovery.
"""

from __future__ import annotations

import asyncio
import re
from typing import Any
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse

import httpx
from bs4 import BeautifulSoup

from sentinel_v2.tools.http_client import HTTPClient


def _parse_forms(html: str, base_url: str) -> list[dict[str, Any]]:
    soup = BeautifulSoup(html, "html.parser")
    forms = []
    for form in soup.find_all("form"):
        action = form.get("action", "")
        if action:
            action = urljoin(base_url, action)
        else:
            action = base_url
        method = (form.get("method") or "GET").upper()
        inputs = []
        for inp in form.find_all(["input", "textarea", "select"]):
            name = inp.get("name")
            if name:
                inputs.append({
                    "name": name,
                    "type": inp.get("type", "text"),
                    "value": inp.get("value", ""),
                })
        forms.append({"action": action, "method": method, "inputs": inputs})
    return forms


def _extract_links(html: str, base_url: str) -> list[str]:
    soup = BeautifulSoup(html, "html.parser")
    urls = set()
    for tag in soup.find_all("a", href=True):
        url = urljoin(base_url, tag["href"])
        urls.add(url)
    return list(urls)


def _extract_endpoints(html: str, base_url: str) -> list[dict[str, Any]]:
    endpoints = []
    patterns = [
        r'"(https?://[^"]+)"',
        r"'(https?://[^']+)'",
        r'fetch\s*\(\s*["\']([^"\']+)["\']',
        r'axios\.(?:get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']',
        r'\.open\s*\(\s*["\'](?:GET|POST|PUT|DELETE|PATCH)["\'],\s*["\']([^"\']+)["\']',
        r'(?:url|endpoint|path|api)\s*[:=]\s*["\']([^"\']+)["\']',
    ]
    seen = set()
    for pattern in patterns:
        for match in re.finditer(pattern, html):
            url = match.group(1)
            full_url = urljoin(base_url, url)
            if full_url not in seen:
                seen.add(full_url)
                endpoints.append({
                    "url": full_url,
                    "method": "GET",
                    "parameters": {},
                })
    return endpoints


class Crawler:
    def __init__(self, http: HTTPClient, max_depth: int = 2, max_pages: int = 50):
        self.http = http
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.visited: set[str] = set()
        self.endpoints: list[Endpoint] = []
        self.forms: list[dict[str, Any]] = []

    async def crawl(self, start_url: str) -> dict[str, Any]:
        queue: list[tuple[str, int]] = [(start_url, 0)]
        pages_crawled = 0

        while queue and pages_crawled < self.max_pages:
            url, depth = queue.pop(0)
            if url in self.visited or depth > self.max_depth:
                continue

            self.visited.add(url)
            pages_crawled += 1

            response = await self.http.request("GET", url)
            if response["error"] or response["status_code"] == 0:
                continue

            body = response["body"]
            base_url = str(response["url"])

            # Extract links for further crawling
            links = _extract_links(body, base_url)
            for link in links:
                if link not in self.visited and self.http.scope.in_scope(link):
                    queue.append((link, depth + 1))

            # Extract forms
            forms = _parse_forms(body, base_url)
            self.forms.extend(forms)

            # Extract endpoints
            endpoints = _extract_endpoints(body, base_url)
            self.endpoints.extend(endpoints)

        return {
            "pages_crawled": pages_crawled,
            "endpoints_found": len(self.endpoints),
            "forms_found": len(self.forms),
            "visited": list(self.visited),
            "endpoints": self.endpoints,
            "forms": self.forms,
        }
