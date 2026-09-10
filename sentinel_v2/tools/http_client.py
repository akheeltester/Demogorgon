"""HTTP Client — recovered from legacy interceptor.py.

Scope guard, rate limiter, auth injection, Burp proxy support.
The backbone for all HTTP operations.
"""

from __future__ import annotations

import asyncio
import contextvars
import time
from typing import Any
from urllib.parse import urlparse

import httpx
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_auth_session: contextvars.ContextVar = contextvars.ContextVar("_auth_session", default=None)


def set_auth_session(session) -> None:
    _auth_session.set(session)


def get_auth_session():
    return _auth_session.get()


def clear_auth_session() -> None:
    _auth_session.set(None)


class RateLimiter:
    def __init__(self, rps: float = 4.0):
        self.interval = 1.0 / rps
        self._last = 0.0
        self._lock = asyncio.Lock()

    async def acquire(self):
        async with self._lock:
            now = time.time()
            wait = self.interval - (now - self._last)
            if wait > 0:
                await asyncio.sleep(wait)
            self._last = time.time()


class ScopeGuard:
    def __init__(self):
        self.allowed: set[str] = set()

    def add(self, domain: str):
        self.allowed.add(domain)

    def in_scope(self, url: str) -> bool:
        if not self.allowed:
            return True
        try:
            host = urlparse(url).hostname or ""
            return any(host == d or host.endswith("." + d) for d in self.allowed)
        except Exception:
            return False


class HTTPClient:
    def __init__(self, proxy: str | None = None, rps: float = 4.0, timeout: float = 30.0):
        self.proxy = proxy
        self.timeout = timeout
        self.rate_limiter = RateLimiter(rps)
        self.scope = ScopeGuard()
        self._client: httpx.AsyncClient | None = None
        self.request_count = 0
        self.total_time = 0.0

    async def _get_client(self, burp: bool = False) -> httpx.AsyncClient:
        session = get_auth_session()
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                          "AppleWebKit/537.36 (KHTML, like Gecko) "
                          "Chrome/131.0.0.0 Safari/537.36"
        }
        cookies = None

        if session is not None:
            try:
                headers.update(session.build_request_headers())
                cookies = session.build_cookie_dict() or None
            except Exception:
                pass

        kwargs: dict[str, Any] = {
            "timeout": self.timeout,
            "follow_redirects": True,
            "verify": False,
            "headers": headers,
        }
        if cookies:
            kwargs["cookies"] = cookies
        if burp:
            kwargs["proxy"] = "http://127.0.0.1:8080"
        elif self.proxy:
            kwargs["proxy"] = self.proxy

        return httpx.AsyncClient(**kwargs)

    async def request(
        self,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
        body: str | bytes | None = None,
        json_data: dict | None = None,
        burp: bool = False,
    ) -> dict[str, Any]:
        if not self.scope.in_scope(url):
            return {"status_code": 0, "headers": {}, "body": "", "elapsed": 0, "url": url, "error": "out_of_scope"}

        await self.rate_limiter.acquire()

        kwargs: dict[str, Any] = {}
        if headers:
            kwargs["headers"] = headers
        if cookies:
            kwargs["cookies"] = cookies
        if body:
            kwargs["content"] = body
        if json_data:
            kwargs["json"] = json_data

        start = time.time()
        try:
            client = await self._get_client(burp)
            async with client:
                response = await client.request(method, url, **kwargs)
                elapsed = time.time() - start
                self.request_count += 1
                self.total_time += elapsed

                return {
                    "status_code": response.status_code,
                    "headers": dict(response.headers),
                    "body": response.text[:100000],
                    "elapsed": elapsed,
                    "url": str(response.url),
                    "error": None,
                }
        except Exception as e:
            elapsed = time.time() - start
            self.request_count += 1
            self.total_time += elapsed
            return {
                "status_code": 0,
                "headers": {},
                "body": "",
                "elapsed": elapsed,
                "url": url,
                "error": str(e),
            }

    async def close(self):
        if self._client and not self._client.is_closed:
            await self._client.aclose()
