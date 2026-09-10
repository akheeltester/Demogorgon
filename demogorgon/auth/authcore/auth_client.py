"""
authcore/auth_client.py — Auth-aware HTTP client for Demogorgon.

Provides AuthAwareClient: a reusable HTTP client that automatically
injects authentication from an AuthSession into every request.

Supports:
    - Cookie injection (CookieJar → httpx cookies)
    - Header injection (HeaderSet → httpx headers)
    - JWT/Bearer token injection (Authorization header)
    - API key injection (custom header)
    - Basic auth injection (Authorization header)
    - CSRF token injection (header or form field)
    - Domain-scope filtering (prevent cookie leakage)
    - Session health validation
    - Retry with backoff

Usage:
    async with AuthAwareClient(session) as client:
        resp = await client.get("https://target.com/api/data")
        # Cookies, headers, JWT all injected automatically
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Dict, List, Optional, Union
from urllib.parse import urlparse

import httpx

from demogorgon.auth.authcore.session import AuthSession, AuthType

logger = logging.getLogger(__name__)


class AuthAwareClient:
    """
    HTTP client that automatically injects authentication from an AuthSession.
    
    Wraps httpx.AsyncClient with auth injection, domain-scope filtering,
    and session health validation.
    
    Usage:
        async with AuthAwareClient(session) as client:
            resp = await client.get(url)
    """
    
    def __init__(
        self,
        auth_session: Optional[AuthSession] = None,
        use_burp: bool = False,
        burp_proxy_url: str = "http://127.0.0.1:8080",
        timeout: float = 10.0,
        verify_ssl: bool = False,
        follow_redirects: bool = True,
        max_retries: int = 2,
        retry_delay: float = 1.0,
    ):
        self.auth_session = auth_session
        self.use_burp = use_burp
        self.burp_proxy_url = burp_proxy_url
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.follow_redirects = follow_redirects
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self._client: Optional[httpx.AsyncClient] = None
    
    def _build_headers(self) -> Dict[str, str]:
        """Build default headers with auth injection."""
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                          "AppleWebKit/537.36 (KHTML, like Gecko) "
                          "Chrome/124.0.0.0 Safari/537.36"
        }
        
        if self.auth_session:
            auth_headers = self.auth_session.build_request_headers()
            headers.update(auth_headers)
        
        return headers
    
    def _build_cookies(self) -> Optional[Dict[str, str]]:
        """Build cookies dict from AuthSession."""
        if not self.auth_session or not self.auth_session.cookies:
            return None
        return dict(self.auth_session.cookies.cookies) or None
    
    def _build_proxy(self) -> Optional[Dict[str, str]]:
        """Build proxy config for Burp Suite."""
        if not self.use_burp:
            return None
        return {
            "http://": self.burp_proxy_url,
            "https://": self.burp_proxy_url,
        }
    
    def _is_in_scope(self, url: str) -> bool:
        """Check if URL is within the auth session's target domain."""
        if not self.auth_session or not self.auth_session.target_domain:
            return True
        
        try:
            hostname = urlparse(url).hostname or ""
            domain = self.auth_session.target_domain
            return hostname == domain or hostname.endswith("." + domain)
        except Exception:
            return False
    
    def _create_client(self) -> httpx.AsyncClient:
        """Create the underlying httpx.AsyncClient with auth injected."""
        headers = self._build_headers()
        cookies = self._build_cookies()
        proxies = self._build_proxy()
        
        kwargs: Dict[str, Any] = {
            "verify": self.verify_ssl,
            "timeout": self.timeout,
            "headers": headers,
            "follow_redirects": self.follow_redirects,
        }
        
        if cookies:
            kwargs["cookies"] = cookies
        if proxies:
            kwargs["proxies"] = proxies
        
        return httpx.AsyncClient(**kwargs)
    
    async def __aenter__(self) -> AuthAwareClient:
        self._client = self._create_client()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self._client:
            await self._client.aclose()
            self._client = None
    
    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: Optional[Dict[str, str]] = None,
        content: Optional[Union[str, bytes]] = None,
        json: Optional[Any] = None,
        data: Optional[Dict[str, str]] = None,
        follow_redirects: Optional[bool] = None,
        **kwargs,
    ) -> Optional[httpx.Response]:
        """
        Send an HTTP request with auth injection.
        
        Auth is injected via default headers/cookies from the AuthSession.
        Per-request headers override auth headers if same key.
        
        Returns httpx.Response or None on failure/out-of-scope.
        """
        if not self._client:
            raise RuntimeError("AuthAwareClient must be used as async context manager")
        
        if not self._is_in_scope(url):
            logger.warning(f"Blocked out-of-scope request to {url} (auth session domain: {self.auth_session.target_domain if self.auth_session else 'none'})")
            return None
        
        # Merge per-request headers (they override auth headers)
        merged_headers = {}
        if headers:
            merged_headers.update(headers)
        
        last_exception = None
        for attempt in range(self.max_retries + 1):
            try:
                resp = await self._client.request(
                    method=method,
                    url=url,
                    headers=merged_headers if merged_headers else None,
                    content=content,
                    json=json,
                    data=data,
                    follow_redirects=follow_redirects if follow_redirects is not None else self.follow_redirects,
                    **kwargs,
                )
                return resp
            except (httpx.TimeoutException, httpx.ConnectError, httpx.RemoteProtocolError) as e:
                last_exception = e
                if attempt < self.max_retries:
                    logger.debug(f"Request to {url} failed (attempt {attempt + 1}): {e}")
                    await asyncio.sleep(self.retry_delay * (attempt + 1))
                    continue
                break
            except Exception as e:
                logger.warning(f"Request to {url} failed: {e}")
                return None
        
        logger.warning(f"Request to {url} failed after {self.max_retries + 1} attempts: {last_exception}")
        return None
    
    async def get(self, url: str, **kwargs) -> Optional[httpx.Response]:
        return await self.request("GET", url, **kwargs)
    
    async def post(self, url: str, **kwargs) -> Optional[httpx.Response]:
        return await self.request("POST", url, **kwargs)
    
    async def put(self, url: str, **kwargs) -> Optional[httpx.Response]:
        return await self.request("PUT", url, **kwargs)
    
    async def patch(self, url: str, **kwargs) -> Optional[httpx.Response]:
        return await self.request("PATCH", url, **kwargs)
    
    async def delete(self, url: str, **kwargs) -> Optional[httpx.Response]:
        return await self.request("DELETE", url, **kwargs)
    
    async def health_check(self, url: Optional[str] = None) -> bool:
        """
        Validate session by sending a request to the validation endpoint.
        
        Returns True if session is valid (2xx response).
        """
        if not self.auth_session:
            return False
        
        check_url = url or self.auth_session.validation_endpoint
        if not check_url:
            # Try the target domain root
            if self.auth_session.target_domain:
                check_url = f"https://{self.auth_session.target_domain}/"
            else:
                return False
        
        resp = await self.get(check_url)
        if resp is None:
            return False
        
        is_valid = 200 <= resp.status_code < 400
        self.auth_session.mark_validated(resp.status_code)
        return is_valid
    
    @property
    def role(self):
        """Get the role of the current auth session."""
        if self.auth_session:
            return self.auth_session.role
        return None
    
    @property
    def org_id(self) -> str:
        """Get the org ID of the current auth session."""
        if self.auth_session:
            return self.auth_session.org.org_id
        return ""
    
    @property
    def label(self) -> str:
        """Get the label of the current auth session."""
        if self.auth_session:
            return self.auth_session.label
        return "anonymous"
    
    def __repr__(self) -> str:
        return (
            f"AuthAwareClient("
            f"session={self.auth_session.label if self.auth_session else 'none'}, "
            f"role={self.auth_session.role.value if self.auth_session else 'none'}, "
            f"burp={self.use_burp})"
        )
