"""Browser Tool — persistent Playwright session with automatic intelligence capture.

The browser is the source of truth. Every request, response, cookie, token,
localStorage item, and DOM change is automatically captured and made available
to the researcher.

No manual export. No explicit calls. It just works.
"""

from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass, field
from typing import Any

from playwright.async_api import async_playwright, Browser, BrowserContext, Page, Playwright


@dataclass
class CapturedRequest:
    """A request captured from the browser."""
    method: str
    url: str
    headers: dict[str, str]
    post_data: str | None
    resource_type: str
    timestamp: float = field(default_factory=time.time)




@dataclass
class CapturedResponse:
    """A response captured from the browser."""
    url: str
    status: int
    headers: dict[str, str]
    body: str | None
    timestamp: float = field(default_factory=time.time)


@dataclass
class TokenState:
    """Current authentication tokens extracted from the browser."""
    cookies: dict[str, str] = field(default_factory=dict)
    localStorage: dict[str, str] = field(default_factory=dict)
    sessionStorage: dict[str, str] = field(default_factory=dict)
    csrf_tokens: list[str] = field(default_factory=list)
    jwt_tokens: list[str] = field(default_factory=list)
    api_keys: list[str] = field(default_factory=list)
    bearer_tokens: list[str] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)

    def get_auth_headers(self) -> dict[str, str]:
        """Extract authorization headers from captured tokens."""
        headers = {}
        for jwt in self.jwt_tokens:
            headers["Authorization"] = f"Bearer {jwt}"
            break
        for key in self.api_keys:
            headers["X-API-Key"] = key
            break
        for token in self.bearer_tokens:
            headers["Authorization"] = f"Bearer {token}"
            break
        return headers

    def get_auth_cookies(self) -> dict[str, str]:
        """Return cookies as a simple dict."""
        return dict(self.cookies)

    def get_csrf_token(self) -> str | None:
        """Get the most recently captured CSRF token."""
        return self.csrf_tokens[-1] if self.csrf_tokens else None

    def to_dict(self) -> dict:
        return {
            "cookies": self.cookies,
            "localStorage": self.localStorage,
            "sessionStorage": self.sessionStorage,
            "csrf_tokens": self.csrf_tokens,
            "jwt_tokens": self.jwt_tokens,
            "api_keys": self.api_keys,
            "bearer_tokens": self.bearer_tokens,
        }


class BrowserTool:
    """Persistent browser session with automatic intelligence capture.

    Every navigation, click, and form submission automatically captures:
    - All HTTP requests and responses
    - All cookies, localStorage, sessionStorage
    - JWT tokens, CSRF tokens, API keys
    - DOM changes and page transitions
    - Screenshots at key moments

    The researcher never needs to explicitly ask for this data.
    It's always available via get_captured_requests(), get_tokens(), etc.
    """

    def __init__(self, headless: bool = True, proxy: str | None = None):
        self.headless = headless
        self.proxy = proxy
        self._playwright: Playwright | None = None
        self._browser: Browser | None = None
        self._context: BrowserContext | None = None
        self._page: Page | None = None

        # Automatic intelligence capture
        self._captured_requests: list[CapturedRequest] = []
        self._captured_responses: list[CapturedResponse] = []
        self._tokens = TokenState()
        self._navigation_history: list[dict[str, Any]] = []
        self._screenshots: list[dict[str, Any]] = []
        self._dom_snapshots: list[dict[str, Any]] = []

        # Auto-extraction patterns
        self._sensitive_patterns = [
            "token", "jwt", "csrf", "session", "auth", "api_key",
            "apikey", "secret", "password", "access_token", "refresh_token",
            "bearer", "authorization", "x-api-key", "x-csrf",
        ]

    async def launch(self):
        """Start the browser and set up automatic capture."""
        self._playwright = await async_playwright().start()

        launch_args: dict[str, Any] = {
            "headless": self.headless,
            "args": [
                "--disable-blink-features=AutomationControlled",
                "--no-sandbox",
            ],
        }
        if self.proxy:
            launch_args["proxy"] = {"server": self.proxy}

        self._browser = await self._playwright.chromium.launch(**launch_args)
        self._context = await self._browser.new_context(
            viewport={"width": 1920, "height": 1080},
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        )
        self._page = await self._context.new_page()

        # Set up automatic request/response capture
        self._page.on("request", self._on_request)
        self._page.on("response", self._on_response)
        self._page.on("framenavigated", self._on_navigation)

    def _on_request(self, request):
        """Automatically capture every outgoing request."""
        captured = CapturedRequest(
            method=request.method,
            url=request.url,
            headers=dict(request.headers),
            post_data=request.post_data,
            resource_type=request.resource_type,
        )
        self._captured_requests.append(captured)

    def _on_response(self, response):
        """Automatically capture every incoming response."""
        async def _capture():
            try:
                body = await response.text()
            except Exception:
                body = None
            captured = CapturedResponse(
                url=response.url,
                status=response.status,
                headers=dict(response.headers),
                body=body[:50000] if body else None,
            )
            self._captured_responses.append(captured)

            # Auto-extract tokens from response
            await self._extract_tokens_from_response(response, body)

        asyncio.create_task(_capture())

    def _on_navigation(self, frame):
        """Track navigation history."""
        if frame == self._page.main_frame:
            self._navigation_history.append({
                "url": frame.url,
                "timestamp": time.time(),
            })

    async def _extract_tokens_from_response(self, response, body: str | None):
        """Automatically extract tokens from response headers and body."""
        headers = response.headers

        # Extract Set-Cookie headers
        for name, value in headers.items():
            if name.lower() == "set-cookie":
                cookie_parts = value.split(";")[0].split("=", 1)
                if len(cookie_parts) == 2:
                    self._tokens.cookies[cookie_parts[0].strip()] = cookie_parts[1].strip()

        # Extract JWT from response body
        if body:
            try:
                # Look for JWT patterns in JSON responses
                if "token" in body.lower() or "jwt" in body.lower():
                    data = json.loads(body)
                    self._extract_tokens_from_dict(data)
            except (json.JSONDecodeError, TypeError):
                pass

        # Extract CSRF tokens from headers
        for name, value in headers.items():
            if "csrf" in name.lower():
                self._tokens.csrf_tokens.append(value)

    def _extract_tokens_from_dict(self, data: dict, depth: int = 0):
        """Recursively extract tokens from a dictionary."""
        if depth > 5:
            return
        for key, value in data.items():
            key_lower = key.lower()
            if isinstance(value, str):
                # Check if this looks like a token
                if any(pattern in key_lower for pattern in self._sensitive_patterns):
                    if "jwt" in key_lower or (len(value) > 100 and "." in value):
                        self._tokens.jwt_tokens.append(value)
                    elif "csrf" in key_lower:
                        self._tokens.csrf_tokens.append(value)
                    elif "api" in key_lower and "key" in key_lower:
                        self._tokens.api_keys.append(value)
                    elif "bearer" in key_lower:
                        self._tokens.bearer_tokens.append(value)
                    elif "token" in key_lower:
                        self._tokens.bearer_tokens.append(value)
            elif isinstance(value, dict):
                self._extract_tokens_from_dict(value, depth + 1)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        self._extract_tokens_from_dict(item, depth + 1)

    async def navigate(self, url: str, wait_until: str = "domcontentloaded") -> dict[str, Any]:
        """Navigate to a URL. Automatically captures all state."""
        if not self._page:
            raise RuntimeError("Browser not launched.")

        start = time.time()
        try:
            response = await self._page.goto(url, wait_until=wait_until, timeout=30000)
            elapsed = time.time() - start

            # Auto-extract tokens from page
            await self._extract_tokens_from_page()

            state = await self._get_page_state()
            state["elapsed"] = elapsed
            state["navigation_status"] = "success"
            if response:
                state["status_code"] = response.status
            return state
        except Exception as e:
            return {
                "url": url,
                "error": str(e),
                "navigation_status": "failed",
                "elapsed": time.time() - start,
            }

    async def click(self, selector: str) -> dict[str, Any]:
        """Click an element. Automatically captures resulting state."""
        if not self._page:
            raise RuntimeError("Browser not launched.")

        try:
            await self._page.click(selector, timeout=10000)
            await self._page.wait_for_load_state("domcontentloaded", timeout=10000)

            # Auto-extract tokens after click
            await self._extract_tokens_from_page()

            return await self._get_page_state()
        except Exception as e:
            return {"error": str(e)}

    async def fill(self, selector: str, value: str) -> dict[str, Any]:
        """Fill a form field."""
        if not self._page:
            raise RuntimeError("Browser not launched.")
        try:
            await self._page.fill(selector, value, timeout=5000)
            return {"status": "filled", "selector": selector}
        except Exception as e:
            return {"error": str(e)}

    async def screenshot(self, name: str | None = None) -> str:
        """Take a screenshot. Returns path."""
        if not self._page:
            raise RuntimeError("Browser not launched.")

        path = f"hunt_output/screenshots/{name or int(time.time())}.png"
        await self._page.screenshot(path=path, full_page=True)
        self._screenshots.append({"path": path, "url": self._page.url, "time": time.time()})
        return path

    async def get_content(self) -> str:
        """Get full page HTML."""
        if not self._page:
            raise RuntimeError("Browser not launched.")
        return await self._page.content()

    async def get_text(self) -> str:
        """Get visible text content."""
        if not self._page:
            raise RuntimeError("Browser not launched.")
        return await self._page.inner_text("body")

    async def evaluate(self, expression: str) -> Any:
        """Execute JavaScript in the page context."""
        if not self._page:
            raise RuntimeError("Browser not launched.")
        return await self._page.evaluate(expression)

    # ============================================================
    # Token and state extraction
    # ============================================================

    async def _extract_tokens_from_page(self):
        """Extract all tokens from the current page state."""
        if not self._page:
            return

        try:
            # Extract localStorage
            self._tokens.localStorage = await self._page.evaluate(
                "() => { let items = {}; for (let i = 0; i < localStorage.length; i++) { "
                "let key = localStorage.key(i); items[key] = localStorage.getItem(key); } "
                "return items; }"
            )

            # Extract sessionStorage
            self._tokens.sessionStorage = await self._page.evaluate(
                "() => { let items = {}; for (let i = 0; i < sessionStorage.length; i++) { "
                "let key = sessionStorage.key(i); items[key] = sessionStorage.getItem(key); } "
                "return items; }"
            )

            # Extract cookies
            cookies = await self._context.cookies()
            self._tokens.cookies = {c["name"]: c["value"] for c in cookies}

            # Extract JWTs from localStorage/sessionStorage
            for storage in [self._tokens.localStorage, self._tokens.sessionStorage]:
                for key, value in storage.items():
                    key_lower = key.lower()
                    if any(p in key_lower for p in self._sensitive_patterns):
                        if len(value) > 100 and "." in value:
                            self._tokens.jwt_tokens.append(value)
                        elif "csrf" in key_lower:
                            self._tokens.csrf_tokens.append(value)

            # Extract CSRF tokens from DOM
            csrf_selectors = [
                'input[name="csrf_token"]',
                'input[name="_token"]',
                'input[name="csrfmiddlewaretoken"]',
                'meta[name="csrf-token"]',
                'meta[name="csrf_token"]',
            ]
            for selector in csrf_selectors:
                try:
                    element = await self._page.query_selector(selector)
                    if element:
                        token = await element.get_attribute("value") or await element.get_attribute("content")
                        if token:
                            self._tokens.csrf_tokens.append(token)
                except Exception:
                    pass

            self._tokens.timestamp = time.time()

        except Exception as e:
            pass  # Don't fail the hunt on token extraction errors

    async def get_tokens(self) -> TokenState:
        """Get current token state (auto-extracted)."""
        await self._extract_tokens_from_page()
        return self._tokens

    # ============================================================
    # Capture inspection (for the researcher)
    # ============================================================

    def get_captured_requests(self, limit: int = 50) -> list[dict]:
        """Get recent captured requests."""
        return [r.__dict__ for r in self._captured_requests[-limit:]]

    def get_api_endpoints(self) -> list[dict]:
        """Extract API endpoints from captured requests (non-page requests)."""
        seen = set()
        endpoints = []
        for req in self._captured_requests:
            if req.resource_type in ("xhr", "fetch", "graphql"):
                key = f"{req.method} {req.url}"
                if key not in seen:
                    seen.add(key)
                    endpoints.append({
                        "method": req.method,
                        "url": req.url,
                        "type": req.resource_type,
                        "has_body": req.post_data is not None,
                    })
        return endpoints

    async def get_all_links(self) -> list[str]:
        """Extract all links from the current page."""
        if not self._page:
            raise RuntimeError("Browser not launched.")
        return await self._page.evaluate(
            "() => Array.from(document.querySelectorAll('a[href]')).map(a => a.href)"
        )

    async def get_all_forms(self) -> list[dict]:
        """Extract all forms from the current page."""
        if not self._page:
            raise RuntimeError("Browser not launched.")
        return await self._page.evaluate("""
            () => Array.from(document.querySelectorAll('form')).map(f => ({
                action: f.action,
                method: f.method,
                fields: Array.from(f.querySelectorAll('input, select, textarea')).map(i => ({
                    name: i.name,
                    type: i.type || i.tagName.toLowerCase(),
                    value: i.value,
                    id: i.id,
                })),
            }))
        """)

    async def _get_page_state(self) -> dict[str, Any]:
        """Capture current page state."""
        if not self._page:
            return {}
        return {
            "url": self._page.url,
            "title": await self._page.title(),
            "content_length": len(await self._page.content()),
            "text_length": len(await self._page.inner_text("body")),
        }

    # ============================================================
    # Deterministic JS extraction (no LLM needed)
    # ============================================================

    async def extract_next_data(self) -> dict[str, Any]:
        """Extract __NEXT_DATA__ from Next.js apps. Returns routes, props, runtimeConfig."""
        if not self._page:
            raise RuntimeError("Browser not launched.")
        try:
            return await self._page.evaluate("""
                () => {
                    const el = document.getElementById('__NEXT_DATA__');
                    if (!el) return null;
                    try {
                        const data = JSON.parse(el.textContent);
                        const routes = [];
                        const props = data.props?.pageProps || {};
                        // Extract API base URL
                        const runtimeConfig = data.runtimeConfig || data.props?.pageProps?.runtimeConfig || {};
                        // Extract build routes
                        if (data.page) routes.push(data.page);
                        if (data.pages) routes.push(...data.pages);
                        return {
                            page: data.page,
                            buildId: data.buildId,
                            runtimeConfig: runtimeConfig,
                            propsKeys: Object.keys(props),
                            routes: routes,
                            raw: JSON.stringify(data).substring(0, 5000),
                        };
                    } catch(e) { return null; }
                }
            """)
        except Exception:
            return None

    async def extract_endpoints_from_js(self) -> list[dict]:
        """Extract API endpoints from page source, script tags, and inline JS."""
        if not self._page:
            raise RuntimeError("Browser not launched.")
        try:
            return await self._page.evaluate(r"""
                () => {
                    const endpoints = [];
                    const seen = new Set();

                    // 1. Extract from script src URLs
                    document.querySelectorAll('script[src]').forEach(s => {
                        const src = s.getAttribute('src') || '';
                        if (src.includes('chunk') || src.includes('main') || src.includes('app')) {
                            // These are webpack chunks - note them for later
                            endpoints.push({url: src, type: 'script', method: 'GET'});
                        }
                    });

                    // 2. Extract from inline scripts (fetch, axios, XMLHttpRequest patterns)
                    document.querySelectorAll('script:not([src])').forEach(s => {
                        const text = s.textContent || '';
                        // Match fetch('...') patterns
                        const fetchPattern = /fetch\s*\(\s*['"`]([^'"`]+)['"`]/g;
                        let m;
                        while ((m = fetchPattern.exec(text)) !== null) {
                            const url = m[1];
                            if (url.startsWith('/') && !seen.has(url)) {
                                seen.add(url);
                                endpoints.push({url: url, type: 'fetch', method: 'GET'});
                            }
                        }
                        // Match axios.get('...') / axios.post('...') patterns
                        const axiosPattern = /axios\s*\.\s*(get|post|put|patch|delete)\s*\(\s*['"`]([^'"`]+)['"`]/g;
                        while ((m = axiosPattern.exec(text)) !== null) {
                            const url = m[2];
                            if (url.startsWith('/') && !seen.has(url)) {
                                seen.add(url);
                                endpoints.push({url: url, type: 'axios', method: m[1].toUpperCase()});
                            }
                        }
                        // Match API base URLs
                        const apiPattern = /['"`](\/api\/[^'"`]+)['"`]/g;
                        while ((m = apiPattern.exec(text)) !== null) {
                            const url = m[1];
                            if (!seen.has(url)) {
                                seen.add(url);
                                endpoints.push({url: url, type: 'api_string', method: 'GET'});
                            }
                        }
                        // Match window.__ENV or process.env patterns
                        const envPattern = /(?:__ENV|process\.env)\s*\.\s*([A-Z_]+)/g;
                        while ((m = envPattern.exec(text)) !== null) {
                            endpoints.push({url: `env:${m[1]}`, type: 'env_var', method: 'GET'});
                        }
                    });

                    // 3. Extract from link[href] (API docs, swagger, etc.)
                    document.querySelectorAll('link[href]').forEach(l => {
                        const href = l.getAttribute('href') || '';
                        if (href.includes('swagger') || href.includes('api') || href.includes('graphql')) {
                            endpoints.push({url: href, type: 'link', method: 'GET'});
                        }
                    });

                    // 4. Extract from meta tags (og:url, etc.)
                    document.querySelectorAll('meta[property="og:url"], meta[name="api"]').forEach(m => {
                        const content = m.getAttribute('content') || '';
                        if (content.startsWith('/')) {
                            endpoints.push({url: content, type: 'meta', method: 'GET'});
                        }
                    });

                    return endpoints;
                }
            """)
        except Exception:
            return []

    async def extract_api_from_network_entries(self) -> list[dict]:
        """Extract API endpoints from performance.getEntriesByType('resource')."""
        if not self._page:
            raise RuntimeError("Browser not launched.")
        try:
            return await self._page.evaluate("""
                () => {
                    const entries = performance.getEntriesByType('resource');
                    const api = [];
                    const seen = new Set();
                    for (const e of entries) {
                        const name = e.name;
                        const type = e.initiatorType;
                        // Filter for API calls (xhr, fetch, graphql) or JSON responses
                        if (type === 'xhr' || type === 'fetch' || type === 'graphql' ||
                            name.includes('/api/') || name.includes('.json')) {
                            const url = new URL(name, window.location.origin);
                            const path = url.pathname;
                            if (!seen.has(path)) {
                                seen.add(path);
                                api.push({
                                    url: path,
                                    full_url: name,
                                    type: type,
                                    method: 'GET',
                                    duration: Math.round(e.duration),
                                    size: e.transferSize,
                                });
                            }
                        }
                    }
                    return api;
                }
            """)
        except Exception:
            return []

    async def extract_form_endpoints(self) -> list[dict]:
        """Extract all form action endpoints with their methods and fields."""
        if not self._page:
            raise RuntimeError("Browser not launched.")
        try:
            return await self._page.evaluate("""
                () => {
                    const forms = [];
                    document.querySelectorAll('form').forEach(f => {
                        const action = f.getAttribute('action') || window.location.pathname;
                        const method = (f.getAttribute('method') || 'GET').toUpperCase();
                        const fields = [];
                        f.querySelectorAll('input, select, textarea').forEach(i => {
                            fields.push({
                                name: i.name,
                                type: i.type || i.tagName.toLowerCase(),
                                value: i.value,
                                required: i.required,
                            });
                        });
                        forms.push({action, method, fields});
                    });
                    return forms;
                }
            """)
        except Exception:
            return []

    async def discover_admin_paths(self, base_url: str, timeout_ms: int = 5000) -> list[dict]:
        """Discover admin panels and hidden paths by probing common URLs."""
        if not self._page:
            raise RuntimeError("Browser not launched.")

        admin_paths = [
            "/admin", "/admin/", "/admin/login", "/admin/dashboard",
            "/administrator", "/administrator/login",
            "/wp-admin", "/wp-admin/login.php",
            "/phpmyadmin", "/phpMyAdmin",
            "/cpanel", "/cpanel/login",
            "/manager", "/manager/login",
            "/console", "/dashboard", "/panel",
            "/internal", "/internal/admin",
            "/debug", "/debug/vars", "/debug/pprof",
            "/actuator", "/actuator/health", "/actuator/env",
            "/swagger", "/swagger-ui.html", "/swagger-ui/",
            "/api-docs", "/openapi.json", "/openapi.yaml",
            "/graphql", "/graphiql",
            "/.env", "/config", "/config.json",
            "/backup", "/backups", "/dump",
            "/test", "/staging", "/dev",
            "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
            "/server-status", "/server-info",
            "/elmah.axd", "/trace.axd",
            "/solr/admin", "/mongo", "/adminer.php",
            "/cgi-bin", "/scripts",
            "/wp-login.php", "/xmlrpc.php",
            "/feed", "/rss",
        ]

        found = []
        base = base_url.rstrip("/")

        # Use fetch to check paths quickly without navigation
        try:
            results = await self._page.evaluate(f"""
                async () => {{
                    const paths = {json.dumps(admin_paths)};
                    const base = '{base}';
                    const results = [];
                    // Check in batches of 10 to avoid overwhelming
                    for (let i = 0; i < Math.min(paths.length, 30); i++) {{
                        try {{
                            const resp = await fetch(base + paths[i], {{
                                method: 'HEAD',
                                credentials: 'same-origin',
                                redirect: 'follow',
                            }});
                            results.push({{
                                path: paths[i],
                                status: resp.status,
                                redirected: resp.redirected,
                                final_url: resp.url,
                            }});
                        }} catch(e) {{
                            results.push({{path: paths[i], status: 0, error: e.message}});
                        }}
                    }}
                    return results;
                }}
            """)
            # Filter to interesting results (non-404, non-403)
            for r in results:
                if r.get("status") and r["status"] not in (0, 404, 403, 500, 502, 503):
                    found.append(r)
        except Exception:
            pass

        return found

    async def close(self):
        """Shut down the browser."""
        if self._page:
            await self._page.close()
        if self._context:
            await self._context.close()
        if self._browser:
            await self._browser.close()
        if self._playwright:
            await self._playwright.stop()
