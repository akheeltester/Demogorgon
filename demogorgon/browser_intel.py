"""Browser Intelligence Engine

The browser is the primary intelligence source.
Every page load, every click, every XHR becomes structured intelligence.

Extracts:
- DOM structure (buttons, forms, links, menus, modals)
- XHR/fetch requests (API endpoints, parameters, responses)
- JavaScript state (__NEXT_DATA__, __NUXT__, React, Redux, Apollo)
- Storage (localStorage, sessionStorage, cookies, IndexedDB)
- WebSocket connections
- GraphQL queries and schemas
- Feature flags, API base URLs, role names, permissions
- JWT tokens (parsed for claims, roles, permissions)

This is what a human sees when they open DevTools.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class UIElement:
    """A UI element discovered in the browser."""
    element_type: str  # button, form, link, input, select, modal, menu, tab
    text: str
    selector: str
    action: str = ""  # what clicking this does
    requires_auth: bool = False
    requires_role: str | None = None


@dataclass
class APIEndpoint:
    """An API endpoint discovered from browser traffic."""
    method: str
    url: str
    parameters: dict[str, Any] = field(default_factory=dict)
    response_schema: dict[str, Any] | None = None
    auth_required: bool = False
    rate_limited: bool = False
    source: str = ""  # xhr, fetch, graphql, form


@dataclass
class JSState:
    """JavaScript state extracted from the page."""
    framework: str = ""  # React, Vue, Angular, Next.js, Nuxt, Svelte
    next_data: dict[str, Any] | None = None  # __NEXT_DATA__
    nuxt_data: dict[str, Any] | None = None  # __NUXT__
    react_state: dict[str, Any] | None = None
    redux_state: dict[str, Any] | None = None
    apollo_cache: dict[str, Any] | None = None
    feature_flags: dict[str, bool] = field(default_factory=dict)
    api_base_urls: list[str] = field(default_factory=list)
    role_names: list[str] = field(default_factory=list)
    permission_strings: list[str] = field(default_factory=list)
    enum_values: dict[str, list[str]] = field(default_factory=dict)
    object_names: list[str] = field(default_factory=list)
    internal_ids: list[str] = field(default_factory=list)


@dataclass
class TokenInfo:
    """Parsed JWT token information."""
    header: dict[str, Any] = field(default_factory=dict)
    payload: dict[str, Any] = field(default_factory=dict)
    role: str | None = None
    user_id: str | None = None
    org_id: str | None = None
    exp: int | None = None
    issuer: str | None = None
    scopes: list[str] = field(default_factory=list)


class BrowserIntel:
    """Extracts structured intelligence from the browser.

    The browser is the primary sensor. Every interaction produces intelligence.
    """

    def __init__(self, browser_tool):
        self.browser = browser_tool
        self._ui_elements: list[UIElement] = []
        self._api_endpoints: list[APIEndpoint] = []
        self._js_state = JSState()
        self._tokens: list[TokenInfo] = []
        self._dom_structure: dict[str, Any] = {}
        self._navigation_path: list[str] = []
        self._screenshots: list[dict[str, Any]] = []

    async def full_scan(self) -> dict[str, Any]:
        """Perform a full intelligence scan of the current page."""
        results = {}

        # 1. DOM Structure
        results["dom"] = await self._scan_dom()

        # 2. UI Elements
        results["ui_elements"] = await self._scan_ui_elements()

        # 3. API Endpoints from network
        results["api_endpoints"] = self._scan_api_endpoints()

        # 4. JavaScript State
        results["js_state"] = await self._scan_js_state()

        # 5. Tokens
        results["tokens"] = await self._scan_tokens()

        # 6. Storage
        results["storage"] = await self._scan_storage()

        # 7. Forms
        results["forms"] = await self.browser.get_all_forms()

        # 8. Links
        results["links"] = await self.browser.get_all_links()

        # 9. Network requests
        results["network"] = self.browser.get_captured_requests(limit=200)

        # Take screenshot
        screenshot = await self.browser.screenshot()
        results["screenshot"] = screenshot

        return results

    async def _scan_dom(self) -> dict[str, Any]:
        """Scan DOM structure for UI elements."""
        if not self.browser._page:
            return {}

        return await self.browser._page.evaluate("""
            () => {
                const result = {
                    buttons: [],
                    forms: [],
                    inputs: [],
                    links: [],
                    modals: [],
                    menus: [],
                    tabs: [],
                    tables: [],
                    iframes: [],
                };

                // Buttons
                document.querySelectorAll('button, [role="button"], input[type="submit"]').forEach(el => {
                    result.buttons.push({
                        text: el.textContent?.trim()?.substring(0, 100) || '',
                        selector: el.id ? '#' + el.id : el.tagName.toLowerCase(),
                        disabled: el.disabled,
                        type: el.type || 'button',
                    });
                });

                // Forms
                document.querySelectorAll('form').forEach(el => {
                    result.forms.push({
                        action: el.action,
                        method: el.method,
                        fields: Array.from(el.querySelectorAll('input, select, textarea')).map(f => ({
                            name: f.name,
                            type: f.type || f.tagName.toLowerCase(),
                            placeholder: f.placeholder || '',
                            required: f.required,
                        })),
                    });
                });

                // Inputs
                document.querySelectorAll('input, select, textarea').forEach(el => {
                    result.inputs.push({
                        name: el.name,
                        type: el.type || el.tagName.toLowerCase(),
                        placeholder: el.placeholder || '',
                        value: el.value?.substring(0, 100) || '',
                    });
                });

                // Links
                document.querySelectorAll('a[href]').forEach(el => {
                    result.links.push({
                        text: el.textContent?.trim()?.substring(0, 100) || '',
                        href: el.href,
                    });
                });

                // Modals
                document.querySelectorAll('[role="dialog"], .modal, [class*="modal"]').forEach(el => {
                    result.modals.push({
                        visible: el.offsetParent !== null,
                        text: el.textContent?.trim()?.substring(0, 200) || '',
                    });
                });

                // Navigation menus
                document.querySelectorAll('nav, [role="navigation"], [class*="nav"], [class*="menu"]').forEach(el => {
                    result.menus.push({
                        text: el.textContent?.trim()?.substring(0, 200) || '',
                        links: Array.from(el.querySelectorAll('a')).map(a => a.href).slice(0, 20),
                    });
                });

                // Tabs
                document.querySelectorAll('[role="tab"], [class*="tab"]').forEach(el => {
                    result.tabs.push({
                        text: el.textContent?.trim()?.substring(0, 100) || '',
                        selected: el.getAttribute('aria-selected') === 'true',
                    });
                });

                // Tables
                document.querySelectorAll('table').forEach(el => {
                    const headers = Array.from(el.querySelectorAll('th')).map(th => th.textContent?.trim());
                    const rows = el.querySelectorAll('tr').length;
                    result.tables.push({ headers, rows });
                });

                // Iframes
                document.querySelectorAll('iframe').forEach(el => {
                    result.iframes.push({ src: el.src });
                });

                return result;
            }
        """)

    async def _scan_ui_elements(self) -> list[dict]:
        """Scan for interactive UI elements."""
        if not self.browser._page:
            return []

        elements = await self.browser._page.evaluate("""
            () => {
                const elements = [];
                const interactive = document.querySelectorAll(
                    'button, a, input, select, textarea, [role="button"], [role="link"], [role="tab"], [role="menuitem"]'
                );

                interactive.forEach(el => {
                    const rect = el.getBoundingClientRect();
                    if (rect.width > 0 && rect.height > 0) {
                        elements.push({
                            tag: el.tagName.toLowerCase(),
                            text: el.textContent?.trim()?.substring(0, 100) || '',
                            type: el.type || '',
                            name: el.name || '',
                            href: el.href || '',
                            selector: el.id ? '#' + el.id : '',
                            visible: rect.width > 0 && rect.height > 0,
                            position: { x: rect.x, y: rect.y, width: rect.width, height: rect.height },
                        });
                    }
                });

                return elements;
            }
        """)
        return elements

    def _scan_api_endpoints(self) -> list[dict]:
        """Extract API endpoints from captured browser requests."""
        if not self.browser:
            return []

        requests = self.browser.get_captured_requests(limit=200)
        endpoints = []
        seen = set()

        for req in requests:
            if req.get("resource_type") in ("xhr", "fetch", "graphql"):
                key = f"{req.get('method', 'GET')} {req.get('url', '')}"
                if key not in seen:
                    seen.add(key)
                    endpoints.append({
                        "method": req.get("method", "GET"),
                        "url": req.get("url", ""),
                        "type": req.get("resource_type", ""),
                        "has_body": req.get("post_data") is not None,
                        "headers": req.get("headers", {}),
                    })

        return endpoints

    async def _scan_js_state(self) -> dict[str, Any]:
        """Extract JavaScript state from the page."""
        if not self.browser._page:
            return {}

        return await self.browser._page.evaluate("""
            () => {
                const state = {
                    framework: 'unknown',
                    next_data: null,
                    nuxt_data: null,
                    react_state: null,
                    redux_state: null,
                    feature_flags: {},
                    api_base_urls: [],
                    role_names: [],
                    permission_strings: [],
                    enum_values: {},
                    object_names: [],
                    internal_ids: [],
                };

                // Detect framework
                if (window.__NEXT_DATA__) {
                    state.framework = 'next.js';
                    state.next_data = window.__NEXT_DATA__;
                } else if (window.__NUXT__) {
                    state.framework = 'nuxt';
                    state.nuxt_data = window.__NUXT__;
                } else if (window.__REACT_DEVTOOLS_GLOBAL_HOOK__) {
                    state.framework = 'react';
                } else if (window.Vue) {
                    state.framework = 'vue';
                } else if (window.ng) {
                    state.framework = 'angular';
                }

                // Extract from __NEXT_DATA__
                if (state.next_data) {
                    try {
                        const props = state.next_data.props?.pageProps;
                        if (props) {
                            // Look for API base URLs
                            const jsonStr = JSON.stringify(props);
                            const urlMatches = jsonStr.match(/https?:\/\/[^\s"]+/g);
                            if (urlMatches) {
                                state.api_base_urls = [...new Set(urlMatches)].slice(0, 10);
                            }
                        }
                    } catch(e) {}
                }

                // Look for feature flags
                const flagPatterns = ['feature', 'flag', 'toggle', 'experiment', 'variant'];
                for (const key of Object.keys(window)) {
                    if (flagPatterns.some(p => key.toLowerCase().includes(p))) {
                        try {
                            state.feature_flags[key] = window[key];
                        } catch(e) {}
                    }
                }

                // Look for role/permission patterns in page source
                const bodyText = document.body?.innerText || '';
                const rolePatterns = ['admin', 'user', 'seller', 'buyer', 'moderator', 'editor', 'viewer', 'owner', 'member'];
                for (const role of rolePatterns) {
                    if (bodyText.toLowerCase().includes(role)) {
                        state.role_names.push(role);
                    }
                }

                // Look for API patterns in scripts
                document.querySelectorAll('script').forEach(script => {
                    const text = script.textContent || '';
                    // API base URLs
                    const apiMatches = text.match(/["'](https?:\/\/api\.[^\s"']+)/g);
                    if (apiMatches) {
                        state.api_base_urls.push(...apiMatches.map(m => m.slice(1, -1)));
                    }
                    // Internal IDs
                    const idMatches = text.match(/["']([a-f0-9]{24})["']/g);
                    if (idMatches) {
                        state.internal_ids.push(...idMatches.map(m => m.slice(1, -1)).slice(0, 10));
                    }
                });

                state.api_base_urls = [...new Set(state.api_base_urls)].slice(0, 20);
                state.role_names = [...new Set(state.role_names)];
                state.internal_ids = [...new Set(state.internal_ids)].slice(0, 20);

                return state;
            }
        """)

    async def _scan_tokens(self) -> list[dict]:
        """Parse JWT tokens and extract claims."""
        tokens = await self.browser.get_tokens()
        parsed = []

        for jwt in tokens.jwt_tokens:
            try:
                # Split JWT
                parts = jwt.split(".")
                if len(parts) == 3:
                    # Decode payload (base64url)
                    import base64
                    payload = parts[1] + "=" * (4 - len(parts[1]) % 4)
                    decoded = json.loads(base64.urlsafe_b64decode(payload))

                    parsed.append({
                        "header": json.loads(parts[0] + "=" * (4 - len(parts[0]) % 4)),
                        "payload": decoded,
                        "role": decoded.get("role") or decoded.get("roles") or decoded.get("permission"),
                        "user_id": decoded.get("sub") or decoded.get("user_id") or decoded.get("userId"),
                        "org_id": decoded.get("org_id") or decoded.get("organizationId"),
                        "exp": decoded.get("exp"),
                        "iss": decoded.get("iss"),
                    })
            except Exception:
                pass

        return parsed

    async def _scan_storage(self) -> dict[str, Any]:
        """Scan all storage for interesting data."""
        tokens = await self.browser.get_tokens()

        interesting = {}
        for key, value in {**tokens.localStorage, **tokens.sessionStorage}.items():
            # Look for tokens, IDs, configs
            if any(p in key.lower() for p in ["token", "jwt", "auth", "user", "session", "config", "feature"]):
                interesting[key] = value[:200] if len(value) > 200 else value

        return {
            "cookies": tokens.cookies,
            "csrf_tokens": tokens.csrf_tokens,
            "jwt_tokens": tokens.jwt_tokens,
            "interesting_storage": interesting,
        }

    def get_summary(self) -> str:
        """Get a summary of all discovered intelligence."""
        lines = []

        if self._api_endpoints:
            lines.append(f"API ENDPOINTS ({len(self._api_endpoints)}):")
            for ep in self._api_endpoints[:10]:
                lines.append(f"  {ep.get('method', 'GET')} {ep.get('url', '')}")

        if self._js_state.framework != "unknown":
            lines.append(f"FRAMEWORK: {self._js_state.framework}")

        if self._tokens:
            lines.append(f"TOKENS: {len(self._tokens)} JWTs parsed")
            for t in self._tokens[:3]:
                lines.append(f"  role={t.role}, user={t.user_id}, org={t.org_id}")

        return "\n".join(lines) if lines else "No intelligence yet"
