"""Knowledge Base — stores and retrieves past hunt patterns.

Remembers what worked on previous targets and applies that knowledge to new ones.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class TechPattern:
    tech_stack: str
    common_vulns: list[str]
    endpoints_to_check: list[str]
    bypass_techniques: list[str]
    description: str = ""
    confidence: float = 0.8

    def to_dict(self) -> dict:
        return {
            "tech_stack": self.tech_stack,
            "common_vulns": self.common_vulns,
            "endpoints_to_check": self.endpoints_to_check,
            "bypass_techniques": self.bypass_techniques,
            "description": self.description,
            "confidence": self.confidence,
        }


@dataclass
class HuntResult:
    target: str
    findings_count: int
    vuln_classes: list[str]
    endpoints_scanned: int
    tools_used: list[str]
    key_lessons: list[str]
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "findings_count": self.findings_count,
            "vuln_classes": self.vuln_classes,
            "endpoints_scanned": self.endpoints_scanned,
            "tools_used": self.tools_used,
            "key_lessons": self.key_lessons,
            "timestamp": self.timestamp,
        }


PATTERN_LIBRARY: dict[str, TechPattern] = {
    "nextjs": TechPattern(
        tech_stack="Next.js",
        common_vulns=[
            "ssrf_via_getServerSideProps",
            "open_redirect_via_next_router",
            "server_side_request_forgery",
            "exposed_api_routes",
            "sensitive_data_in_props",
            "path_traversal_via_dynamic_routes",
            "cors_misconfiguration",
        ],
        endpoints_to_check=[
            "/api/", "/_next/data/", "/_next/static/", "/api/auth/",
            "/api/health", "/api/admin/", "/.env", "/robots.txt",
            "/sitemap.xml", "/manifest.json", "/_next/", "/api/v1/",
        ],
        bypass_techniques=[
            "double_encoding_%252e%252e",
            "null_byte_%00",
            "unicode_encoding_%c0%ae%c0%ae",
            "backslash_instead_of_slash",
            "protocol_abuse_file://",
            "host_header_injection",
        ],
        description="Next.js applications have server-side rendering, API routes, and client-side data fetching",
    ),
    "shopify": TechPattern(
        tech_stack="Shopify",
        common_vulns=[
            "graphql_introspection",
            "storefront_api_abuse",
            "admin_api_access",
            "theme_asset_injection",
            "webhook_abuse",
            "discount_code_enumeration",
            "customer_data_exposure",
        ],
        endpoints_to_check=[
            "/graphql", "/admin/api/", "/storefront/api/", "/cart/",
            "/checkout/", "/account/", "/meta.json", "/admin/",
            "/api/2024-01/", "/webhooks/", "/pages/", "/collections/",
        ],
        bypass_techniques=[
            "graphql_introspection_query",
            "storefront_api_token_abuse",
            "pagination_abuse",
            "rate_limit_bypass",
            "admin_api_token_leak",
        ],
        description="Shopify stores have GraphQL APIs, Storefront API, Admin API, and theme customization",
    ),
    "keycloak": TechPattern(
        tech_stack="Keycloak",
        common_vulns=[
            "jwt_algorithm_confusion",
            "token_exchange_abuse",
            "user_impersonation",
            "admin_console_access",
            "session_fixation",
            "open_redirect_via_callback",
            "saml_bypass",
        ],
        endpoints_to_check=[
            "/auth/realms/", "/auth/admin/", "/auth/realms/master/",
            "/auth/realms/master/protocol/openid-connect/certs",
            "/auth/realms/master/account/",
        ],
        bypass_techniques=[
            "jwt_alg_none_attack",
            "realm_manipulation",
            "client_id_confusion",
            "token_exchange_chain",
            "saml_comment_injection",
        ],
        description="Keycloak identity and access management with SAML, OIDC, JWT tokens",
    ),
    "express": TechPattern(
        tech_stack="Express.js",
        common_vulns=[
            "prototype_pollution",
            "rce_via_child_process",
            "ssti_via_template_engines",
            "cors_misconfiguration",
            "rate_limit_bypass",
            "path_traversal",
            "ssrf_via_http_module",
        ],
        endpoints_to_check=[
            "/api/", "/api/v1/", "/api/v2/", "/graphql",
            "/admin/", "/health", "/status", "/debug/",
            "/.env", "/package.json", "/node_modules/",
        ],
        bypass_techniques=[
            "path_traversal_dot_dot_slash",
            "prototype_pollution___proto__",
            "ssti_double_braces",
            "cors_wildcard_reflection",
            "rate_limit_x_forwarded_for",
        ],
        description="Express.js applications with middleware chains and dynamic routing",
    ),
    "react_spa": TechPattern(
        tech_stack="React SPA",
        common_vulns=[
            "xss_via_dangerouslySetInnerHTML",
            "client_side_storage_misuse",
            "jwt_exposed_in_localstorage",
            "cors_misconfiguration",
            "api_endpoint_exposure",
            "missing_server_side_validation",
            "insecure_direct_object_reference",
        ],
        endpoints_to_check=[
            "/api/", "/graphql", "/static/js/",
            "/manifest.json", "/service-worker.js",
            "/api/health", "/api/config",
        ],
        bypass_techniques=[
            "dangerouslySetInnerHTML_xss",
            "prototype_pollution_react_state",
            "localstorage_jwt_theft",
            "cors_origin_reflection",
            "api_enumeration_via_js",
        ],
        description="React single-page applications with client-side routing and API consumption",
    ),
    "django": TechPattern(
        tech_stack="Django",
        common_vulns=[
            "ssrf_via_urllib",
            "sql_injection_via_orm",
            "template_injection",
            "cst_middleware_bypass",
            "admin_panel_access",
            "csrf_token_leakage",
            "path_traversal_via_file_upload",
        ],
        endpoints_to_check=[
            "/admin/", "/api/", "/static/", "/media/",
            "/graphql", "/health/", "/debug/",
            "/robots.txt", "/sitemap.xml",
        ],
        bypass_techniques=[
            "ssrf_127.0.0.1",
            "sqli_time_based",
            "ssti_django_template",
            "csrf_double_submit",
            "path_traversal_null_byte",
        ],
        description="Django applications with ORM, admin panel, and template engine",
    ),
    "laravel": TechPattern(
        tech_stack="Laravel",
        common_vulns=[
            "ssti_via_blade",
            "sql_injection_via_query_builder",
            "rce_via_deserialization",
            "debug_mode_exposure",
            "env_file_exposure",
            "mass_assignment",
            "open_redirect_via_redirect",
        ],
        endpoints_to_check=[
            "/api/", "/admin/", "/.env", "/storage/",
            "/telescope/", "/horizon/", "/graphql",
            "/api/v1/", "/debug/",
        ],
        bypass_techniques=[
            "ssti_blade_double_braces",
            "deserialization_pop_chain",
            "debug_mode_rce",
            "env_file_direct_access",
            "mass_assignment_role_field",
        ],
        description="Laravel applications with Blade templates, Eloquent ORM, and Artisan CLI",
    ),
}


class KnowledgeBase:
    """Stores and retrieves past hunt patterns."""

    def __init__(self, persistence_path: str | Path | None = None):
        self.patterns = dict(PATTERN_LIBRARY)
        self.hunt_history: list[HuntResult] = []
        self.persistence_path = Path(persistence_path) if persistence_path else None
        if self.persistence_path and self.persistence_path.exists():
            self._load()

    def _load(self) -> None:
        if not self.persistence_path or not self.persistence_path.exists():
            return
        try:
            data = json.loads(self.persistence_path.read_text())
            for h in data.get("history", []):
                self.hunt_history.append(HuntResult(**h))
            for name, p in data.get("patterns", {}).items():
                if name not in self.patterns:
                    self.patterns[name] = TechPattern(**p)
        except Exception:
            pass

    def _save(self) -> None:
        if not self.persistence_path:
            return
        self.persistence_path.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "history": [h.to_dict() for h in self.hunt_history[-100:]],
            "patterns": {k: v.to_dict() for k, v in self.patterns.items()},
        }
        self.persistence_path.write_text(json.dumps(data, indent=2))

    def detect_stack(self, headers: dict[str, str], body: str, url: str = "") -> list[str]:
        detected = []
        server = headers.get("server", "").lower()
        powered_by = headers.get("x-powered-by", "").lower()
        body_lower = body.lower()

        if "next" in server or "__next" in body or "_next/static" in body:
            detected.append("nextjs")
        if "shopify" in server or "shopify" in body_lower:
            detected.append("shopify")
        if "keycloak" in server or "keycloak" in body_lower or "/auth/realms/" in body:
            detected.append("keycloak")
        if "express" in powered_by or "x-express" in server:
            detected.append("express")
        if "react" in body_lower or "reactroot" in body_lower or "_react" in body_lower:
            detected.append("react_spa")
        if "django" in server or "csrfmiddlewaretoken" in body_lower:
            detected.append("django")
        if "laravel" in server or "laravel_session" in str(headers):
            detected.append("laravel")

        return detected

    def get_patterns_for_stack(self, stack: list[str]) -> list[TechPattern]:
        return [self.patterns[s] for s in stack if s in self.patterns]

    def get_attack_plan(self, stack: list[str]) -> dict[str, Any]:
        plan: dict[str, Any] = {
            "stacks": stack,
            "common_vulns": [],
            "endpoints_to_check": [],
            "bypass_techniques": [],
            "recommended_tools": [],
        }
        for pattern in self.get_patterns_for_stack(stack):
            plan["common_vulns"].extend(pattern.common_vulns)
            plan["endpoints_to_check"].extend(pattern.endpoints_to_check)
            plan["bypass_techniques"].extend(pattern.bypass_techniques)
        plan["common_vulns"] = list(dict.fromkeys(plan["common_vulns"]))
        plan["endpoints_to_check"] = list(dict.fromkeys(plan["endpoints_to_check"]))
        plan["bypass_techniques"] = list(dict.fromkeys(plan["bypass_techniques"]))
        plan["recommended_tools"] = self._recommend_tools(stack)
        return plan

    def _recommend_tools(self, stack: list[str]) -> list[str]:
        tools = ["nuclei", "ffuf", "katana"]
        if "shopify" in stack or "graphql" in str(stack):
            tools.append("graphql-cop")
        if "keycloak" in stack:
            tools.extend(["jwt_tool", "socat"])
        if "react_spa" in stack or "nextjs" in stack:
            tools.extend(["browser", "katana"])
        return list(dict.fromkeys(tools))

    def record_hunt(self, result: HuntResult) -> None:
        self.hunt_history.append(result)
        self._save()

    def get_lessons_learned(self, stack: list[str]) -> list[str]:
        lessons = []
        for h in self.hunt_history:
            for lesson in h.key_lessons:
                lessons.append(lesson)
        return list(dict.fromkeys(lessons))[-10:]

    def to_dict(self) -> dict:
        return {
            "patterns": {k: v.to_dict() for k, v in self.patterns.items()},
            "history": [h.to_dict() for h in self.hunt_history[-20:]],
        }
