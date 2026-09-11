"""
VK Bug Bounty Program — Scope, Exclusions & Tier Configuration
==============================================================
Reference: https://vk.com/bugbounty (last verified 2024-12)

Usage:
    from demogorgon.programs.vk.scope import VKScope
    scope = VKScope()
    scope.in_scope("id.vk.com")          # True
    scope.tier("id.vk.com")              # 1
    scope.is_excluded("vk.com/ads")      # True
    scope.allowed_vuln_type("IDOR")      # True
    scope.allowed_vuln_type("Logout CSRF") # False
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
from urllib.parse import urlparse


class VKTier(Enum):
    """Bounty tier mapping. Higher tier = higher payout potential."""
    TIER_1_VK_ID = 1          # Highest bounty — VK ID (SSO Engine)
    TIER_2_VK_COM = 2         # High bounty — VK.com core
    TIER_3_SUBDOMAINS = 3     # Standard — Mobile & subdomains
    TIER_4_NATIVE = 4         # Native apps (iOS/Android)
    OUT_OF_SCOPE = 0


class VKVulnCategory(Enum):
    """Maps to VK's Maximum Bounty Table categories."""
    ACCOUNT_TAKEOVER = "account_takeover"
    RCE = "rce"
    CROSS_SERVICE_ACCESS = "cross_service_access"
    PRIVATE_MESSAGE_READ = "private_message_reading"
    SQL_INJECTION = "sql_injection"
    SSRF = "ssrf"
    XSS = "xss"
    IDOR = "idor"
    CSRF = "csrf"
    AUTH_BYPASS = "auth_bypass"
    FILE_UPLOAD = "file_upload"
    OPEN_REDIRECT = "open_redirect"
    INFO_DISCLOSURE = "info_disclosure"
    BUSINESS_LOGIC = "business_logic"
    OTHER = "other"


# ─── Maximum Bounty Matrix (VK official) ──────────────────────────────────────
VK_BOUNTY_MATRIX: dict[VKVulnCategory, dict] = {
    VKVulnCategory.ACCOUNT_TAKEOVER: {"max_bounty": "MAX", "description": "Full account takeover without user interaction"},
    VKVulnCategory.RCE: {"max_bounty": "MAX", "description": "Remote code execution on any VK server"},
    VKVulnCategory.CROSS_SERVICE_ACCESS: {"max_bounty": "MAX", "description": "Access to VK internal services/APIs from external"},
    VKVulnCategory.PRIVATE_MESSAGE_READ: {"max_bounty": "MAX", "description": "Reading private messages of any user"},
    VKVulnCategory.SQL_INJECTION: {"max_bounty": "HIGH", "description": "SQL injection with data exfiltration"},
    VKVulnCategory.SSRF: {"max_bounty": "HIGH", "description": "Server-side request forgery hitting internal services"},
    VKVulnCategory.XSS: {"max_bounty": "MEDIUM", "description": "Reflected/Stored XSS with cookie theft or action hijacking"},
    VKVulnCategory.IDOR: {"max_bounty": "MEDIUM", "description": "Accessing other users' private data via ID manipulation"},
    VKVulnCategory.CSRF: {"max_bounty": "MEDIUM", "description": "State-changing actions without CSRF protection"},
    VKVulnCategory.AUTH_BYPASS: {"max_bounty": "HIGH", "description": "Bypassing authentication or authorization checks"},
    VKVulnCategory.FILE_UPLOAD: {"max_bounty": "HIGH", "description": "Uploading executable files to VK servers"},
    VKVulnCategory.OPEN_REDIRECT: {"max_bounty": "LOW", "description": "Open redirect (only with session token theft PoC)"},
    VKVulnCategory.INFO_DISCLOSURE: {"max_bounty": "LOW", "description": "Sensitive info disclosure beyond version numbers"},
    VKVulnCategory.BUSINESS_LOGIC: {"max_bounty": "MEDIUM", "description": "Business logic flaws with financial impact"},
}


@dataclass
class VKScope:
    """VK Bug Bounty scope definition and assessment engine."""

    # ─── Tier 1: VK ID (SSO Engine) — Highest Bounty ────────────────────────
    tier1_domains: list[str] = field(default_factory=lambda: [
        "id.vk.com",
        "id.mail.ru",           # Same SSO infrastructure
        "login.vk.com",         # VK ID login endpoint
        "oauth.vk.com",         # OAuth 2.0 endpoint
    ])

    # ─── Tier 2: VK.com Core — High Bounty ──────────────────────────────────
    tier2_domains: list[str] = field(default_factory=lambda: [
        "vk.com",
        "m.vk.com",             # Mobile web
        "api.vk.com",           # Official API
        "vk.com/api",           # API documentation
    ])

    # ─── Tier 3: Mobile & Subdomains — Standard Scope ────────────────────────
    tier3_domains: list[str] = field(default_factory=lambda: [
        "*.vk.cc",              # Short URLs
        "*.vk.link",            # Link service
        "dev.vk.com",           # Developer portal
        "platform.vk.com",      # Platform API
        "store.vk.com",         # App store
        "vkvideo.ru",           # Video platform
    ])

    # ─── Tier 4: Native Apps ────────────────────────────────────────────────
    tier4_apps: list[str] = field(default_factory=lambda: [
        "VK App (iOS/Android)",
        "VK Me (iOS/Android)",
        "VK Admin (iOS/Android)",
        "VK Messenger (iOS/Android)",
    ])

    # ─── Explicit Exclusions (NO BOUNTY) ─────────────────────────────────────
    excluded_paths: list[str] = field(default_factory=lambda: [
        "vk.com/ads",               # Advertising — Informational / Unpaid
        "vk.com/ads/*",             # All ad-related paths
        "/away.php",                # Redirect endpoint (unless full session theft)
        "vk.com/legal",             # Legal pages
        "vk.com/terms",             # Terms of service
        "vk.com/privacy",           # Privacy policy
        "vk.com/brands",            # Brand pages
    ])

    excluded_domains: list[str] = field(default_factory=lambda: [
        "*.smailru.net",            # Dedicated proxy SSRF
        "*.go.mail.ru",             # Mail proxy
        "proxy.oneme.ru",           # Proxy service
        "mail.ru",                  # Mail domain (separate program)
        "*.mail.ru",                # All Mail subdomains
        "ok.ru",                    # Odnoklassniki (separate)
    ])

    # ─── Excluded Vulnerability Types (NO BOUNTY) ────────────────────────────
    excluded_vuln_types: list[str] = field(default_factory=lambda: [
        "Logout CSRF",
        "DoS",
        "Denial of Service",
        "Flooding",
        "User Account Enumeration",       # Without password access
        "EXIF Data Exposure",
        "Version Number Disclosure",      # e.g. "X-Powered-By: Express 4.18.2"
        "Internal IP Address Disclosure",
        "Source Map Exposure",
        "SPF/DMARC Policy Disclosure",
        "Local Path Disclosure",
        "Generic Open Redirect via away.php",  # Unless full token theft
        "SSL/TLS Weak Cipher",            # Generic
        "Missing Security Headers",       # Generic
        "Clickjacking",                   # On non-sensitive pages
        "Self-XSS",                       # Only affects the reporter
        "Scanner-generated Reports",      # Automated/AI without manual proof
    ])

    # ─── Vulnerability Types with MAXIMUM BOUNTY ─────────────────────────────
    max_bounty_vulns: list[str] = field(default_factory=lambda: [
        "Account Takeover",
        "Remote Code Execution",
        "Cross-service Access",
        "Private Message Reading",
        "SQL Injection with Data Exfiltration",
    ])

    # ─── PoC Requirements ────────────────────────────────────────────────────
    poc_minimal_commands: list[str] = field(default_factory=lambda: [
        "sleep 10",                     # Time-based blind
        "cat /etc/passwd",              # File read
        "curl http://attacker.com",     # Outbound request
        "id",                           # Current user
        "whoami",                       # Current user
    ])

    # ─── Evidence Requirements ───────────────────────────────────────────────
    evidence_requirements: dict[str, str] = field(default_factory=lambda: {
        "screenshot": "Clear screenshot of the vulnerability in action",
        "video": "Screen recording showing full reproduction steps (preferred for complex chains)",
        "request_response": "Raw HTTP request and response (redact tokens)",
        "curl_command": "Minimal curl command that reproduces the issue",
        "impact_demonstration": "Proof of impact (e.g., leaked data, account access)",
    })

    def normalize_domain(self, url: str) -> str:
        """Extract normalized domain from URL or raw domain string."""
        if "://" in url:
            parsed = urlparse(url)
            return parsed.hostname or ""
        return url.lower().strip().rstrip("/")

    def normalize_path(self, url: str) -> str:
        """Extract path from URL."""
        if "://" in url:
            parsed = urlparse(url)
            return parsed.path
        return url

    def tier(self, target: str) -> VKTier:
        """Determine bounty tier for a target domain/path."""
        domain = self.normalize_domain(target)
        path = self.normalize_path(target)

        # Check tier 1 (VK ID)
        for t1 in self.tier1_domains:
            if t1.startswith("*."):
                suffix = t1[1:]  # .vk.com
                if domain.endswith(suffix):
                    return VKTier.TIER_1_VK_ID
            elif domain == t1:
                return VKTier.TIER_1_VK_ID

        # Check tier 2 (VK.com)
        for t2 in self.tier2_domains:
            if t2.startswith("*."):
                suffix = t2[1:]
                if domain.endswith(suffix):
                    return VKTier.TIER_2_VK_COM
            elif domain == t2:
                return VKTier.TIER_2_VK_COM

        # Check tier 3 (Subdomains)
        for t3 in self.tier3_domains:
            if t3.startswith("*."):
                suffix = t3[1:]  # .vk.cc
                if domain.endswith(suffix):
                    return VKTier.TIER_3_SUBDOMAINS
            elif domain == t3:
                return VKTier.TIER_3_SUBDOMAINS

        # Check tier 4 (Apps)
        for t4 in self.tier4_apps:
            if t4.lower() in target.lower():
                return VKTier.TIER_4_NATIVE

        return VKTier.OUT_OF_SCOPE

    def in_scope(self, target: str) -> bool:
        """Check if a target is in VK's bug bounty scope."""
        return self.tier(target) != VKTier.OUT_OF_SCOPE

    def is_excluded(self, target: str) -> bool:
        """Check if a target/path is explicitly excluded from bounty."""
        domain = self.normalize_domain(target)
        path = self.normalize_path(target)

        # Check excluded domains
        for excl in self.excluded_domains:
            if excl.startswith("*."):
                suffix = excl[1:]
                if domain.endswith(suffix):
                    return True
            elif domain == excl:
                return True

        # Check excluded paths
        for excl in self.excluded_paths:
            if excl.startswith("*"):
                if path.endswith(excl[1:]):
                    return True
            elif path == excl or path.startswith(excl + "/"):
                return True

        return False

    def allowed_vuln_type(self, vuln_type: str) -> bool:
        """Check if a vulnerability type is eligible for bounty."""
        return vuln_type not in self.excluded_vuln_types

    def is_max_bounty(self, vuln_type: str) -> bool:
        """Check if a vulnerability type qualifies for maximum bounty."""
        return vuln_type in self.max_bounty_vulns

    def bounty_category(self, vuln_type: str) -> Optional[VKVulnCategory]:
        """Map a vuln type string to VK's bounty category enum."""
        mapping = {
            "Account Takeover": VKVulnCategory.ACCOUNT_TAKEOVER,
            "Remote Code Execution": VKVulnCategory.RCE,
            "RCE": VKVulnCategory.RCE,
            "Cross-service Access": VKVulnCategory.CROSS_SERVICE_ACCESS,
            "Private Message Reading": VKVulnCategory.PRIVATE_MESSAGE_READ,
            "SQL Injection": VKVulnCategory.SQL_INJECTION,
            "SSRF": VKVulnCategory.SSRF,
            "XSS": VKVulnCategory.XSS,
            "Reflected XSS": VKVulnCategory.XSS,
            "Stored XSS": VKVulnCategory.XSS,
            "DOM XSS": VKVulnCategory.XSS,
            "IDOR": VKVulnCategory.IDOR,
            "CSRF": VKVulnCategory.CSRF,
            "Auth Bypass": VKVulnCategory.AUTH_BYPASS,
            "Authorization Bypass": VKVulnCategory.AUTH_BYPASS,
            "File Upload": VKVulnCategory.FILE_UPLOAD,
            "Open Redirect": VKVulnCategory.OPEN_REDIRECT,
            "Information Disclosure": VKVulnCategory.INFO_DISCLOSURE,
            "Business Logic": VKVulnCategory.BUSINESS_LOGIC,
        }
        return mapping.get(vuln_type)

    def assess_finding(self, target: str, vuln_type: str) -> dict:
        """
        Full assessment of a finding against VK's scope and rules.
        Returns a verdict with recommendation.
        """
        domain = self.normalize_domain(target)
        vk_tier = self.tier(target)
        excluded = self.is_excluded(target)
        allowed_vuln = self.allowed_vuln_type(vuln_type)
        category = self.bounty_category(vuln_type)
        max_bounty = self.is_max_bounty(vuln_type)

        verdict = {
            "target": target,
            "domain": domain,
            "vuln_type": vuln_type,
            "vk_tier": vk_tier.name if vk_tier != VKTier.OUT_OF_SCOPE else "OUT_OF_SCOPE",
            "in_scope": self.in_scope(target),
            "is_excluded": excluded,
            "vuln_allowed": allowed_vuln,
            "bounty_category": category.value if category else "unknown",
            "max_bounty_qualifies": max_bounty,
            "eligible": False,
            "rejection_reasons": [],
        }

        # Determine eligibility
        if not verdict["in_scope"]:
            verdict["rejection_reasons"].append(f"Target {domain} is out of VK's bug bounty scope")
        if excluded:
            verdict["rejection_reasons"].append(f"Target/path is explicitly excluded from bounty")
        if not allowed_vuln:
            verdict["rejection_reasons"].append(f'"{vuln_type}" is excluded from VK bounty — will NOT be paid')

        verdict["eligible"] = (
            verdict["in_scope"]
            and not excluded
            and allowed_vuln
        )

        # Add tier-specific guidance
        if vk_tier == VKTier.TIER_1_VK_ID:
            verdict["guidance"] = (
                "MAXIMUM BOUNTY POTENTIAL. VK ID is the SSO engine. "
                "Focus on: auth bypass, OAuth token leakage, account takeover chains, "
                "cross-service access via SSO token. "
                "A full ATO chain here impacts ALL VK services."
            )
        elif vk_tier == VKTier.TIER_2_VK_COM:
            verdict["guidance"] = (
                "HIGH BOUNTY POTENTIAL. Focus on: IDOR on user data, "
                "stored XSS in messaging, SSRF via API, business logic flaws. "
                "Private message reading = MAX bounty."
            )
        elif vk_tier == VKTier.TIER_3_SUBDOMAINS:
            verdict["guidance"] = (
                "STANDARD BOUNTY. Focus on: subdomain takeover, "
                "API misconfig, developer portal access. "
                "Lower payout but easier to find bugs."
            )
        elif vk_tier == VKTier.TIER_4_NATIVE:
            verdict["guidance"] = (
                "NATIVE APP scope. Focus on: deeplink hijacking, "
                "insecure storage, certificate pinning bypass, "
                "inter-process communication flaws."
            )
        else:
            verdict["guidance"] = "Target is out of scope. Do not submit."

        return verdict

    def filter_findings(self, findings: list[dict]) -> dict:
        """
        Filter a list of findings against VK scope.
        Returns dict with 'eligible', 'excluded', 'out_of_scope' lists.
        """
        eligible = []
        excluded = []
        out_of_scope = []

        for f in findings:
            target = f.get("target", "")
            vuln_type = f.get("vuln_type", f.get("type", "other"))
            assessment = self.assess_finding(target, vuln_type)

            if assessment["eligible"]:
                eligible.append({**f, "vk_assessment": assessment})
            elif assessment["is_excluded"]:
                excluded.append({**f, "vk_assessment": assessment})
            else:
                out_of_scope.append({**f, "vk_assessment": assessment})

        return {
            "eligible": eligible,
            "excluded": excluded,
            "out_of_scope": out_of_scope,
            "summary": {
                "total": len(findings),
                "eligible": len(eligible),
                "excluded": len(excluded),
                "out_of_scope": len(out_of_scope),
            },
        }

    def poc_is_minimal(self, poc: str) -> tuple[bool, str]:
        """
        Validate that a PoC uses minimal commands per VK guidelines.
        Returns (is_valid, reason).
        """
        poc_lower = poc.lower().strip()

        # Check for overly complex PoCs
        red_flags = [
            ("import ", "Script imports not allowed — use minimal commands"),
            ("require(", "Script imports not allowed — use minimal commands"),
            ("eval(", "Dynamic code evaluation not allowed"),
            ("exec(", "Dynamic code execution not allowed"),
            ("subprocess", "Subprocess calls not allowed — use minimal commands"),
            ("os.system", "OS system calls not allowed — use minimal commands"),
            ("bash -i", "Reverse shells not allowed in PoC"),
            ("nc -", "Netcat reverse shells not allowed in PoC"),
            ("/bin/sh", "Shell spawning not allowed in PoC"),
            ("python -c", "Inline Python not allowed — use minimal commands"),
            ("perl -e", "Inline Perl not allowed — use minimal commands"),
        ]

        for flag, reason in red_flags:
            if flag in poc_lower:
                return False, reason

        # Check that PoC is under 500 characters
        if len(poc) > 500:
            return False, "PoC too long — VK requires minimal commands (under 500 chars)"

        return True, "PoC is minimal"

    def get_target_priority_order(self, custom_targets: Optional[list[str]] = None) -> list[dict]:
        """
        Return targets sorted by bounty priority.
        Use this to decide which targets to test first.
        """
        targets = []

        for domain in self.tier1_domains:
            targets.append({"domain": domain, "tier": 1, "priority": "CRITICAL"})
        for domain in self.tier2_domains:
            targets.append({"domain": domain, "tier": 2, "priority": "HIGH"})
        for domain in self.tier3_domains:
            targets.append({"domain": domain, "tier": 3, "priority": "STANDARD"})
        for app in self.tier4_apps:
            targets.append({"domain": app, "tier": 4, "priority": "LOW"})

        if custom_targets:
            for t in custom_targets:
                vk_tier = self.tier(t)
                if vk_tier != VKTier.OUT_OF_SCOPE:
                    targets.append({
                        "domain": t,
                        "tier": vk_tier.value,
                        "priority": "HIGH" if vk_tier.value <= 2 else "STANDARD",
                    })

        # Sort: tier 1 first, then by priority
        targets.sort(key=lambda x: (x["tier"], x["priority"]))
        return targets


# ─── Convenience Instance ──────────────────────────────────────────────────────
vk_scope = VKScope()


# ─── CLI Demo ──────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    from rich.console import Console
    from rich.table import Table

    console = Console()
    scope = VKScope()

    console.rule("[bold red]VK Bug Bounty — Scope Assessment[/bold red]")

    # Test some targets
    test_cases = [
        ("id.vk.com", "SQL Injection"),
        ("vk.com", "IDOR"),
        ("m.vk.com", "XSS"),
        ("api.vk.com", "SSRF"),
        ("vk.com/ads", "XSS"),
        ("mail.ru", "SQL Injection"),
        ("smailru.net", "SSRF"),
        ("away.php", "Open Redirect"),
        ("dev.vk.com", "Auth Bypass"),
        ("random-site.com", "XSS"),
    ]

    table = Table(title="VK Scope Assessment Results")
    table.add_column("Target", style="cyan")
    table.add_column("Vuln Type", style="magenta")
    table.add_column("Tier", style="green")
    table.add_column("Eligible", style="bold")
    table.add_column("Reason", style="yellow")

    for target, vuln in test_cases:
        assessment = scope.assess_finding(target, vuln)
        eligible = "✅ YES" if assessment["eligible"] else "❌ NO"
        tier = assessment["vk_tier"]
        reason = "; ".join(assessment["rejection_reasons"]) if assessment["rejection_reasons"] else "In scope"
        table.add_row(target, vuln, tier, eligible, reason[:80])

    console.print(table)

    # Priority order
    console.rule("\n[bold]Target Priority Order[/bold]")
    priority = scope.get_target_priority_order()
    ptable = Table(title="Hunt Priority")
    ptable.add_column("Target", style="cyan")
    ptable.add_column("Tier", style="green")
    ptable.add_column("Priority", style="bold")

    seen = set()
    for p in priority:
        key = p["domain"]
        if key not in seen:
            seen.add(key)
            ptable.add_row(str(p["domain"]), str(p["tier"]), p["priority"])
    console.print(ptable)
