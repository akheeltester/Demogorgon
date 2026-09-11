"""Scope Parser — parses bug bounty program policies into structured data.

Supports raw text input from:
- HackerOne
- Bugcrowd
- Intigriti
- YesWeHack
- Immunefi
- Custom programs

The parser preserves the original policy and extracts:
- Program name
- Organization
- In-scope assets
- Out-of-scope assets
- Testing restrictions
- Vulnerability classes
- Authentication rules
- Disclosure policies
"""

from __future__ import annotations

import re
from typing import Any
from ..engagement import ScopeAsset, TestingRestriction, ProgramPolicy


# ─── Platform Detection ──────────────────────────────────────────

PLATFORM_PATTERNS = {
    "hackerone": [
        r"hackerone\.com",
        r"hackerone",
        r"program\s+page",
    ],
    "bugcrowd": [
        r"bugcrowd\.com",
        r"bugcrowd",
        r"crowdstream",
    ],
    "intigriti": [
        r"intigriti\.com",
        r"intigriti",
    ],
    "yeswehack": [
        r"yeswehack\.com",
        r"yeswehack",
    ],
    "immunefi": [
        r"immunefi\.com",
        r"immunefi",
    ],
    "manual": [
        r"^manual$",
        r"platform:\s*manual",
    ],
}


def detect_platform(text: str) -> str:
    """Detect the bug bounty platform from the program text."""
    text_lower = text.lower()
    for platform, patterns in PLATFORM_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, text_lower, re.MULTILINE):
                return platform
    return "custom"


# ─── Scope Parsing ───────────────────────────────────────────────

def _extractdomains(text: str) -> list[str]:
    """Extract domain-like patterns from text."""
    # Match domain patterns
    domain_pattern = r'(?:(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}|(?:\*\.)?[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.[a-zA-Z]{2,})'
    matches = re.findall(domain_pattern, text)
    # Filter out common false positives
    false_positives = {
        'example.com', 'localhost', '127.0.0.1', '0.0.0.0',
        'your.domain.com', 'target.com', 'company.com',
        'email.com', 'http.com', 'https.com',
    }
    return [m for m in matches if m.lower() not in false_positives]


def _extract_urls(text: str) -> list[str]:
    """Extract URLs from text."""
    url_pattern = r'https?://[^\s<>"\')\]]+'
    return re.findall(url_pattern, text)


def _extract_ip_ranges(text: str) -> list[str]:
    """Extract IP ranges/CIDR from text."""
    cidr_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b'
    return re.findall(cidr_pattern, text)


def _extract_wildcards(text: str) -> list[str]:
    """Extract wildcard domain patterns."""
    wildcard_pattern = r'\*\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.[a-zA-Z]{2,}'
    return re.findall(wildcard_pattern, text)


def parse_scope_from_text(text: str) -> list[ScopeAsset]:
    """Parse scope assets from raw program text."""
    assets = []
    seen = set()
    
    # Extract wildcards first (they're most specific)
    for wc in _extract_wildcards(text):
        if wc not in seen:
            seen.add(wc)
            assets.append(ScopeAsset(
                pattern=wc,
                asset_type="subdomain",
                source="program_policy",
            ))
    
    # Extract URLs
    for url in _extract_urls(text):
        # Normalize URL
        normalized = url.rstrip('/')
        if normalized not in seen:
            seen.add(normalized)
            assets.append(ScopeAsset(
                pattern=normalized,
                asset_type="url",
                source="program_policy",
            ))
    
    # Extract domains (that aren't already covered by wildcards)
    for domain in _extractdomains(text):
        # Check if already covered by a wildcard
        covered = False
        for wc in seen:
            if domain.endswith(wc.lstrip('*')):
                covered = True
                break
        if not covered and domain not in seen:
            seen.add(domain)
            assets.append(ScopeAsset(
                pattern=domain,
                asset_type="domain",
                source="program_policy",
            ))
    
    # Extract IP ranges
    for ip_range in _extract_ip_ranges(text):
        if ip_range not in seen:
            seen.add(ip_range)
            assets.append(ScopeAsset(
                pattern=ip_range,
                asset_type="ip_range",
                source="program_policy",
            ))
    
    return assets


# ─── Restriction Parsing ─────────────────────────────────────────

RESTRICTION_PATTERNS = {
    "dos": [
        r"no\s+dos",
        r"denial[\s-]of[\s-]service",
        r"do\s+not\s+dos",
        r"dos\s+prohibited",
    ],
    "social_engineering": [
        r"no\s+social\s+engineering",
        r"social\s+engineering\s+prohibited",
        r"do\s+not\s+perform\s+social\s+engineering",
    ],
    "automated_scanning": [
        r"no\s+automated\s+scanning",
        r"automated\s+scanning\s+prohibited",
        r"do\s+not\s+use\s+automated",
        r"manual\s+testing\s+only",
    ],
    "physical": [
        r"no\s+physical\s+testing",
        r"physical\s+access\s+prohibited",
    ],
    "spam": [
        r"no\s+spam",
        r"spamming\s+prohibited",
    ],
    "rate_limit": [
        r"rate\s+limit[:\s]+(\d+)",
        r"maximum\s+(\d+)\s+requests",
        r"do\s+not\s+exceed\s+(\d+)",
    ],
}


def parse_restrictions_from_text(text: str) -> list[TestingRestriction]:
    """Parse testing restrictions from program text."""
    restrictions = []
    text_lower = text.lower()
    
    for category, patterns in RESTRICTION_PATTERNS.items():
        for pattern in patterns:
            match = re.search(pattern, text_lower)
            if match:
                rate_limit = None
                if category == "rate_limit" and match.lastindex:
                    try:
                        rate_limit = float(match.group(1))
                    except (ValueError, IndexError):
                        pass
                
                restrictions.append(TestingRestriction(
                    category=category,
                    allowed=False,
                    description=match.group(0),
                    rate_limit=rate_limit,
                ))
                break  # Only one restriction per category
    
    return restrictions


# ─── Vulnerability Class Parsing ─────────────────────────────────

VULN_CLASS_KEYWORDS = {
    "xss": ["xss", "cross-site scripting", "reflected xss", "stored xss"],
    "sqli": ["sql injection", "sqli", "sql inject"],
    "ssrf": ["ssrf", "server-side request forgery"],
    "csrf": ["csrf", "cross-site request forgery"],
    "idor": ["idor", "insecure direct object reference", "broken access control"],
    "auth_bypass": ["authentication bypass", "auth bypass", "login bypass"],
    "privesc": ["privilege escalation", "privesc", "elevation of privilege"],
    "race_condition": ["race condition", "race condition"],
    "file_upload": ["file upload", "unrestricted upload", "webshell"],
    "ssti": ["ssti", "server-side template injection"],
    "xxe": ["xxe", "xml external entity"],
    "open_redirect": ["open redirect", "url redirect", "forward redirect"],
    "information_disclosure": ["information disclosure", "information leak", "data exposure"],
    "business_logic": ["business logic", "logic flaw", "workflow bypass"],
    "jwt": ["jwt", "json web token"],
    "cors": ["cors", "cross-origin resource sharing"],
}


def parse_vuln_classes_from_text(text: str) -> tuple[list[str], list[str]]:
    """Extract allowed and forbidden vulnerability classes from text."""
    text_lower = text.lower()
    allowed = []
    forbidden = []
    
    for vuln_class, keywords in VULN_CLASS_KEYWORDS.items():
        for keyword in keywords:
            if keyword in text_lower:
                # Check if it's forbidden
                # Look for patterns like "no xss testing", "xss not allowed", etc.
                is_forbidden = False
                for neg_pattern in [
                    rf"no\s+{re.escape(keyword)}",
                    rf"{re.escape(keyword)}\s+not\s+allowed",
                    rf"{re.escape(keyword)}\s+prohibited",
                    rf"do\s+not\s+test\s+for\s+{re.escape(keyword)}",
                ]:
                    if re.search(neg_pattern, text_lower):
                        is_forbidden = True
                        break
                
                if is_forbidden:
                    if vuln_class not in forbidden:
                        forbidden.append(vuln_class)
                else:
                    if vuln_class not in allowed:
                        allowed.append(vuln_class)
                break
    
    return allowed, forbidden


# ─── Program Name Extraction ─────────────────────────────────────

def extract_program_name(text: str) -> str:
    """Extract the program/organization name from the policy text."""
    lines = text.strip().split('\n')
    
    # Try first non-empty line
    for line in lines[:5]:
        line = line.strip()
        if line and len(line) > 2 and len(line) < 100:
            # Skip lines that look like URLs or headers
            if not line.startswith(('http', '#', '=', '-', '*')):
                return line
    
    return "Unknown Program"


# ─── Main Parser ─────────────────────────────────────────────────

def parse_program_policy(text: str) -> ProgramPolicy:
    """Parse raw program policy text into a structured ProgramPolicy.

    This is the main entry point for the policy parser.
    It extracts all relevant information from the raw text.
    """
    platform = detect_platform(text)
    program_name = extract_program_name(text)
    
    # Parse scope
    in_scope = parse_scope_from_text(text)
    
    # Parse restrictions
    restrictions = parse_restrictions_from_text(text)
    
    # Parse vulnerability classes
    allowed_vulns, forbidden_vulns = parse_vuln_classes_from_text(text)
    
    # Determine account creation rules
    account_creation_allowed = True
    text_lower = text.lower()
    if re.search(r"no\s+account\s+creation|account\s+creation\s+prohibited|do\s+not\s+create\s+accounts", text_lower):
        account_creation_allowed = False
    
    # Determine safe harbor
    safe_harbor = bool(re.search(r"safe\s+harbor|responsible\s+disclosure", text_lower))
    
    policy = ProgramPolicy(
        program_name=program_name,
        platform=platform,
        in_scope=in_scope,
        restrictions=restrictions,
        allowed_vulnerabilities=allowed_vulns,
        forbidden_vulnerabilities=forbidden_vulns,
        account_creation_allowed=account_creation_allowed,
        safe_harbor=safe_harbor,
        raw_policy=text,
    )
    
    return policy
