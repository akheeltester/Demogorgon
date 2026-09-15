"""Deterministic vulnerability detection patterns.

Provides pattern-based detection for SQL errors, XSS reflection,
timing anomalies, and information disclosure without LLM dependency.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Any


# ============================================================
# SQL Error Patterns
# ============================================================

SQL_ERROR_PATTERNS: list[re.Pattern] = [
    # MySQL
    re.compile(r"SQL syntax.*?MySQL", re.I),
    re.compile(r"Warning.*?\bmysql_", re.I),
    re.compile(r"MySQLSyntaxErrorException", re.I),
    re.compile(r"valid MySQL result", re.I),
    re.compile(r"check the manual that corresponds to your MySQL", re.I),
    re.compile(r"MySqlClient\.", re.I),
    re.compile(r"com\.mysql\.jdbc", re.I),
    re.compile(r"Unclosed quotation mark.*?'", re.I),
    # PostgreSQL
    re.compile(r"PostgreSQL.*?ERROR", re.I),
    re.compile(r"Warning.*?\bpg_", re.I),
    re.compile(r"valid PostgreSQL result", re.I),
    re.compile(r"Npgsql\.", re.I),
    re.compile(r"PG::SyntaxError", re.I),
    re.compile(r"org\.postgresql\.util\.PSQLException", re.I),
    re.compile(r"ERROR:\s+syntax error at or near", re.I),
    # MSSQL
    re.compile(r"Driver.*?SQL[\-\_\ ]*Server", re.I),
    re.compile(r"OLE DB.*?SQL Server", re.I),
    re.compile(r"\bSQL Server[^&lt;&quot;]+Driver", re.I),
    re.compile(r"Warning.*?\bmssql_", re.I),
    re.compile(r"\bSQL Server[^&lt;&quot;]+[0-9a-fA-F]{8}", re.I),
    re.compile(r"System\.Data\.SqlClient\.SqlException", re.I),
    re.compile(r"Unclosed quotation mark.*?'", re.I),
    re.compile(r"Microsoft SQL Native Client error", re.I),
    # Oracle
    re.compile(r"\bORA-[0-9][0-9][0-9][0-9]", re.I),
    re.compile(r"Oracle error", re.I),
    re.compile(r"Oracle.*?Driver", re.I),
    re.compile(r"Warning.*?\boci_", re.I),
    re.compile(r"Warning.*?\bora_", re.I),
    re.compile(r"oracle\.jdbc", re.I),
    # SQLite
    re.compile(r"SQLite/JDBCDriver", re.I),
    re.compile(r"SQLite\.Exception", re.I),
    re.compile(r"System\.Data\.SQLite\.SQLiteException", re.I),
    re.compile(r"Warning.*?\bsqlite_", re.I),
    re.compile(r"Warning.*?\bSQLite3::", re.I),
    re.compile(r"\[SQLITE_ERROR\]", re.I),
    re.compile(r"SQLite error", re.I),
    # Generic
    re.compile(r"SQL syntax error", re.I),
    re.compile(r"Syntax error.*?in query", re.I),
    re.compile(r"Unexpected end of SQL command", re.I),
    re.compile(r"Invalid column name", re.I),
    re.compile(r"Column.*?not found", re.I),
    re.compile(r"Conversion failed", re.I),
    re.compile(r"The conversion.*?failed", re.I),
    re.compile(r"Microsoft OLE DB Provider for", re.I),
    re.compile(r"ODBC SQL Server Driver", re.I),
    re.compile(r"SQL command not properly ended", re.I),
]


# ============================================================
# XSS Reflection Patterns
# ============================================================

def detect_xss_reflection(
    payload: str,
    response_body: str,
) -> dict[str, Any] | None:
    """Check if a payload is reflected in the response body.

    Returns detection info if reflected, None otherwise.
    """
    if not payload or not response_body:
        return None

    # Exact match
    count = response_body.count(payload)
    if count > 0:
        return {
            "type": "exact_reflection",
            "payload": payload,
            "count": count,
            "severity": "high",
        }

    # HTML-encoded reflection (e.g., < becomes &lt;)
    import html
    encoded = html.escape(payload)
    if encoded != payload:
        count = response_body.count(encoded)
        if count > 0:
            return {
                "type": "encoded_reflection",
                "payload": payload,
                "encoded_as": encoded,
                "count": count,
                "severity": "medium",
                "note": "Payload reflected but HTML-encoded — may be exploitable with event handlers",
            }

    # URL-encoded reflection
    from urllib.parse import quote
    url_encoded = quote(payload)
    if url_encoded != payload:
        count = response_body.count(url_encoded)
        if count > 0:
            return {
                "type": "url_encoded_reflection",
                "payload": payload,
                "encoded_as": url_encoded,
                "count": count,
                "severity": "low",
                "note": "Payload reflected but URL-encoded",
            }

    return None


# ============================================================
# Timing Detection
# ============================================================

@dataclass
class TimingResult:
    """Result of a timing comparison."""
    baseline_ms: float
    test_ms: float
    diff_ms: float
    ratio: float
    suspicious: bool
    threshold_ms: float = 2000.0
    reason: str = ""


def compare_timing(
    baseline_ms: float,
    test_ms: float,
    threshold_ms: float = 2000.0,
) -> TimingResult:
    """Compare two request timings and flag anomalies.

    Useful for blind SQL injection, timing oracles, and race conditions.
    """
    diff = test_ms - baseline_ms
    ratio = test_ms / baseline_ms if baseline_ms > 0 else float("inf")

    suspicious = False
    reason = ""

    if diff > threshold_ms:
        suspicious = True
        reason = f"Test request took {diff:.0f}ms longer than baseline (>{threshold_ms}ms threshold)"
    elif ratio > 3.0 and diff > 500:
        suspicious = True
        reason = f"Test request was {ratio:.1f}x slower than baseline ({diff:.0f}ms difference)"

    return TimingResult(
        baseline_ms=baseline_ms,
        test_ms=test_ms,
        diff_ms=diff,
        ratio=ratio,
        suspicious=suspicious,
        threshold_ms=threshold_ms,
        reason=reason,
    )


async def measure_request_timing(
    http_client: Any,
    method: str,
    url: str,
    **kwargs: Any,
) -> tuple[dict[str, Any], float]:
    """Make an HTTP request and return (response, timing_ms)."""
    start = time.monotonic()
    resp = await http_client.request(method, url, **kwargs)
    elapsed = (time.monotonic() - start) * 1000
    return resp, elapsed


# ============================================================
# Information Disclosure Patterns
# ============================================================

INFO_DISCLOSURE_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    ("stack_trace", re.compile(r"Traceback \(most recent call last\)", re.I), "Python stack trace"),
    ("stack_trace", re.compile(r"at [\w.$]+\([\w.]+:\d+\)"), "Java/JS stack trace"),
    ("stack_trace", re.compile(r"File \".*?\",\s*line \d+"), "Python file reference"),
    ("debug_info", re.compile(r"debug[=:]\s*true", re.I), "Debug mode enabled"),
    ("debug_info", re.compile(r"APP_DEBUG", re.I), "Debug flag in response"),
    ("version_disclosure", re.compile(r"X-Powered-By:\s*\S+", re.I), "Server version header"),
    ("version_disclosure", re.compile(r"Server:\s*\S+", re.I), "Server header"),
    ("config_exposure", re.compile(r"AKIA[0-9A-Z]{16}"), "AWS access key"),
    ("config_exposure", re.compile(r"sk_live_[0-9a-zA-Z]+"), "Stripe secret key"),
    ("config_exposure", re.compile(r"ghp_[0-9a-zA-Z]{36}"), "GitHub personal access token"),
    ("config_exposure", re.compile(r"-----BEGIN (RSA |EC )?PRIVATE KEY-----"), "Private key"),
    ("sensitive_path", re.compile(r"/etc/passwd", re.I), "Passwd file reference"),
    ("sensitive_path", re.compile(r"/etc/shadow", re.I), "Shadow file reference"),
    ("sensitive_path", re.compile(r"/proc/self/"), "Proc filesystem access"),
    ("env_exposure", re.compile(r"process\.env\.", re.I), "Environment variable reference"),
    ("env_exposure", re.compile(r"os\.environ", re.I), "Python environment reference"),
    ("sql_dump", re.compile(r"INSERT\s+INTO\s+\w+", re.I), "SQL INSERT statement"),
    ("sql_dump", re.compile(r"CREATE\s+TABLE\s+\w+", re.I), "SQL CREATE TABLE statement"),
    ("source_code", re.compile(r"<pre.*?>.*?(function|class|import|const|var|let)\s", re.I | re.S), "Source code in HTML"),
    ("error_verbose", re.compile(r"Exception\s+in\s+thread", re.I), "Verbose thread error"),
    ("backup_file", re.compile(r"\.(bak|old|orig|save|swp|sql|dump|tar|gz|zip)\b", re.I), "Backup file reference"),
]


@dataclass
class InfoDisclosure:
    """Detected information disclosure."""
    category: str
    pattern_name: str
    description: str
    matched_text: str
    line_number: int = 0


def detect_info_disclosure(body: str, headers: dict[str, str] | None = None) -> list[InfoDisclosure]:
    """Scan response body and headers for information disclosure."""
    findings: list[InfoDisclosure] = []
    text_to_scan = body
    if headers:
        text_to_scan += "\n" + "\n".join(f"{k}: {v}" for k, v in headers.items())

    for category, pattern, description in INFO_DISCLOSURE_PATTERNS:
        match = pattern.search(text_to_scan)
        if match:
            start = max(0, match.start() - 50)
            end = min(len(text_to_scan), match.end() + 50)
            snippet = text_to_scan[start:end].replace("\n", " ").strip()
            findings.append(InfoDisclosure(
                category=category,
                pattern_name=pattern.pattern[:60],
                description=description,
                matched_text=snippet,
            ))

    return findings


# ============================================================
# WAF Detection
# ============================================================

WAF_SIGNATURES: list[tuple[str, re.Pattern, str]] = [
    ("cloudflare", re.compile(r"cloudflare", re.I), "Cloudflare"),
    ("akamai", re.compile(r"akamai", re.I), "Akamai"),
    ("aws_waf", re.compile(r"x-amzn-waf", re.I), "AWS WAF"),
    ("incapsula", re.compile(r"incap_ses|incapsula", re.I), "Incapsula/Imperva"),
    ("sucuri", re.compile(r"sucuri", re.I), "Sucuri"),
    ("wordfence", re.compile(r"wordfence", re.I), "Wordfence"),
    ("mod_security", re.compile(r"mod_security|modsecurity", re.I), "ModSecurity"),
    ("f5", re.compile(r"F5\b|BIG-IP", re.I), "F5 BIG-IP"),
    ("fortiweb", re.compile(r"FortiWeb", re.I), "FortiWeb"),
    ("barracuda", re.compile(r"Barracuda", re.I), "Barracuda WAF"),
    ("radware", re.compile(r"Radware|DefenScript", re.I), "Radware"),
    ("denied_page", re.compile(r"access.*?denied.*?by.*?policy", re.I), "Generic WAF block page"),
    ("captcha_challenge", re.compile(r"(captcha|challenge).*?(verify|human)", re.I), "CAPTCHA challenge"),
]


def detect_waf(headers: dict[str, str], body: str = "") -> list[str]:
    """Detect WAF/CDN from response headers and body."""
    detected: list[str] = []
    header_text = "\n".join(f"{k}: {v}" for k, v in headers.items())
    scan_text = header_text + "\n" + body

    for name, pattern, display_name in WAF_SIGNATURES:
        if pattern.search(scan_text):
            detected.append(display_name)

    return detected


# ============================================================
# Technology Fingerprinting
# ============================================================

TECH_FINGERPRINTS: list[tuple[str, re.Pattern, str]] = [
    ("nextjs", re.compile(r"__NEXT_DATA__|_next/static", re.I), "Next.js"),
    ("react", re.compile(r"react|__REACT_DEVTOOLS", re.I), "React"),
    ("vue", re.compile(r"vue|__VUE__", re.I), "Vue.js"),
    ("angular", re.compile(r"ng-version|angular", re.I), "Angular"),
    ("svelte", re.compile(r"svelte", re.I), "Svelte"),
    ("django", re.compile(r"csrfmiddlewaretoken|django", re.I), "Django"),
    ("flask", re.compile(r"werkzeug|flask", re.I), "Flask"),
    ("express", re.compile(r"express|x-powered-by.*?Express", re.I), "Express"),
    ("laravel", re.compile(r"laravel|XSRF-TOKEN", re.I), "Laravel"),
    ("rails", re.compile(r"ruby|rails|_session", re.I), "Ruby on Rails"),
    ("spring", re.compile(r"spring|X-Application-Context", re.I), "Spring"),
    ("php", re.compile(r"\.php|PHPSESSID", re.I), "PHP"),
    ("aspnet", re.compile(r"\.aspx|asp\.net|__VIEWSTATE", re.I), "ASP.NET"),
    ("wordpress", re.compile(r"wp-content|wp-includes|wordpress", re.I), "WordPress"),
    ("shopify", re.compile(r"shopify|cdn\.shopify", re.I), "Shopify"),
    ("ghost", re.compile(r"ghost/.*?\.js|ghost-", re.I), "Ghost CMS"),
    ("keycloak", re.compile(r"keycloak", re.I), "Keycloak"),
    ("graphql", re.compile(r"graphql|__schema", re.I), "GraphQL"),
]


def fingerprint_tech(headers: dict[str, str], body: str = "") -> list[str]:
    """Detect technology stack from response headers and body."""
    detected: list[str] = []
    header_text = "\n".join(f"{k}: {v}" for k, v in headers.items())
    scan_text = header_text + "\n" + body[:50000]

    for name, pattern, display_name in TECH_FINGERPRINTS:
        if pattern.search(scan_text):
            detected.append(display_name)

    return detected


# ============================================================
# Detector Class (used by research_loop.py)
# ============================================================


class Detector:
    """Unified detector that runs all pattern-based checks on a response."""

    def detect(
        self,
        url: str,
        body: str,
        status_code: int,
        method: str = "GET",
        response_headers: dict[str, str] | None = None,
        request_body: str = "",
        **kwargs: Any,
    ) -> list[dict[str, Any]]:
        """Run all detectors and return findings."""
        findings: list[dict[str, Any]] = []
        headers = response_headers or {}

        # SQL error detection
        if body:
            for pattern in SQL_ERROR_PATTERNS:
                match = pattern.search(body)
                if match:
                    start = max(0, match.start() - 100)
                    end = min(len(body), match.end() + 100)
                    snippet = body[start:end].replace("\n", " ").strip()
                    findings.append({
                        "title": f"SQL Error disclosed in {url}",
                        "type": "sql_error",
                        "severity": "high",
                        "confidence": 0.85,
                        "evidence": f"SQL error pattern matched: {snippet}",
                        "parameter": "",
                        "steps": f"1. Send {method} request to {url}\n2. Observe SQL error in response",
                        "impact": "Database error messages may reveal table names, column names, or query structure, aiding SQL injection attacks",
                        "url": url,
                        "method": method,
                    })
                    break  # One SQL error finding per response

        # XSS reflection detection
        if body and request_body:
            reflection = detect_xss_reflection(request_body, body)
            if reflection:
                findings.append({
                    "title": f"XSS reflection detected at {url}",
                    "type": "xss_reflection",
                    "severity": reflection.get("severity", "medium"),
                    "confidence": 0.80,
                    "evidence": f"Payload reflected {reflection['count']} time(s) as {reflection['type']}",
                    "parameter": "",
                    "steps": f"1. Send {method} request to {url} with payload\n2. Observe reflection in response",
                    "impact": "Reflected user input may allow cross-site scripting if HTML encoding is insufficient",
                    "url": url,
                    "method": method,
                })

        # Information disclosure detection
        if body or headers:
            disclosures = detect_info_disclosure(body, headers)
            for d in disclosures:
                findings.append({
                    "title": f"{d.description} at {url}",
                    "type": "info_disclosure",
                    "severity": "medium" if d.category in ("config_exposure", "sensitive_path") else "low",
                    "confidence": 0.75,
                    "evidence": f"[{d.category}] {d.matched_text}",
                    "parameter": "",
                    "steps": f"1. Send {method} request to {url}\n2. Observe {d.description.lower()} in response",
                    "impact": f"{d.description} may expose internal system details to attackers",
                    "url": url,
                    "method": method,
                })

        # WAF detection (informational)
        if headers:
            wafs = detect_waf(headers, body)
            if wafs:
                findings.append({
                    "title": f"WAF detected: {', '.join(wafs)} at {url}",
                    "type": "waf_detected",
                    "severity": "info",
                    "confidence": 0.90,
                    "evidence": f"WAF/CDN: {', '.join(wafs)}",
                    "parameter": "",
                    "steps": "",
                    "impact": "WAF may block or sanitize attack payloads",
                    "url": url,
                    "method": method,
                })

        return findings
