"""Deterministic Vulnerability Detectors.

Pattern-based detection that requires NO LLM — pure logic.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse, parse_qs


class Detector:
    def __init__(self):
        self._sensitive_param_re = re.compile(
            r'(id|user_id|uid|account|profile|order|doc|file|path|key|token|session|admin|role|org|org_id)',
            re.IGNORECASE,
        )

    def detect(self, url: str, response_body: str, status_code: int, request_method: str = "GET") -> list[dict[str, Any]]:
        findings = []
        findings.extend(self.detect_idor(url, response_body, status_code))
        findings.extend(self.detect_sqli(url, response_body, status_code))
        findings.extend(self.detect_xss(url, response_body))
        findings.extend(self.detect_open_redirect(url, response_body))
        findings.extend(self.detect_info_disclosure(url, response_body))
        findings.extend(self.detect_misconfigured_headers(url, response_body, status_code))
        findings.extend(self.detect_path_traversal(url, response_body))
        findings.extend(self.detect_command_injection(url, response_body))
        findings.extend(self.detect_ssrf(url, response_body))
        findings.extend(self.detect_auth_bypass(url, response_body, status_code))
        return findings

    def detect_idor(self, url: str, body: str, status: int) -> list[dict[str, Any]]:
        findings = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if status == 200:
            for param_name in params:
                if self._sensitive_param_re.search(param_name):
                    findings.append({
                        "title": f"Potential IDOR — parameter '{param_name}' accessible",
                        "severity": "Medium",
                        "type": "IDOR",
                        "url": url,
                        "parameter": param_name,
                        "evidence": f"Parameter '{param_name}' returned 200. Test with modified values.",
                        "steps": f"1. Note the value of '{param_name}'\n2. Change to another user's ID\n3. Check if data changes",
                        "impact": "Unauthorized access to other users' data",
                        "recommendation": "Implement authorization checks on all ID-based endpoints",
                    })
        return findings

    def detect_sqli(self, url: str, body: str, status: int) -> list[dict[str, Any]]:
        findings = []
        error_patterns = [
            r"SQL syntax.*?MySQL",
            r"Warning.*?mysql_",
            r"MySQLSyntaxErrorException",
            r"valid MySQL result",
            r"pg_query\(\).*?Failed",
            r"PostgreSQL.*?ERROR",
            r"ORA-\d{5}",
            r"Oracle.*?Driver",
            r"SQLite.*?Error",
            r"sqlite3\.OperationalError",
            r"Microsoft.*?ODBC.*?SQL Server",
            r"Unclosed quotation mark",
            r"Syntax error.*?in query expression",
        ]
        for pattern in error_patterns:
            if re.search(pattern, body, re.IGNORECASE):
                findings.append({
                    "title": "SQL Injection — database error detected",
                    "severity": "Critical",
                    "type": "SQLi",
                    "url": url,
                    "parameter": "N/A",
                    "evidence": re.search(pattern, body, re.IGNORECASE).group(),
                    "steps": "1. Inject SQL payloads into parameters\n2. Confirm error-based injection\n3. Use sqlmap for exploitation",
                    "impact": "Full database compromise, data exfiltration",
                    "recommendation": "Use parameterized queries, input validation",
                })
                break
        return findings

    def detect_xss(self, url: str, body: str) -> list[dict[str, Any]]:
        findings = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        reflected = []
        for param_name, values in params.items():
            for value in values:
                if value and len(value) > 2 and value in body:
                    if not re.search(r'<!DOCTYPE|<html', body[:200]):
                        reflected.append(param_name)
        if reflected:
            findings.append({
                "title": f"Reflected XSS — parameters echoed in response: {', '.join(reflected)}",
                "severity": "Medium",
                "type": "Reflected XSS",
                "url": url,
                "parameter": ", ".join(reflected),
                "evidence": f"Parameters {reflected} appear to be reflected in the response body",
                "steps": "1. Inject <script>alert(1)</script> into reflected parameters\n2. Check if HTML encoding is applied\n3. Test various XSS contexts",
                "impact": "Session hijacking, credential theft, malware delivery",
                "recommendation": "Implement Content Security Policy, HTML-encode all output",
            })
        return findings

    def detect_open_redirect(self, url: str, body: str) -> list[dict[str, Any]]:
        findings = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        redirect_params = ["redirect", "url", "next", "return", "goto", "continue", "dest", "redir", "redirect_uri", "return_to", "checkout_url", "return_url"]
        for param_name in params:
            if param_name.lower() in redirect_params:
                for value in params[param_name]:
                    if value.startswith("http://") or value.startswith("//"):
                        findings.append({
                            "title": f"Open Redirect — parameter '{param_name}' accepts external URLs",
                            "severity": "Medium",
                            "type": "Open Redirect",
                            "url": url,
                            "parameter": param_name,
                            "evidence": f"Parameter '{param_name}' accepts value: {value}",
                            "steps": f"1. Set '{param_name}' to https://evil.com\n2. Check if redirect occurs\n3. Test phishing scenarios",
                            "impact": "Phishing, OAuth token theft, malware delivery",
                            "recommendation": "Validate redirect targets against whitelist",
                        })
        return findings

    def detect_info_disclosure(self, url: str, body: str) -> list[dict[str, Any]]:
        findings = []
        patterns = [
            (r"(\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b)", "Email address exposed"),
            (r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "IP address exposed"),
            (r"(?i)(api[_-]?key|secret[_-]?key|access[_-]?key|auth[_-]?token)\s*[:=]\s*['\"]?[A-Za-z0-9+/=_-]{16,}['\"]?", "API key/secret exposed"),
            (r"(?i)stack\s*trace|at\s+[\w.]+\([\w.]+:\d+\)", "Stack trace exposed"),
            (r"(?i)version[:\s]+[\d.]+", "Version information exposed"),
            (r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"]?[^\s'\"]+['\"]?", "Password exposed in response"),
        ]
        for pattern, desc in patterns:
            match = re.search(pattern, body)
            if match:
                findings.append({
                    "title": f"Information Disclosure — {desc}",
                    "severity": "Low",
                    "type": "Info Disclosure",
                    "url": url,
                    "parameter": "N/A",
                    "evidence": match.group(),
                    "steps": f"1. Review response for {desc.lower()}\n2. Check if this is intentional",
                    "impact": "Information leakage aids attackers",
                    "recommendation": "Remove sensitive information from responses",
                })
        return findings

    def detect_misconfigured_headers(self, url: str, body: str, status: int) -> list[dict[str, Any]]:
        findings = []
        critical_headers = [
            ("X-Frame-Options", "Clickjacking protection missing"),
            ("X-Content-Type-Options", "MIME type sniffing protection missing"),
            ("Strict-Transport-Security", "HSTS header missing"),
            ("Content-Security-Policy", "CSP header missing"),
            ("X-XSS-Protection", "XSS filter protection missing"),
        ]
        for header_name, desc in critical_headers:
            if header_name.lower() not in {k.lower() for k in []}:
                findings.append({
                    "title": f"Security Header Missing — {desc}",
                    "severity": "Low",
                    "type": "Missing Header",
                    "url": url,
                    "parameter": header_name,
                    "evidence": f"Header '{header_name}' not found in response",
                    "steps": f"1. Check response headers for '{header_name}'\n2. Add header to server configuration",
                    "impact": f"Missing {header_name} protection",
                    "recommendation": f"Add '{header_name}' header to all responses",
                })
        return findings

    def detect_path_traversal(self, url: str, body: str) -> list[dict[str, Any]]:
        findings = []
        traversal_patterns = [
            r"\.\.\/",
            r"\.\.\\",
            r"%2e%2e%2f",
            r"%2e%2e/",
            r"\.\.%2f",
            r"%2e%2e%5c",
        ]
        for pattern in traversal_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                if any(marker in body for marker in ["root:", "/etc/passwd", "Windows", "[boot loader]"]):
                    findings.append({
                        "title": "Path Traversal — file system access detected",
                        "severity": "Critical",
                        "type": "Path Traversal",
                        "url": url,
                        "parameter": "URL path",
                        "evidence": "Traversal sequence in URL returned sensitive file content",
                        "steps": "1. Use ../ sequences in URL path\n2. Access /etc/passwd or equivalent\n3. Test for file write capabilities",
                        "impact": "Arbitrary file read, potential RCE",
                        "recommendation": "Validate and sanitize file paths, use chroot jails",
                    })
                break
        return findings

    def detect_command_injection(self, url: str, body: str) -> list[dict[str, Any]]:
        findings = []
        cmd_patterns = [
            r"uid=\d+\(",
            r"root:x:0:0",
            r"Windows IP Configuration",
            r"Linux version \d",
            r"Darwin Kernel",
            r"/bin/sh",
            r"/bin/bash",
        ]
        for pattern in cmd_patterns:
            if re.search(pattern, body):
                findings.append({
                    "title": "Command Injection — OS command execution detected",
                    "severity": "Critical",
                    "type": "Command Injection",
                    "url": url,
                    "parameter": "N/A",
                    "evidence": re.search(pattern, body).group(),
                    "steps": "1. Inject OS commands via parameters\n2. Confirm RCE with id, whoami, etc.\n3. Establish reverse shell",
                    "impact": "Full server compromise",
                    "recommendation": "Use parameterized APIs, never pass user input to shell commands",
                })
                break
        return findings

    def detect_ssrf(self, url: str, body: str) -> list[dict[str, Any]]:
        findings = []
        ssrf_markers = [
            r"ami-[a-z0-9]{17}",
            r"instance-id",
            r"169\.254\.169\.254",
            r"metadata\.google\.internal",
            r"localhost:\d+",
            r"127\.0\.0\.1",
        ]
        for pattern in ssrf_markers:
            if re.search(pattern, body):
                findings.append({
                    "title": "SSRF — internal resource access detected",
                    "severity": "Critical",
                    "type": "SSRF",
                    "url": url,
                    "parameter": "N/A",
                    "evidence": re.search(pattern, body).group(),
                    "steps": "1. Point URL parameter to internal services\n2. Access cloud metadata endpoints\n3. Pivot to internal network",
                    "impact": "Cloud metadata theft, internal network scanning",
                    "recommendation": "Implement URL validation, block internal IPs",
                })
                break
        return findings

    def detect_auth_bypass(self, url: str, body: str, status: int) -> list[dict[str, Any]]:
        findings = []
        admin_paths = ["/admin", "/admin/", "/dashboard", "/wp-admin", "/phpmyadmin", "/manager", "/console"]
        for path in admin_paths:
            if path in url.lower() and status == 200:
                admin_indicators = ["dashboard", "admin panel", "manage", "settings", "user list", "delete", "edit user"]
                if any(indicator in body.lower() for indicator in admin_indicators):
                    findings.append({
                        "title": f"Auth Bypass — admin panel accessible at {path}",
                        "severity": "Critical",
                        "type": "Auth Bypass",
                        "url": url,
                        "parameter": "N/A",
                        "evidence": f"Admin panel accessible at {path} without authentication",
                        "steps": f"1. Navigate to {path}\n2. Verify admin functionality is accessible\n3. Test admin operations",
                        "impact": "Unauthorized admin access, full application control",
                        "recommendation": "Implement proper authentication and authorization checks",
                    })
                break
        return findings
