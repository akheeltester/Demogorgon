"""Deterministic (no-LLM) research backbone.

This module is the always-available fallback reasoning engine. When no LLM
provider is configured, reachable, or affordable, the research loop must
still make progress instead of stalling with "No LLM provider".

Design rules:
- Only passive/safe GET requests. No fuzzing, no state changes, no auth.
- Fixed, auditable playbook — nothing is invented at runtime.
- STOP is emitted as soon as the playbook is exhausted, so the loop
  terminates cleanly instead of spinning.

Playbook (safe GET, in order):
    1. GET /                     (root + security headers)
    2. GET /robots.txt
    3. GET /sitemap.xml
    4. GET /.well-known/security.txt
    5. GET /.git/HEAD
    6. GET /.env
    7. GET /.DS_Store
    8. GET /admin  (existence probe only, no interaction)
    9. STOP
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from ..interfaces import (
    ActionType,
    Decision,
    ExperimentPlanner,
    Reasoner,
    Validator,
)

logger = logging.getLogger(__name__)

# (path, label, vuln_class, why)
SAFE_GET_PLAYBOOK: list[tuple[str, str, str, str]] = [
    ("/", "root", "info_disclosure",
     "Baseline response, server banner and security headers (HSTS/CSP/XFO)"),
    ("/robots.txt", "robots", "info_disclosure",
     "Disallowed paths frequently expose unlinked admin/debug endpoints"),
    ("/sitemap.xml", "sitemap", "info_disclosure",
     "Sitemap may enumerate endpoints missing from navigation"),
    ("/.well-known/security.txt", "security_txt", "info_disclosure",
     "Security contact and policy disclosure"),
    ("/.git/HEAD", "git_head", "info_disclosure",
     "Exposed git metadata would leak source code history"),
    ("/.env", "env_file", "info_disclosure",
     "Exposed environment file would leak secrets"),
    ("/.DS_Store", "ds_store", "info_disclosure",
     "macOS directory listing artifact leaks file names"),
    ("/admin", "admin_probe", "info_disclosure",
     "Existence probe for unlinked admin surface (GET only)"),
]

# Findings we will accept deterministically: a leak must be unambiguous.
# Each detector: (marker that proves the leak, vuln class, severity, title)
LEAK_DETECTORS: list[tuple[str, str, str, str]] = [
    ("ref: refs/heads/", "info_disclosure", "medium",
     "Exposed .git/HEAD leaks source control metadata"),
    ("APP_KEY=", "info_disclosure", "high",
     "Exposed .env file leaks application secrets"),
    ("DB_PASSWORD=", "info_disclosure", "high",
     "Exposed .env file leaks database credentials"),
    ("AWS_SECRET_ACCESS_KEY=", "info_disclosure", "critical",
     "Exposed .env file leaks cloud credentials"),
]

# Header names whose absence is worth reporting (defense in depth only).
MISSING_SECURITY_HEADERS = [
    "strict-transport-security",
    "x-frame-options",
    "content-security-policy",
]


@dataclass
class PlaybookState:
    """Tracks deterministic playbook progress across iterations."""
    cursor: int = 0
    visited: set[str] = field(default_factory=set)
    findings_made: set[str] = field(default_factory=set)

    @property
    def exhausted(self) -> bool:
        return self.cursor >= len(SAFE_GET_PLAYBOOK)


class DeterministicReasoner(Reasoner):
    """Fixed-playbook reasoner. No LLM, no invention, no repetition."""

    def __init__(self, state: PlaybookState | None = None, target: str = ""):
        self._state = state or PlaybookState()
        self._target = target

    async def reason(self, context: dict[str, Any]) -> Decision:
        target = context.get("target") or self._target
        tested = set(context.get("tested_actions", []) or [])

        # Walk the playbook to the next untested step
        while self._state.cursor < len(SAFE_GET_PLAYBOOK):
            path, label, vuln_class, why = SAFE_GET_PLAYBOOK[self._state.cursor]
            self._state.cursor += 1

            url = self._join(target, path)
            action_key = f"{ActionType.TEST_ENDPOINT.value}:{url}"
            if action_key in tested or url in self._state.visited:
                continue  # already covered by an earlier run
            self._state.visited.add(url)

            return Decision(
                action=ActionType.TEST_ENDPOINT,
                target=url,
                reason=f"[deterministic] {why}",
                confidence=0.6,
                priority=0.5,
                params={"method": "GET", "vuln_class": vuln_class,
                        "playbook_label": label, "safe": True},
                tool_hint="",
            )

        return Decision(
            action=ActionType.STOP,
            target=target,
            reason="[deterministic] Safe-GET playbook exhausted; "
                   "deeper testing requires an LLM provider.",
            confidence=1.0,
            priority=1.0,
        )

    async def explain(self, decision: Decision) -> str:
        """Explain a decision without an LLM — the reason field is already
        deterministic and self-describing."""
        return decision.reason

    @staticmethod
    def _join(base: str, path: str) -> str:
        if path == "/":
            return (base or "").rstrip("/") + "/"
        return (base or "").rstrip("/") + path


class DeterministicPlanner(ExperimentPlanner):
    """Plans a single safe GET request. Never mutates state."""

    async def plan(self, hypothesis: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
        endpoint = hypothesis.get("endpoint", "")
        vuln_class = hypothesis.get("vuln_class", "info_disclosure")
        return {
            "steps": [
                {
                    "step": 1,
                    "action": "send_request",
                    "target": endpoint,
                    "method": "GET",
                    "expected": "Capture response body, status and headers for analysis",
                }
            ],
            "preconditions": ["Target is in scope", "Target is reachable"],
            "expected_outcomes": [
                "Sensitive data or file contents disclosed (finding)",
                "Normal response (hypothesis rejected)",
            ],
            "safety_checks": [
                "GET request only — no state change",
                "In-scope target verified by SafetyGate",
                "Single request per endpoint (no scanning)",
            ],
            "evidence_to_collect": [
                "Full request/response pair",
                "Response headers",
                "Response body",
            ],
            "rollback_steps": [],
            "estimated_duration_seconds": 5,
            "risk_level": "low",
            "hypothesis_id": hypothesis.get("id", ""),
            "hypothesis_description": hypothesis.get("description", ""),
            "vuln_class": vuln_class,
            "deterministic": True,
        }


class DeterministicValidator(Validator):
    """Pattern-based validator. Accepts only unambiguous leaks; everything
    else is rejected with an explicit reason (never a guess)."""

    async def validate(self, evidence: dict[str, Any]) -> dict[str, Any]:
        endpoint = evidence.get("endpoint", "")
        body, status, headers = self._extract(evidence)

        # 1. Content leak detectors (strongest signal first)
        for marker, vuln_class, severity, title in LEAK_DETECTORS:
            if marker in body:
                return {
                    "is_finding": True,
                    "confidence": 0.9,
                    "severity": severity,
                    "title": title,
                    "vuln_class": vuln_class,
                    "endpoint": endpoint,
                    "method": "GET",
                    "description": (
                        f"A GET request to {endpoint} returned content matching "
                        f"'{marker}', which indicates an exposed sensitive file."
                    ),
                    "impact": (
                        "An unauthenticated attacker can retrieve this content and "
                        "use leaked credentials/history to escalate access."
                    ),
                    "remediation": (
                        "Block access to sensitive files at the web server/WAF, "
                        "rotate any exposed secrets, and purge VCS metadata from "
                        "deployed artifacts."
                    ),
                    "steps_to_reproduce": [
                        f"curl -i {endpoint}",
                        f"Observe the marker '{marker}' in the response body",
                    ],
                    "false_positive_reason": "",
                }

        # 2. Directory-listing detector (needs more than a bare 200)
        if ("Index of /" in body or "<title>Index of" in body) and status == 200:
            return {
                "is_finding": True,
                "confidence": 0.75,
                "severity": "medium",
                "title": "Directory listing enabled",
                "vuln_class": "info_disclosure",
                "endpoint": endpoint,
                "method": "GET",
                "description": "The server returns an auto-generated directory index.",
                "impact": "Attackers can enumerate files, including backups and configs.",
                "remediation": "Disable auto-indexing (e.g. 'options -Indexes').",
                "steps_to_reproduce": [f"curl -i {endpoint}"],
                "false_positive_reason": "",
            }

        # 3. Missing security headers — real, but low severity; only report on
        #    the root document to avoid duplicate low-value findings.
        rootish = endpoint.rstrip("/").endswith(
            ("example.com", "localhost:3000")
        ) or endpoint.endswith("/")
        if rootish:
            missing = [h for h in MISSING_SECURITY_HEADERS if h not in headers]
            if status == 200 and missing:
                return {
                    "is_finding": True,
                    "confidence": 0.6,
                    "severity": "low",
                    "title": "Missing security headers",
                    "vuln_class": "info_disclosure",
                    "endpoint": endpoint,
                    "method": "GET",
                    "description": "Response is missing: " + ", ".join(missing),
                    "impact": "Weakened browser-side protections (clickjacking, XSS mitigation).",
                    "remediation": "Add the missing security headers.",
                    "steps_to_reproduce": [f"curl -i {endpoint}"],
                    "false_positive_reason": "",
                }

        return {
            "is_finding": False,
            "confidence": 0.0,
            "severity": "info",
            "title": "",
            "vuln_class": evidence.get("vuln_class", "info_disclosure"),
            "endpoint": endpoint,
            "false_positive_reason": "No deterministic leak indicator in response",
        }

    @staticmethod
    def _extract(evidence: dict[str, Any]) -> tuple[str, int, dict[str, str]]:
        body, status, headers = "", 200, {}

        rr = evidence.get("request_response") or {}
        resp = rr.get("response") or evidence.get("response") or {}
        if isinstance(resp, str):
            body = resp
            headers = dict(
                line.split(":", 1) for line in resp.splitlines()
                if ":" in line and not line.lower().startswith(("http/", "{", "["))
            )
            headers = {k.strip().lower(): v.strip() for k, v in headers.items()}
        elif isinstance(resp, dict):
            body = str(resp.get("body", resp.get("content", "")))
            raw_headers = resp.get("headers") or {}
            if isinstance(raw_headers, dict):
                headers = {str(k).lower(): str(v) for k, v in raw_headers.items()}
            status = int(resp.get("status", resp.get("status_code", 200)) or 200)

        if not body:
            items = evidence.get("evidence") or []
            for item in items:
                if isinstance(item, dict):
                    body += str(item.get("description", "")) + "\n"
                    body += str(item.get("data", "")) + "\n"

        return body, status, headers
