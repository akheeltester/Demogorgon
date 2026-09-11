"""EvidencePackager — packages raw evidence into report-ready structures."""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from typing import Any

from .types import EvidenceItem, EvidenceType, EvidenceRequest, EvidenceResponse

logger = logging.getLogger(__name__)


@dataclass
class PackagedEvidence:
    """Evidence packaged for validation and reporting.

    Contains:
    - Structured reproduction steps
    - Request/response pairs
    - Impact assessment
    - Severity suggestion
    - All raw evidence items
    """
    vuln_class: str = ""
    title: str = ""
    severity: str = "unknown"
    endpoint: str = ""
    method: str = ""
    description: str = ""
    impact: str = ""
    remediation: str = ""
    reproduction_steps: list[str] = field(default_factory=list)
    request_response_pairs: list[dict[str, Any]] = field(default_factory=list)
    raw_evidence: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "vuln_class": self.vuln_class,
            "title": self.title,
            "severity": self.severity,
            "endpoint": self.endpoint,
            "method": self.method,
            "description": self.description,
            "impact": self.impact,
            "remediation": self.remediation,
            "reproduction_steps": self.reproduction_steps,
            "request_response_pairs": self.request_response_pairs,
            "raw_evidence": self.raw_evidence,
            "metadata": self.metadata,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PackagedEvidence:
        return cls(
            vuln_class=data.get("vuln_class", ""),
            title=data.get("title", ""),
            severity=data.get("severity", "unknown"),
            endpoint=data.get("endpoint", ""),
            method=data.get("method", ""),
            description=data.get("description", ""),
            impact=data.get("impact", ""),
            remediation=data.get("remediation", ""),
            reproduction_steps=data.get("reproduction_steps", []),
            request_response_pairs=data.get("request_response_pairs", []),
            raw_evidence=data.get("raw_evidence", []),
            metadata=data.get("metadata", {}),
        )


class EvidencePackager:
    """Packages raw evidence into report-ready structures.

    Takes EvidenceItems collected during research and creates
    PackagedEvidence objects suitable for validation and reporting.
    """

    def __init__(self, workspace_dir: str = ""):
        self._workspace_dir = workspace_dir

    def package(
        self,
        vuln_class: str,
        evidence_items: list[EvidenceItem],
        title: str = "",
        endpoint: str = "",
        method: str = "",
        description: str = "",
        impact: str = "",
        remediation: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> PackagedEvidence:
        """Package evidence items into a PackagedEvidence.

        Args:
            vuln_class: Vulnerability class (e.g., "idor", "xss", "ssrf")
            evidence_items: List of evidence items collected
            title: Report title
            endpoint: Affected endpoint
            method: HTTP method
            description: Vulnerability description
            impact: Impact statement
            remediation: Remediation advice
            metadata: Additional metadata
        """
        request_response_pairs = []
        raw_evidence = []
        reproduction_steps = []

        for item in evidence_items:
            raw_evidence.append(item.to_dict())

            if item.request and item.response:
                pair = {
                    "request": item.request.to_dict(),
                    "response": item.response.to_dict(),
                }
                request_response_pairs.append(pair)

                step = f"{item.request.method} {item.request.url}"
                if item.response.status_code:
                    step += f" → {item.response.status_code}"
                reproduction_steps.append(step)

            elif item.description:
                reproduction_steps.append(item.description)

        if not title:
            title = f"{vuln_class.upper()} on {endpoint}"

        return PackagedEvidence(
            vuln_class=vuln_class,
            title=title,
            endpoint=endpoint,
            method=method,
            description=description,
            impact=impact,
            remediation=remediation,
            reproduction_steps=reproduction_steps,
            request_response_pairs=request_response_pairs,
            raw_evidence=raw_evidence,
            metadata=metadata or {},
        )

    def package_from_http(
        self,
        vuln_class: str,
        method: str,
        url: str,
        status_code: int,
        request_headers: dict[str, str] | None = None,
        request_body: str = "",
        response_headers: dict[str, str] | None = None,
        response_body: str = "",
        title: str = "",
        description: str = "",
    ) -> PackagedEvidence:
        """Quick packaging from a single HTTP exchange."""
        request = EvidenceRequest(
            method=method,
            url=url,
            headers=request_headers or {},
            body=request_body,
        )
        response = EvidenceResponse(
            status_code=status_code,
            headers=response_headers or {},
            body=response_body,
        )
        item = EvidenceItem(
            type=EvidenceType.HTTP_REQUEST,
            description=f"{method} {url} → {status_code}",
            request=request,
            response=response,
            confidence=0.7,
        )
        return self.package(
            vuln_class=vuln_class,
            evidence_items=[item],
            title=title,
            endpoint=url,
            method=method,
            description=description,
        )

    def save(self, packaged: PackagedEvidence, path: str | None = None) -> str:
        """Save packaged evidence to disk. Returns the file path."""
        if not path:
            if not self._workspace_dir:
                raise ValueError("No workspace_dir and no path specified")
            filename = f"evidence_{packaged.vuln_class}_{packaged.endpoint.replace('/', '_')[:50]}.json"
            path = os.path.join(self._workspace_dir, "evidence", filename)

        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w") as f:
            f.write(packaged.to_json())

        logger.info(f"Evidence saved: {path}")
        return path

    def load(self, path: str) -> PackagedEvidence:
        """Load packaged evidence from disk."""
        with open(path) as f:
            data = json.load(f)
        return PackagedEvidence.from_dict(data)

    def get_summary(self, packaged: PackagedEvidence) -> str:
        """Get a human-readable summary of packaged evidence."""
        lines = [
            f"Vulnerability: {packaged.vuln_class.upper()}",
            f"Endpoint: {packaged.endpoint}",
            f"Method: {packaged.method}",
            f"Severity: {packaged.severity}",
            f"Evidence items: {len(packaged.raw_evidence)}",
            f"Reproduction steps: {len(packaged.reproduction_steps)}",
        ]
        if packaged.description:
            lines.append(f"Description: {packaged.description}")
        return "\n".join(lines)
