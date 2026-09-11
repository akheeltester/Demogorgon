"""Evidence Collector — captures and manages evidence from experiments.

Provides structured evidence packaging, storage, and retrieval.
Each evidence item includes request/response pairs, observations,
and metadata for validation.
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class EvidenceItem:
    """A single piece of evidence."""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    type: str = ""  # http_request, browser_navigation, tool_output, observation
    description: str = ""
    request: dict[str, Any] = field(default_factory=dict)
    response: dict[str, Any] = field(default_factory=dict)
    data: dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    confidence: float = 0.5

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "type": self.type,
            "description": self.description,
            "request": self.request,
            "response": self.response,
            "data": self.data,
            "timestamp": self.timestamp,
            "confidence": self.confidence,
        }

    @classmethod
    def from_dict(cls, data: dict) -> EvidenceItem:
        return cls(
            id=data.get("id", ""),
            type=data.get("type", ""),
            description=data.get("description", ""),
            request=data.get("request", {}),
            response=data.get("response", {}),
            data=data.get("data", {}),
            timestamp=data.get("timestamp", ""),
            confidence=data.get("confidence", 0.5),
        )


class EvidenceCollector:
    """Collects and manages evidence from experiments.

    Usage:
        collector = EvidenceCollector(workspace_dir="./evidence")
        item = collector.add_evidence(
            type="http_request",
            description="IDOR test on /api/users/1",
            request={"method": "GET", "url": "/api/users/1"},
            response={"status_code": 200, "body": "..."},
        )
        evidence_package = collector.package_for_validation("idor", "/api/users/1")
    """

    def __init__(self, workspace_dir: str = ""):
        self._workspace = Path(workspace_dir) if workspace_dir else Path(".")
        self._evidence: list[EvidenceItem] = []
        self._by_type: dict[str, list[EvidenceItem]] = {}
        self._by_endpoint: dict[str, list[EvidenceItem]] = {}
        self._persist = bool(workspace_dir)
        self._evidence_file = self._workspace / "evidence.json"
        if self._persist:
            self._load_existing()

    def _load_existing(self) -> None:
        """Load existing evidence from disk."""
        if self._evidence_file.exists():
            try:
                with open(self._evidence_file) as f:
                    data = json.load(f)
                # Support both formats: {"evidence": [...]} and plain [...]
                items = data.get("evidence", data) if isinstance(data, dict) else data
                if isinstance(items, list):
                    for item_dict in items:
                        if isinstance(item_dict, dict):
                            item = EvidenceItem.from_dict(item_dict)
                            self._evidence.append(item)
                            self._by_type.setdefault(item.type, []).append(item)
                            url = item.request.get("url", "")
                            if url:
                                self._by_endpoint.setdefault(url, []).append(item)
            except (json.JSONDecodeError, KeyError):
                pass

    def _save(self) -> None:
        """Persist evidence to disk."""
        if not self._persist:
            return
        self._workspace.mkdir(parents=True, exist_ok=True)
        with open(self._evidence_file, "w") as f:
            json.dump([item.to_dict() for item in self._evidence], f, indent=2)

    def add_evidence(
        self,
        type: str = "",
        description: str = "",
        request: dict[str, Any] | None = None,
        response: dict[str, Any] | None = None,
        data: dict[str, Any] | None = None,
        confidence: float = 0.5,
    ) -> EvidenceItem:
        """Add a piece of evidence."""
        item = EvidenceItem(
            type=type,
            description=description,
            request=request or {},
            response=response or {},
            data=data or {},
            confidence=confidence,
        )

        self._evidence.append(item)
        self._by_type.setdefault(type, []).append(item)

        # Index by endpoint URL
        url = (request or {}).get("url", "")
        if url:
            self._by_endpoint.setdefault(url, []).append(item)

        self._save()
        return item

    def add_http_evidence(
        self,
        method: str,
        url: str,
        status_code: int,
        response_headers: dict[str, str] | None = None,
        response_body: str = "",
        description: str = "",
    ) -> EvidenceItem:
        """Add HTTP request/response evidence."""
        return self.add_evidence(
            type="http_request",
            description=description or f"{method} {url} -> {status_code}",
            request={"method": method, "url": url},
            response={
                "status_code": status_code,
                "headers": response_headers or {},
                "body": response_body[:10000],
            },
        )

    def add_observation_evidence(
        self,
        description: str,
        data: dict[str, Any] | None = None,
    ) -> EvidenceItem:
        """Add observation evidence."""
        return self.add_evidence(
            type="observation",
            description=description,
            data=data or {},
        )

    def get_evidence_for_endpoint(self, url: str) -> list[EvidenceItem]:
        """Get all evidence for a specific endpoint."""
        return self._by_endpoint.get(url, [])

    def get_evidence_by_type(self, type: str) -> list[EvidenceItem]:
        """Get all evidence of a specific type."""
        return self._by_type.get(type, [])

    def get_all_evidence(self) -> list[EvidenceItem]:
        """Get all evidence items."""
        return list(self._evidence)

    def get_request_response_pairs(self) -> list[dict[str, Any]]:
        """Get all request/response pairs."""
        pairs = []
        for item in self._evidence:
            if item.request and item.response:
                pairs.append({
                    "request": item.request,
                    "response": item.response,
                })
        return pairs

    def package_for_validation(
        self,
        vuln_class: str,
        endpoint: str,
        method: str = "GET",
    ) -> dict[str, Any]:
        """Package evidence for the Validator.

        Returns a structured dict ready for LLMValidator.validate().
        """
        # Collect all evidence for this endpoint
        endpoint_evidence = self.get_evidence_for_endpoint(endpoint)

        # Build evidence list
        evidence_list = []
        for item in endpoint_evidence:
            evidence_list.append({
                "id": item.id,
                "type": item.type,
                "description": item.description,
                "data": item.data,
            })

        # Get the most relevant request/response pair
        request_response = {}
        for item in endpoint_evidence:
            if item.request and item.response:
                request_response = {
                    "request": item.request,
                    "response": item.response,
                }
                break

        return {
            "vuln_class": vuln_class,
            "endpoint": endpoint,
            "method": method,
            "evidence": evidence_list,
            "request_response": request_response,
            "context": {
                "total_evidence_items": len(endpoint_evidence),
                "evidence_types": list(set(item.type for item in endpoint_evidence)),
            },
        }

    def clear(self) -> None:
        """Clear all evidence."""
        self._evidence.clear()
        self._by_type.clear()
        self._by_endpoint.clear()

    def save(self, path: str) -> None:
        """Save evidence to a JSON file."""
        data = {
            "evidence": [item.to_dict() for item in self._evidence],
            "count": len(self._evidence),
        }
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            json.dump(data, f, indent=2)

    def load(self, path: str) -> bool:
        """Load evidence from a JSON file, replacing any existing evidence."""
        try:
            with open(path) as f:
                data = json.load(f)

            # Clear existing evidence
            self._evidence.clear()
            self._by_type.clear()
            self._by_endpoint.clear()

            for item_data in data.get("evidence", []):
                item = EvidenceItem.from_dict(item_data)
                self._evidence.append(item)
                self._by_type.setdefault(item.type, []).append(item)
                url = item.request.get("url", "")
                if url:
                    self._by_endpoint.setdefault(url, []).append(item)

            return True
        except Exception:
            return False

    def get_summary(self) -> dict[str, Any]:
        """Get a summary of collected evidence."""
        return {
            "total_items": len(self._evidence),
            "by_type": {t: len(items) for t, items in self._by_type.items()},
            "endpoints_covered": len(self._by_endpoint),
            "request_response_pairs": len(self.get_request_response_pairs()),
        }
