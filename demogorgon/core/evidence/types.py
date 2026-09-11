"""Evidence types — data models for evidence collection."""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class EvidenceType(Enum):
    """Types of evidence."""
    HTTP_REQUEST = "http_request"
    HTTP_RESPONSE = "http_response"
    OBSERVATION = "observation"
    SCANNER_OUTPUT = "scanner_output"
    BROWSER_ACTION = "browser_action"
    TOOL_OUTPUT = "tool_output"
    LOG_ENTRY = "log_entry"
    SCREENSHOT = "screenshot"
    REPRODUCTION_STEPS = "reproduction_steps"


@dataclass
class EvidenceRequest:
    """An HTTP request captured as evidence."""
    method: str = "GET"
    url: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "method": self.method,
            "url": self.url,
            "headers": self.headers,
            "body": self.body,
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EvidenceRequest:
        return cls(
            method=data.get("method", "GET"),
            url=data.get("url", ""),
            headers=data.get("headers", {}),
            body=data.get("body", ""),
            timestamp=data.get("timestamp", 0),
        )


@dataclass
class EvidenceResponse:
    """An HTTP response captured as evidence."""
    status_code: int = 0
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    response_time_ms: float = 0
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "status_code": self.status_code,
            "headers": self.headers,
            "body": self.body,
            "response_time_ms": self.response_time_ms,
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EvidenceResponse:
        return cls(
            status_code=data.get("status_code", 0),
            headers=data.get("headers", {}),
            body=data.get("body", ""),
            response_time_ms=data.get("response_time_ms", 0),
            timestamp=data.get("timestamp", 0),
        )


@dataclass
class EvidenceItem:
    """A single piece of evidence."""
    id: str = field(default_factory=lambda: secrets.token_hex(8))
    type: EvidenceType = EvidenceType.OBSERVATION
    description: str = ""
    request: EvidenceRequest | None = None
    response: EvidenceResponse | None = None
    data: dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.5
    source: str = ""
    tags: list[str] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type.value,
            "description": self.description,
            "request": self.request.to_dict() if self.request else None,
            "response": self.response.to_dict() if self.response else None,
            "data": self.data,
            "confidence": self.confidence,
            "source": self.source,
            "tags": self.tags,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EvidenceItem:
        return cls(
            id=data.get("id", ""),
            type=EvidenceType(data.get("type", "observation")),
            description=data.get("description", ""),
            request=EvidenceRequest.from_dict(data["request"]) if data.get("request") else None,
            response=EvidenceResponse.from_dict(data["response"]) if data.get("response") else None,
            data=data.get("data", {}),
            confidence=data.get("confidence", 0.5),
            source=data.get("source", ""),
            tags=data.get("tags", []),
            created_at=data.get("created_at", 0),
        )
