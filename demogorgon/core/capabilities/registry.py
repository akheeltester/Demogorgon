"""Environment capability registry (Phase 4).

Answers a single question the runner needs for honest status reporting:

    "Which subsystems are actually usable right now?"

Distinct from ``agent.capabilities`` (tool→capability bindings the LLM picks
from) — this registry probes *environment* capabilities: LLM provider, recon
tools, network access, crawler, report generator. Each capability reports a
CapabilityStatus so the runner can choose COMPLETED / DEGRADED / BLOCKED
instead of always printing "Engagement Complete".

Small on purpose (Phase 16): one enum, one record, one registry.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable

logger = logging.getLogger(__name__)


class CapabilityStatus(Enum):
    """Availability of an environment capability."""

    AVAILABLE = "available"
    DEGRADED = "degraded"      # usable, but with reduced quality/coverage
    UNAVAILABLE = "unavailable"  # probe failed or dependency missing
    UNKNOWN = "unknown"          # never probed


@dataclass
class Capability:
    """A named environment capability with an optional probe."""

    name: str
    description: str = ""
    required: bool = False  # required capabilities ⇒ BLOCKED when missing
    probe: Callable[[], Any] | None = None
    #: set by the registry after probing
    status: CapabilityStatus = CapabilityStatus.UNKNOWN
    detail: str = ""
    latency: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def usable(self) -> bool:
        return self.status in (CapabilityStatus.AVAILABLE, CapabilityStatus.DEGRADED)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "required": self.required,
            "status": self.status.value,
            "detail": self.detail,
            "latency": round(self.latency, 3),
            "usable": self.usable,
        }


@dataclass
class CapabilityDiagnostic:
    """Aggregate result of probing the whole registry."""

    capabilities: list[dict[str, Any]] = field(default_factory=list)
    available: list[str] = field(default_factory=list)
    degraded: list[str] = field(default_factory=list)
    unavailable: list[str] = field(default_factory=list)
    #: required capabilities that are missing
    missing_required: list[str] = field(default_factory=list)

    @property
    def healthy(self) -> bool:
        return not self.missing_required

    @property
    def degraded_mode(self) -> bool:
        return bool(self.degraded) or bool(self.unavailable)

    def to_dict(self) -> dict[str, Any]:
        return {
            "capabilities": self.capabilities,
            "available": self.available,
            "degraded": self.degraded,
            "unavailable": self.unavailable,
            "missing_required": self.missing_required,
            "healthy": self.healthy,
            "degraded_mode": self.degraded_mode,
        }


class CapabilityRegistry:
    """Registry of environment capabilities with probing and diagnosis."""

    def __init__(self) -> None:
        self._capabilities: dict[str, Capability] = {}

    def register(
        self,
        name: str,
        description: str = "",
        required: bool = False,
        probe: Callable[[], Any] | None = None,
    ) -> Capability:
        cap = Capability(
            name=name, description=description, required=required, probe=probe
        )
        self._capabilities[name] = cap
        return cap

    def get(self, name: str) -> Capability | None:
        return self._capabilities.get(name)

    def __contains__(self, name: str) -> bool:
        return name in self._capabilities

    def __iter__(self):
        return iter(self._capabilities.values())

    def names(self) -> list[str]:
        return list(self._capabilities)

    def update_status(
        self,
        name: str,
        status: CapabilityStatus,
        detail: str = "",
        latency: float = 0.0,
        **metadata: Any,
    ) -> None:
        """Record a status for a capability (used by probes and callers)."""
        cap = self._capabilities.get(name)
        if cap is None:
            cap = self.register(name)
        cap.status = status
        cap.detail = detail
        cap.latency = latency
        cap.metadata.update(metadata)

    def probe_all(self, timeout: float = 10.0) -> CapabilityDiagnostic:
        """Run every registered probe and build a diagnostic.

        A probe may return:
          - True / False
          - a CapabilityStatus
          - a (status, detail) tuple
          - a dict with optional keys status/detail
        Exceptions ⇒ UNAVAILABLE (a broken probe is a failed capability).
        """
        diag = CapabilityDiagnostic()
        for cap in self._capabilities.values():
            if cap.probe is None:
                diag.capabilities.append(cap.to_dict())
                self._bucket(diag, cap)
                continue
            start = time.time()
            try:
                result = cap.probe()
                status, detail = _interpret_probe(result)
            except Exception as e:  # noqa: BLE001 — probe failure IS the signal
                logger.debug("Capability %s probe failed: %s", cap.name, e)
                status, detail = CapabilityStatus.UNAVAILABLE, str(e)
            cap.status = status
            cap.detail = detail
            cap.latency = time.time() - start
            diag.capabilities.append(cap.to_dict())
            self._bucket(diag, cap)
        return diag

    @staticmethod
    def _bucket(diag: CapabilityDiagnostic, cap: Capability) -> None:
        if cap.status == CapabilityStatus.AVAILABLE:
            diag.available.append(cap.name)
        elif cap.status == CapabilityStatus.DEGRADED:
            diag.degraded.append(cap.name)
        elif cap.status == CapabilityStatus.UNAVAILABLE:
            diag.unavailable.append(cap.name)
        if cap.required and not cap.usable:
            diag.missing_required.append(cap.name)


def _interpret_probe(result: Any) -> tuple[CapabilityStatus, str]:
    """Normalize whatever a probe returned into (status, detail)."""
    if isinstance(result, CapabilityStatus):
        return result, ""
    if isinstance(result, bool):
        return (
            CapabilityStatus.AVAILABLE if result else CapabilityStatus.UNAVAILABLE,
            "" if result else "probe returned False",
        )
    if isinstance(result, tuple) and len(result) == 2:
        status, detail = result
        if isinstance(status, CapabilityStatus):
            return status, str(detail)
        return (
            CapabilityStatus.AVAILABLE if status else CapabilityStatus.UNAVAILABLE,
            str(detail),
        )
    if isinstance(result, dict):
        raw = result.get("status", CapabilityStatus.AVAILABLE)
        status = raw if isinstance(raw, CapabilityStatus) else CapabilityStatus(str(raw))
        return status, str(result.get("detail", ""))
    if result is None:
        return CapabilityStatus.UNAVAILABLE, "probe returned None"
    return CapabilityStatus.AVAILABLE, str(result)
