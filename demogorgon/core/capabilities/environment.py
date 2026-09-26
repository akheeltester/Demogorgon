"""Default environment capability probes.

Each probe answers "is this subsystem usable right now?" without side effects
beyond cheap checks (import tests, binary discovery, loopback HTTP).
"""

from __future__ import annotations

import importlib.util
import shutil
from typing import Any

from .registry import CapabilityRegistry, CapabilityStatus


def llm_circuit_state(llm_generate: Any = None) -> dict[str, Any]:
    """Circuit-breaker state reachable from an injected LLM callable.

    The runner only holds ``manager.generate`` (a bound method), so we reach
    the manager through ``__self__``.  Anything else — a test double, a plain
    function — yields an inert result.

    Returns ``{"open": {provider: reason}, "exhausted": bool}`` where
    ``exhausted`` means every registered provider is circuit-open, i.e. the
    LLM cannot be reached at all.
    """
    inert: dict[str, Any] = {"open": {}, "exhausted": False}
    mgr = getattr(llm_generate, "__self__", None)
    if mgr is None:
        return inert
    try:
        circuits = getattr(mgr, "open_circuits", None)
        open_circuits = (
            {str(k): str(v) for k, v in circuits.items()}
            if isinstance(circuits, dict) and circuits
            else {}
        )
        providers = getattr(mgr, "_providers", None)
        candidates = getattr(mgr, "_candidate_providers", None)
        if isinstance(providers, dict) and providers and callable(candidates):
            remaining = candidates()
            exhausted = isinstance(remaining, list) and not remaining
        else:
            exhausted = False
    except Exception:  # noqa: BLE001 — diagnostics must never raise
        return inert
    return {"open": open_circuits, "exhausted": bool(exhausted)}


def _probe_llm(llm_generate: Any = None) -> Any:
    """LLM capability: a callable was injected, or a provider is configured."""
    if llm_generate is not None:
        circuits = llm_circuit_state(llm_generate)
        if circuits["exhausted"]:
            detail = "; ".join(
                f"{k} ({v})" for k, v in circuits["open"].items()
            ) or "all providers circuit-open"
            return CapabilityStatus.UNAVAILABLE, f"all LLM providers circuit-open: {detail}"
        if circuits["open"]:
            detail = "; ".join(f"{k} ({v})" for k, v in circuits["open"].items())
            return CapabilityStatus.DEGRADED, f"circuit open: {detail}"
        return CapabilityStatus.AVAILABLE, "llm_generate injected"
    try:
        from demogorgon.llm.manager import AIProviderManager

        mgr = AIProviderManager()
        if not mgr.available:
            return CapabilityStatus.UNAVAILABLE, "no LLM provider configured"
        # configured but untested — degraded until first successful call
        return CapabilityStatus.DEGRADED, f"provider={mgr.active_provider or 'unknown'}"
    except Exception as e:  # noqa: BLE001
        return CapabilityStatus.UNAVAILABLE, f"provider manager error: {e}"


def _probe_recon(tool_registry: Any = None) -> Any:
    """Recon capability: tool registry present AND recon engine importable."""
    if importlib.util.find_spec("demogorgon.recon.engine") is None:
        return CapabilityStatus.UNAVAILABLE, "demogorgon.recon not importable"
    if tool_registry is None:
        return CapabilityStatus.DEGRADED, "no tool registry — passive stages only"
    try:
        available = (
            tool_registry.get_available_tools()
            if hasattr(tool_registry, "get_available_tools")
            else []
        )
    except Exception as e:  # noqa: BLE001
        return CapabilityStatus.DEGRADED, f"tool registry error: {e}"
    if not available:
        return CapabilityStatus.DEGRADED, "tool registry has no available tools"
    return CapabilityStatus.AVAILABLE, f"{len(available)} tools available"


def _probe_network(target: str = "") -> Any:
    """Network capability: outbound HTTPS works (or explicitly disabled)."""
    import os

    if os.environ.get("DEMOGORGON_OFFLINE") == "1":
        return CapabilityStatus.UNAVAILABLE, "DEMOGORGON_OFFLINE=1"
    import socket

    try:
        socket.create_connection(("1.1.1.1", 443), timeout=3).close()
        return CapabilityStatus.AVAILABLE, "outbound 443 ok"
    except OSError as e:
        return CapabilityStatus.UNAVAILABLE, f"no outbound connectivity: {e}"


def _probe_http_client() -> Any:
    """HTTP client capability: an HTTP library is importable."""
    for mod in ("httpx", "aiohttp", "requests"):
        if importlib.util.find_spec(mod):
            return CapabilityStatus.AVAILABLE, mod
    return CapabilityStatus.UNAVAILABLE, "no HTTP library installed"


def _probe_crawler() -> Any:
    if importlib.util.find_spec("demogorgon.core.crawl.pipeline") is None:
        return CapabilityStatus.UNAVAILABLE, "crawl pipeline not importable"
    return CapabilityStatus.AVAILABLE, "crawl pipeline importable"


def _probe_report() -> Any:
    if importlib.util.find_spec("demogorgon.core.reporting") is None:
        return CapabilityStatus.UNAVAILABLE, "reporting module not importable"
    return CapabilityStatus.AVAILABLE, "reporting module importable"


def _probe_deterministic_research() -> Any:
    """Deterministic (no-LLM) research backbone must always exist."""
    if importlib.util.find_spec("demogorgon.core.research_loop.deterministic") is None:
        return CapabilityStatus.UNAVAILABLE, "deterministic backbone missing"
    return CapabilityStatus.AVAILABLE, "deterministic backbone present"


def _probe_tools_binaries() -> Any:
    """Optional external binaries used by recon stages."""
    found = [b for b in ("httpx", "subfinder", "nmap", "dnsx") if shutil.which(b)]
    if not found:
        return CapabilityStatus.DEGRADED, "no external recon binaries on PATH"
    return CapabilityStatus.AVAILABLE, f"binaries: {', '.join(found)}"


def build_environment_registry(
    llm_generate: Any = None,
    tool_registry: Any = None,
    target: str = "",
) -> CapabilityRegistry:
    """Build the standard environment capability registry for a run."""
    registry = CapabilityRegistry()
    registry.register(
        "llm",
        description="LLM provider for research reasoning",
        required=False,
        probe=lambda: _probe_llm(llm_generate),
    )
    registry.register(
        "deterministic_research",
        description="No-LLM deterministic research backbone",
        required=True,
        probe=_probe_deterministic_research,
    )
    registry.register(
        "recon",
        description="Recon engine + tool registry",
        required=False,
        probe=lambda: _probe_recon(tool_registry),
    )
    registry.register(
        "network",
        description="Outbound network connectivity",
        required=False,
        probe=lambda: _probe_network(target),
    )
    registry.register(
        "http_client",
        description="HTTP client library",
        required=False,
        probe=_probe_http_client,
    )
    registry.register(
        "crawler",
        description="Application crawler",
        required=False,
        probe=_probe_crawler,
    )
    registry.register(
        "reporting",
        description="Report generator",
        required=False,
        probe=_probe_report,
    )
    registry.register(
        "recon_binaries",
        description="External recon binaries (httpx, subfinder, …)",
        required=False,
        probe=_probe_tools_binaries,
    )
    return registry
