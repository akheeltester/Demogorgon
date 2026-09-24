"""ResearchConfig — the single source of truth for all hunt configuration.

Replaces LoopConfig and ad-hoc constructor parameters scattered across
Researcher, ResearcherV3, and CLI arg handling.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class AIConfig:
    provider: str = ""
    api_key: str = ""
    base_url: str = ""
    model: str = ""
    reasoning_model: str = ""
    fast_model: str = ""


@dataclass
class LayaConfig:
    enabled: bool = True
    confidence_threshold: float = 0.75
    fallback_to_llm: bool = True


@dataclass
class SafetyConfig:
    strict_scope: bool = True
    require_authorization: bool = True
    hitl_level: str = "AUTOMATIC"


@dataclass
class ToolsConfig:
    nmap_enabled: bool = False
    nuclei_enabled: bool = True
    ffuf_enabled: bool = True
    subfinder_enabled: bool = False
    httpx_enabled: bool = False
    burp_enabled: bool = False
    nessus_enabled: bool = False


@dataclass
class DemogorgonConfig:
    """Centralized configuration for a Demogorgon hunt."""

    # ── Target & Auth ────────────────────────────────────────────────
    target_url: str = ""
    authorization_confirmed: bool = False
    
    # ── Sub-configs ──────────────────────────────────────────────────
    ai: AIConfig = field(default_factory=AIConfig)
    laya: LayaConfig = field(default_factory=LayaConfig)
    safety: SafetyConfig = field(default_factory=SafetyConfig)
    tools: ToolsConfig = field(default_factory=ToolsConfig)

    # ── Execution controls ───────────────────────────────────────────
    max_experiments: int = 50
    max_requests: int = 500
    max_cost: float = 2.0
    rate_limit_delay: float = 1.0          # seconds between requests
    headless: bool = True
    proxy: str | None = None
    output_dir: str = "hunt_output"

    # ── Loop tuning ──────────────────────────────────────────────────
    self_eval_interval: int = 20
    stagnation_threshold: int = 5
    max_duplicate_actions: int = 3
    max_same_endpoint: int = 5
    max_same_vuln_class: int = 3
    context_window_limit: int = 8000       # chars for LLM context

    # ── Scope ────────────────────────────────────────────────────────
    extra_scopes: list[str] = field(default_factory=list)
    excluded_hosts: list[str] = field(default_factory=list)

    # ── Mode ─────────────────────────────────────────────────────────
    use_v3: bool = False
    benchmark: bool = False

    @property
    def requests_per_second(self) -> float:
        """Convert delay-between-requests to requests-per-second."""
        return 1.0 / max(self.rate_limit_delay, 0.1)

    def with_overrides(self, **kwargs) -> DemogorgonConfig:
        """Return a copy with selected fields overridden."""
        import dataclasses
        changes = {k: v for k, v in kwargs.items() if k in {f.name for f in dataclasses.fields(self)}}
        return dataclasses.replace(self, **changes)


# Alias for backward compatibility
ResearchConfig = DemogorgonConfig
