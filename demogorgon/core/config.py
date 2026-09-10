"""ResearchConfig — the single source of truth for all hunt configuration.

Replaces LoopConfig and ad-hoc constructor parameters scattered across
Researcher, ResearcherV3, and CLI arg handling.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ResearchConfig:
    """Centralized configuration for a Demogorgon hunt.

    Every component reads from this object. The CLI builds one,
    then passes it to Researcher which threads it through to
    ResearchLoop, HTTPClient, BrowserTool, etc.
    """

    # ── Target ───────────────────────────────────────────────────────
    target_url: str = ""

    # ── Execution controls ───────────────────────────────────────────
    max_experiments: int = 50
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

    # ── Derived helpers ──────────────────────────────────────────────
    @property
    def requests_per_second(self) -> float:
        """Convert delay-between-requests to requests-per-second."""
        return 1.0 / max(self.rate_limit_delay, 0.1)

    def with_overrides(self, **kwargs) -> ResearchConfig:
        """Return a copy with selected fields overridden."""
        import dataclasses
        changes = {k: v for k, v in kwargs.items() if k in {f.name for f in dataclasses.fields(self)}}
        return dataclasses.replace(self, **changes)
