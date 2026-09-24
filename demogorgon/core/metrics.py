"""Metrics — collects hunt metrics (discovery, testing, findings) and saves to JSON.

Tracked at every phase boundary so reports can show measurable improvement.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


@dataclass
class HuntMetrics:
    """Collects all measurable outcomes of a hunt."""
    target: str = ""
    start_time: float = field(default_factory=time.time)
    end_time: float = 0.0

    # Discovery
    endpoints_discovered: int = 0
    subdomains_discovered: int = 0
    live_hosts: int = 0
    forms_discovered: int = 0
    openapi_endpoints: int = 0
    admin_paths: int = 0
    js_endpoints: int = 0

    # Testing
    experiments_run: int = 0
    requests_made: int = 0
    unique_actions_tested: int = 0
    tools_invoked: dict[str, int] = field(default_factory=dict)

    # Findings
    findings_total: int = 0
    findings_by_severity: dict[str, int] = field(default_factory=dict)
    findings_by_class: dict[str, int] = field(default_factory=dict)
    reportable_count: int = 0
    avg_confidence: float = 0.0

    # Performance
    parallel_batches: int = 0
    parallel_requests: int = 0
    llm_calls: int = 0
    llm_failures: int = 0

    # Coverage
    vuln_classes_tested: set[str] = field(default_factory=set)
    strategy_changes: int = 0

    def mark_end(self) -> None:
        self.end_time = time.time()

    @property
    def runtime_seconds(self) -> float:
        end = self.end_time or time.time()
        return max(0.0, end - self.start_time)

    @property
    def findings_per_minute(self) -> float:
        mins = self.runtime_seconds / 60.0
        return self.findings_total / mins if mins > 0 else 0.0

    @property
    def endpoints_per_minute(self) -> float:
        mins = self.runtime_seconds / 60.0
        return self.endpoints_discovered / mins if mins > 0 else 0.0

    def record_finding(self, severity: str, vuln_class: str, confidence: float = 0.0) -> None:
        self.findings_total += 1
        sev = (severity or "info").lower()
        self.findings_by_severity[sev] = self.findings_by_severity.get(sev, 0) + 1
        vc = (vuln_class or "unknown").lower()
        self.findings_by_class[vc] = self.findings_by_class.get(vc, 0) + 1
        if confidence >= 0.85:
            self.reportable_count += 1

    def record_tool(self, tool_name: str) -> None:
        self.tools_invoked[tool_name] = self.tools_invoked.get(tool_name, 0) + 1

    def record_llm(self, success: bool = True) -> None:
        self.llm_calls += 1
        if not success:
            self.llm_failures += 1

    def record_parallel(self, batch_size: int) -> None:
        self.parallel_batches += 1
        self.parallel_requests += batch_size

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["vuln_classes_tested"] = sorted(self.vuln_classes_tested)
        d["runtime_seconds"] = self.runtime_seconds
        d["findings_per_minute"] = self.findings_per_minute
        d["endpoints_per_minute"] = self.endpoints_per_minute
        return d

    def summary_lines(self) -> list[str]:
        """Human-readable summary for report header."""
        lines = [
            f"**Runtime:** {self.runtime_seconds:.0f}s",
            f"**Endpoints discovered:** {self.endpoints_discovered}",
            f"**Subdomains:** {self.subdomains_discovered}",
            f"**Experiments run:** {self.experiments_run}",
            f"**Requests made:** {self.requests_made}",
            f"**Parallel batches:** {self.parallel_batches} ({self.parallel_requests} requests)",
            f"**LLM calls:** {self.llm_calls} ({self.llm_failures} failed)",
            f"**Findings:** {self.findings_total} "
            f"(reportable ≥85%: {self.reportable_count})",
        ]
        if self.findings_by_severity:
            sev_parts = [f"{k}:{v}" for k, v in sorted(self.findings_by_severity.items())]
            lines.append(f"**By severity:** {', '.join(sev_parts)}")
        if self.findings_by_class:
            class_parts = [f"{k}:{v}" for k, v in sorted(self.findings_by_class.items())]
            lines.append(f"**By class:** {', '.join(class_parts)}")
        if self.tools_invoked:
            tool_parts = [f"{k}:{v}" for k, v in sorted(self.tools_invoked.items())]
            lines.append(f"**Tools invoked:** {', '.join(tool_parts)}")
        if self.vuln_classes_tested:
            lines.append(f"**Vuln classes tested:** {', '.join(sorted(self.vuln_classes_tested))}")
        lines.append(f"**Findings/min:** {self.findings_per_minute:.2f}")
        lines.append(f"**Endpoints/min:** {self.endpoints_per_minute:.2f}")
        return lines


class MetricsCollector:
    """Singleton-ish collector for the current hunt."""

    def __init__(self, target: str = ""):
        self.metrics = HuntMetrics(target=target)

    def reset(self, target: str = "") -> HuntMetrics:
        self.metrics = HuntMetrics(target=target)
        return self.metrics

    def save(self, path: str | Path) -> Path:
        self.metrics.mark_end()
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(self.metrics.to_dict(), indent=2, default=str))
        return p

    @staticmethod
    def load(path: str | Path) -> HuntMetrics | None:
        p = Path(path)
        if not p.exists():
            return None
        try:
            data = json.loads(p.read_text())
            m = HuntMetrics(target=data.get("target", ""))
            # Read-only properties (computed) that cannot be setattr'd
            readonly = {
                "runtime_seconds", "findings_per_minute", "endpoints_per_minute",
            }
            for k, v in data.items():
                if k in readonly:
                    continue
                if k == "vuln_classes_tested":
                    m.vuln_classes_tested = set(v or [])
                elif hasattr(m, k):
                    try:
                        setattr(m, k, v)
                    except AttributeError:
                        continue
            return m
        except Exception:
            return None
