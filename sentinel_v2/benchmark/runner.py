"""Benchmark Runner — auto-runs against vulnerable applications and compares results."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class BenchmarkTarget:
    name: str
    url: str
    expected_findings: list[dict[str, str]]
    description: str = ""


@dataclass
class BenchmarkResult:
    target: str
    actual_findings: list[dict[str, Any]]
    expected_findings: list[dict[str, str]]
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    coverage: float = 0.0
    runtime: float = 0.0
    passed: bool = False

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "false_negatives": self.false_negatives,
            "coverage": self.coverage,
            "runtime": self.runtime,
            "passed": self.passed,
            "actual_count": len(self.actual_findings),
            "expected_count": len(self.expected_findings),
        }


BENCHMARK_TARGETS: list[BenchmarkTarget] = [
    BenchmarkTarget(
        name="EEMS",
        url="http://172.16.0.66:30005",
        expected_findings=[
            {"vuln_class": "cors", "severity": "high", "title": "CORS misconfiguration"},
            {"vuln_class": "auth_bypass", "severity": "critical", "title": "Dashboard accessible without auth"},
        ],
        description="Enterprise Employee Management System — local test target",
    ),
]


class BenchmarkRunner:
    """Runs benchmarks against vulnerable applications."""

    def __init__(self, output_dir: str = "benchmark_results"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.results: list[BenchmarkResult] = []

    async def run_all(self, sentinel_fn) -> list[BenchmarkResult]:
        for target in BENCHMARK_TARGETS:
            result = await self.run_target(target, sentinel_fn)
            self.results.append(result)
        self._save_results()
        return self.results

    async def run_target(
        self, target: BenchmarkTarget, sentinel_fn
    ) -> BenchmarkResult:
        start = time.time()
        actual_findings = await sentinel_fn(target.url)
        runtime = time.time() - start

        true_positives = 0
        false_positives = 0
        matched_expected = set()

        for actual in actual_findings:
            matched = False
            for i, expected in enumerate(target.expected_findings):
                if i not in matched_expected:
                    if (
                        actual.get("vuln_class") == expected.get("vuln_class")
                        or expected.get("title", "").lower() in actual.get("title", "").lower()
                    ):
                        true_positives += 1
                        matched_expected.add(i)
                        matched = True
                        break
            if not matched:
                false_positives += 1

        false_negatives = len(target.expected_findings) - len(matched_expected)
        coverage = len(matched_expected) / len(target.expected_findings) if target.expected_findings else 0

        return BenchmarkResult(
            target=target.name,
            actual_findings=actual_findings,
            expected_findings=target.expected_findings,
            true_positives=true_positives,
            false_positives=false_positives,
            false_negatives=false_negatives,
            coverage=coverage,
            runtime=runtime,
            passed=coverage >= 0.8 and false_positives <= 2,
        )

    def _save_results(self) -> None:
        results_data = {
            "timestamp": time.time(),
            "results": [r.to_dict() for r in self.results],
            "summary": {
                "total_targets": len(self.results),
                "passed": sum(1 for r in self.results if r.passed),
                "failed": sum(1 for r in self.results if not r.passed),
                "average_coverage": (
                    sum(r.coverage for r in self.results) / len(self.results)
                    if self.results else 0
                ),
            },
        }
        path = self.output_dir / "benchmark_results.json"
        path.write_text(json.dumps(results_data, indent=2))

    def get_regression_report(self, previous_results: list[dict] | None = None) -> dict[str, Any]:
        if not previous_results:
            return {"status": "no_previous_results"}

        current = {r.target: r for r in self.results}
        previous = {r["target"]: r for r in previous_results}

        regressions = []
        improvements = []

        for target_name in current:
            if target_name in previous:
                curr = current[target_name]
                prev = previous[target_name]
                if curr.coverage < prev.coverage:
                    regressions.append({
                        "target": target_name,
                        "previous_coverage": prev.coverage,
                        "current_coverage": curr.coverage,
                    })
                elif curr.coverage > prev.coverage:
                    improvements.append({
                        "target": target_name,
                        "previous_coverage": prev.coverage,
                        "current_coverage": curr.coverage,
                    })

        return {
            "regressions": regressions,
            "improvements": improvements,
            "build_should_fail": len(regressions) > 0,
        }
