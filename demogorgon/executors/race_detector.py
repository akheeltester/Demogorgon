"""Race Condition Detector — tests for race conditions using concurrent requests."""

from __future__ import annotations

import asyncio
from typing import Any

from demogorgon.executors.base import BaseExecutor


class RaceDetector(BaseExecutor):
    """Tests for race conditions by sending concurrent requests to state-changing endpoints."""

    # Common race condition targets
    RACE_ENDPOINTS = [
        "transfer", "withdraw", "purchase", "redeem", "claim",
        "apply", "submit", "approve", "reject", "delete",
        "create", "update", "modify", "change", "set",
    ]

    @property
    def name(self) -> str:
        return "race_detector"

    @property
    def vuln_class(self) -> str:
        return "race"

    @property
    def description(self) -> str:
        return "Tests for race conditions using concurrent requests to state-changing endpoints"

    async def test(self, endpoint: str, **kwargs) -> dict[str, Any]:
        findings = []
        evidence = []
        http = kwargs.get("http_client")
        headers = kwargs.get("headers", {})
        method = kwargs.get("method", "POST")
        body = kwargs.get("body")
        concurrency = kwargs.get("concurrency", 5)

        if not http:
            return {"findings": [], "evidence": [], "error": "No HTTP client"}

        # Send concurrent requests
        tasks = []
        for i in range(concurrency):
            task = http.request(method, endpoint, headers=headers, body=body)
            tasks.append(task)

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Analyze results
        statuses = []
        lengths = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                evidence.append({
                    "request": i,
                    "error": str(result),
                })
                continue

            statuses.append(result["status_code"])
            lengths.append(len(result["body"]))
            evidence.append({
                "request": i,
                "status": result["status_code"],
                "length": len(result["body"]),
                "snippet": result["body"][:200],
            })

        # Check for race condition indicators
        if len(set(statuses)) > 1:
            # Different status codes suggest race condition
            findings.append(self._create_finding(
                title=f"Race Condition — inconsistent responses across {concurrency} concurrent requests",
                severity="high",
                endpoint=endpoint,
                evidence=f"Status codes: {statuses}. Multiple requests returned different statuses.",
                steps=[
                    f"Send {concurrency} concurrent {method} requests to {endpoint}",
                    "Observe different response statuses",
                    "Analyze which requests succeeded/failed",
                    "Determine if state was modified multiple times",
                ],
                impact="Double-spending, duplicate transactions, state corruption",
                confidence=0.7,
            ))
        elif len(set(lengths)) > 50:
            # Different response lengths suggest partial success
            findings.append(self._create_finding(
                title=f"Race Condition — response length variation across {concurrency} requests",
                severity="medium",
                endpoint=endpoint,
                evidence=f"Response lengths: {lengths}. Variation suggests partial success.",
                steps=[
                    f"Send {concurrency} concurrent {method} requests to {endpoint}",
                    "Compare response lengths",
                    "Determine if some requests were processed differently",
                ],
                impact="Inconsistent state, partial transaction processing",
                confidence=0.5,
            ))

        # Check for success in multiple requests (double-spend)
        success_count = sum(1 for s in statuses if 200 <= s < 300)
        if success_count > 1:
            findings.append(self._create_finding(
                title=f"Race Condition — {success_count}/{concurrency} requests succeeded",
                severity="high",
                endpoint=endpoint,
                evidence=f"Multiple requests succeeded: {success_count} out of {concurrency}",
                steps=[
                    f"Send {concurrency} concurrent {method} requests to {endpoint}",
                    f"Observe {success_count} successful responses",
                    "Verify if state was modified multiple times",
                ],
                impact="Double-spending, duplicate resource creation",
                confidence=0.8,
            ))

        return {
            "findings": [f.to_dict() for f in findings],
            "evidence": evidence,
            "tested_count": concurrency,
            "vulnerable": len(findings) > 0,
        }
