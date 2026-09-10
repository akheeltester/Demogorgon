"""CORS Detector — tests for CORS misconfiguration."""

from __future__ import annotations

from typing import Any


class CORSDetector:
    """Tests for CORS misconfiguration by sending requests with various Origin headers."""

    EVIL_ORIGINS = [
        "https://evil.com",
        "http://localhost",
        "null",
        "https://127.0.0.1",
        "https://attacker.com",
    ]

    def __init__(self, http_client: Any):
        self.http = http_client

    async def test(self, endpoint: str, method: str = "GET") -> dict[str, Any]:
        findings = []
        evidence = []

        for origin in self.EVIL_ORIGINS:
            result = await self.http.request(
                method=method,
                url=endpoint,
                headers={"Origin": origin},
            )
            acao = result["headers"].get("access-control-allow-origin", "")
            acac = result["headers"].get("access-control-allow-credentials", "")

            evidence.append({
                "origin": origin,
                "acao": acao,
                "acac": acac,
                "status": result["status_code"],
            })

            if acao and (acao == origin or acao == "*"):
                findings.append({
                    "title": f"CORS misconfiguration — reflects Origin: {origin}",
                    "severity": "high" if acac == "true" else "medium",
                    "vuln_class": "cors",
                    "endpoint": endpoint,
                    "evidence": f"ACAO: {acao}, ACAC: {acac}",
                    "origin_tested": origin,
                })

        preflight_result = await self.http.request(
            method="OPTIONS",
            url=endpoint,
            headers={
                "Origin": "https://evil.com",
                "Access-Control-Request-Method": "POST",
            },
        )
        evidence.append({
            "type": "preflight",
            "status": preflight_result["status_code"],
            "headers": {
                k: v for k, v in preflight_result["headers"].items()
                if k.lower().startswith("access-control")
            },
        })

        return {
            "findings": findings,
            "evidence": evidence,
            "tested_origins": len(self.EVIL_ORIGINS),
            "vulnerable": len(findings) > 0,
        }
