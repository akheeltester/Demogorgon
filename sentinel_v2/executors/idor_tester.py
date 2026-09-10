"""IDOR Tester — tests endpoints for Insecure Direct Object Reference."""

from __future__ import annotations

from typing import Any


class IDORTester:
    """Tests endpoints with sequential/predictable IDs for unauthorized access."""

    def __init__(self, http_client: Any):
        self.http = http_client

    async def test(
        self,
        endpoint_template: str,
        valid_id: str | None = None,
        id_range: list[str] | None = None,
        auth_token: str | None = None,
    ) -> dict[str, Any]:
        findings = []
        evidence = []

        if id_range is None:
            id_range = ["0", "1", "2", "3", "4", "5", "100", "999", "-1"]

        headers = {}
        if auth_token:
            headers["Authorization"] = f"Bearer {auth_token}"

        baseline_result = None
        if valid_id:
            baseline_url = endpoint_template.replace("{id}", valid_id)
            baseline_result = await self.http.request(
                method="GET", url=baseline_url, headers=headers
            )
            evidence.append({
                "type": "baseline",
                "id": valid_id,
                "status": baseline_result["status_code"],
                "length": len(baseline_result["body"]),
            })

        no_auth_result = await self.http.request(
            method="GET",
            url=endpoint_template.replace("{id}", id_range[0] if id_range else "1"),
            headers={},
        )
        evidence.append({
            "type": "no_auth",
            "status": no_auth_result["status_code"],
            "length": len(no_auth_result["body"]),
        })

        if 200 <= no_auth_result["status_code"] < 400:
            findings.append({
                "title": f"IDOR — endpoint accessible without authentication",
                "severity": "high",
                "vuln_class": "idor",
                "endpoint": endpoint_template,
                "evidence": f"No auth returned {no_auth_result['status_code']}, body length {len(no_auth_result['body'])}",
            })

        for test_id in id_range:
            if valid_id and test_id == valid_id:
                continue

            test_url = endpoint_template.replace("{id}", test_id)
            result = await self.http.request(
                method="GET", url=test_url, headers=headers
            )
            evidence.append({
                "type": "id_test",
                "id": test_id,
                "status": result["status_code"],
                "length": len(result["body"]),
            })

            if baseline_result and 200 <= result["status_code"] < 400:
                if result["status_code"] == baseline_result["status_code"]:
                    if len(result["body"]) == len(baseline_result["body"]):
                        findings.append({
                            "title": f"IDOR — access to resource ID {test_id}",
                            "severity": "high",
                            "vuln_class": "idor",
                            "endpoint": test_url,
                            "evidence": f"ID {test_id} returned same response as baseline (status={result['status_code']}, length={len(result['body'])})",
                        })

        return {
            "findings": findings,
            "evidence": evidence,
            "ids_tested": len(id_range),
            "vulnerable": len(findings) > 0,
        }
