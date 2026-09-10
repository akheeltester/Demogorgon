"""Logic Tester — tests for business logic flaws."""

from __future__ import annotations

from typing import Any

from sentinel_v2.executors.base import BaseExecutor


class LogicTester(BaseExecutor):
    """Tests for business logic flaws (negative quantities, price manipulation, step skipping)."""

    @property
    def name(self) -> str:
        return "logic_tester"

    @property
    def vuln_class(self) -> str:
        return "business_logic"

    @property
    def description(self) -> str:
        return "Tests for business logic flaws including negative quantities, price manipulation, and step skipping"

    async def test(self, endpoint: str, **kwargs) -> dict[str, Any]:
        findings = []
        evidence = []
        http = kwargs.get("http_client")
        headers = kwargs.get("headers", {})
        method = kwargs.get("method", "POST")
        body = kwargs.get("body", "")
        workflow_type = kwargs.get("workflow_type", "general")

        if not http:
            return {"findings": [], "evidence": [], "error": "No HTTP client"}

        # Test 1: Negative quantities
        if workflow_type in ("purchase", "order", "payment", "transfer"):
            neg_result = await self._test_negative_quantity(http, endpoint, method, headers, body)
            evidence.extend(neg_result["evidence"])
            if neg_result["vulnerable"]:
                findings.append(self._create_finding(
                    title="Business Logic — negative quantity accepted",
                    severity="high",
                    endpoint=endpoint,
                    evidence=f"Negative quantity was accepted in {workflow_type} operation",
                    steps=[
                        "Set quantity to negative value (-1, -100)",
                        "Submit the request",
                        "Verify if balance/credit was added instead of subtracted",
                    ],
                    impact="Credit/refund manipulation, balance increase",
                    confidence=0.8,
                ))

        # Test 2: Price manipulation
        if workflow_type in ("purchase", "order", "checkout"):
            price_result = await self._test_price_manipulation(http, endpoint, method, headers, body)
            evidence.extend(price_result["evidence"])
            if price_result["vulnerable"]:
                findings.append(self._create_finding(
                    title="Business Logic — price/amount parameter modifiable",
                    severity="critical",
                    endpoint=endpoint,
                    evidence="Price or amount parameter can be modified by client",
                    steps=[
                        "Intercept the checkout/payment request",
                        "Modify price/amount to 0 or 1",
                        "Submit modified request",
                        "Verify if order was placed at modified price",
                    ],
                    impact="Free purchases, financial fraud",
                    confidence=0.85,
                ))

        # Test 3: Step skipping
        if workflow_type in ("registration", "onboarding", "checkout"):
            skip_result = await self._test_step_skipping(http, endpoint, method, headers)
            evidence.extend(skip_result["evidence"])
            if skip_result["vulnerable"]:
                findings.append(self._create_finding(
                    title="Business Logic — workflow step can be skipped",
                    severity="medium",
                    endpoint=endpoint,
                    evidence="Workflow step was skipped without validation",
                    steps=[
                        "Skip a required step in the workflow",
                        "Submit final step directly",
                        "Verify if workflow completed without required validation",
                    ],
                    impact="Incomplete verification, bypass required steps",
                    confidence=0.7,
                ))

        # Test 4: Race condition on balance/points
        if workflow_type in ("transfer", "redeem", "claim"):
            race_result = await self._test_balance_race(http, endpoint, method, headers)
            evidence.extend(race_result["evidence"])
            if race_result["vulnerable"]:
                findings.append(self._create_finding(
                    title="Business Logic — race condition on balance operation",
                    severity="high",
                    endpoint=endpoint,
                    evidence="Concurrent balance operations resulted in inconsistent state",
                    steps=[
                        "Send multiple concurrent transfer/redeem requests",
                        "Check if balance was deducted multiple times",
                        "Verify if double-spend occurred",
                    ],
                    impact="Double-spending, balance manipulation",
                    confidence=0.75,
                ))

        return {
            "findings": [f.to_dict() for f in findings],
            "evidence": evidence,
            "tested_count": 4,
            "vulnerable": len(findings) > 0,
        }

    async def _test_negative_quantity(self, http, endpoint: str, method: str,
                                      headers: dict, body: str) -> dict:
        """Test if negative quantities are accepted."""
        evidence = []
        vulnerable = False

        # Try negative quantity in body
        if body:
            import json
            try:
                data = json.loads(body)
                for key in ["quantity", "amount", "count", "qty", "units"]:
                    if key in data:
                        original = data[key]
                        data[key] = -1
                        neg_body = json.dumps(data)
                        result = await http.request(method, endpoint, headers=headers, body=neg_body)
                        evidence.append({
                            "test": f"negative_{key}",
                            "status": result["status_code"],
                            "length": len(result["body"]),
                        })
                        if 200 <= result["status_code"] < 300:
                            vulnerable = True
                        data[key] = original
            except json.JSONDecodeError:
                pass

        # Try negative quantity in URL params
        test_url = f"{endpoint}?quantity=-1"
        result = await http.request("GET", test_url, headers=headers)
        evidence.append({
            "test": "negative_quantity_param",
            "status": result["status_code"],
        })

        return {"vulnerable": vulnerable, "evidence": evidence}

    async def _test_price_manipulation(self, http, endpoint: str, method: str,
                                       headers: dict, body: str) -> dict:
        """Test if price/amount can be manipulated."""
        evidence = []
        vulnerable = False

        if body:
            import json
            try:
                data = json.loads(body)
                for key in ["price", "amount", "total", "cost", "value"]:
                    if key in data:
                        original = data[key]
                        # Try zero price
                        data[key] = 0
                        zero_body = json.dumps(data)
                        result = await http.request(method, endpoint, headers=headers, body=zero_body)
                        evidence.append({
                            "test": f"zero_{key}",
                            "status": result["status_code"],
                            "length": len(result["body"]),
                        })
                        if 200 <= result["status_code"] < 300:
                            vulnerable = True

                        # Try very low price
                        data[key] = 0.01
                        low_body = json.dumps(data)
                        result = await http.request(method, endpoint, headers=headers, body=low_body)
                        evidence.append({
                            "test": f"low_{key}",
                            "status": result["status_code"],
                        })
                        if 200 <= result["status_code"] < 300:
                            vulnerable = True

                        data[key] = original
            except json.JSONDecodeError:
                pass

        return {"vulnerable": vulnerable, "evidence": evidence}

    async def _test_step_skipping(self, http, endpoint: str, method: str,
                                  headers: dict) -> dict:
        """Test if workflow steps can be skipped."""
        evidence = []
        vulnerable = False

        # Try to access final step directly
        result = await http.request(method, endpoint, headers=headers)
        evidence.append({
            "test": "direct_access",
            "status": result["status_code"],
            "length": len(result["body"]),
        })

        # If we get a success response, step was skipped
        if 200 <= result["status_code"] < 300:
            vulnerable = True

        return {"vulnerable": vulnerable, "evidence": evidence}

    async def _test_balance_race(self, http, endpoint: str, method: str,
                                 headers: dict) -> dict:
        """Test race condition on balance operations."""
        import asyncio
        evidence = []
        vulnerable = False

        # Send concurrent requests
        tasks = [http.request(method, endpoint, headers=headers) for _ in range(5)]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        statuses = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                continue
            statuses.append(result["status_code"])
            evidence.append({
                "request": i,
                "status": result["status_code"],
            })

        # Multiple successes suggest race condition
        success_count = sum(1 for s in statuses if 200 <= s < 300)
        if success_count > 1:
            vulnerable = True

        return {"vulnerable": vulnerable, "evidence": evidence}
