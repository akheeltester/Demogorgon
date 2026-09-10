"""XSS Detector — tests input parameters for reflected/stored XSS."""

from __future__ import annotations

from typing import Any


class XSSDetector:
    """Tests input parameters for XSS using payload mutation."""

    PAYLOADS = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "javascript:alert(1)",
        "{{7*7}}",
        "${7*7}",
        "'-alert(1)-'",
        "\"><script>alert(1)</script>",
        "<iframe src=javascript:alert(1)>",
        "<body onload=alert(1)>",
    ]

    def __init__(self, http_client: Any):
        self.http = http_client

    async def test(
        self,
        endpoint: str,
        method: str = "POST",
        param_name: str = "q",
        body_template: dict[str, Any] | None = None,
        content_type: str = "application/json",
    ) -> dict[str, Any]:
        findings = []
        evidence = []

        for payload in self.PAYLOADS:
            if method == "GET":
                url = f"{endpoint}?{param_name}={payload}"
                result = await self.http.request(method="GET", url=url)
            else:
                if body_template:
                    body = dict(body_template)
                    body[param_name] = payload
                else:
                    body = {param_name: payload}

                result = await self.http.request(
                    method=method,
                    url=endpoint,
                    headers={"Content-Type": content_type},
                    body=body,
                )

            resp_body = result["body"]
            reflected = payload in resp_body
            html_context = "<" in resp_body and ">" in resp_body

            evidence.append({
                "payload": payload,
                "status": result["status_code"],
                "reflected": reflected,
                "html_context": html_context,
                "body_length": len(resp_body),
            })

            if reflected and html_context:
                findings.append({
                    "title": f"Reflected XSS via {param_name} parameter",
                    "severity": "high",
                    "vuln_class": "xss",
                    "endpoint": endpoint,
                    "evidence": f"Payload '{payload[:50]}' reflected in HTML response",
                    "param": param_name,
                })

        return {
            "findings": findings,
            "evidence": evidence,
            "payloads_tested": len(self.PAYLOADS),
            "vulnerable": len(findings) > 0,
        }
