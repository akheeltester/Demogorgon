"""Tool Selection Matrix — maps vulnerability classes to deterministic executors.

Each executor is a standalone module that generates payloads and tests for a
specific vulnerability class. The controller invokes the appropriate executor
based on the hypothesis.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class ExecutorSpec:
    name: str
    vuln_class: str
    module_path: str
    class_name: str
    description: str
    requires_auth: bool = False
    requires_token: bool = False
    input_types: list[str] = None

    def __post_init__(self):
        if self.input_types is None:
            self.input_types = ["endpoint", "parameter"]


EXECUTOR_REGISTRY: dict[str, ExecutorSpec] = {
    "cors_detector": ExecutorSpec(
        name="cors_detector",
        vuln_class="cors",
        module_path="sentinel_v2.executors.cors_detector",
        class_name="CORSDetector",
        description="Tests for CORS misconfiguration by sending requests with various Origin headers and checking response headers",
        requires_auth=False,
        input_types=["endpoint"],
    ),
    "jwt_attacker": ExecutorSpec(
        name="jwt_attacker",
        vuln_class="jwt",
        module_path="sentinel_v2.executors.jwt_attacker",
        class_name="JWTAttacker",
        description="Tests JWT tokens for alg:none, role manipulation, exp bypass, and key confusion",
        requires_auth=True,
        requires_token=True,
        input_types=["token"],
    ),
    "idor_tester": ExecutorSpec(
        name="idor_tester",
        vuln_class="idor",
        module_path="sentinel_v2.executors.idor_tester",
        class_name="IDORTester",
        description="Tests endpoints with sequential/ predictable IDs for unauthorized access",
        requires_auth=True,
        input_types=["endpoint", "parameter", "id_range"],
    ),
    "xss_detector": ExecutorSpec(
        name="xss_detector",
        vuln_class="xss",
        module_path="sentinel_v2.executors.xss_detector",
        class_name="XSSDetector",
        description="Tests input parameters for reflected/stored XSS using payload mutation",
        input_types=["endpoint", "parameter", "form"],
    ),
    "auth_bypass_tester": ExecutorSpec(
        name="auth_bypass_tester",
        vuln_class="auth_bypass",
        module_path="sentinel_v2.executors.auth_bypass_tester",
        class_name="AuthBypassTester",
        description="Tests endpoints for authentication bypass (no auth, expired token, modified token)",
        input_types=["endpoint"],
    ),
    "privesc_tester": ExecutorSpec(
        name="privesc_tester",
        vuln_class="privesc",
        module_path="sentinel_v2.executors.privesc_tester",
        class_name="PrivescTester",
        description="Tests for privilege escalation via role manipulation, parameter injection",
        requires_auth=True,
        input_types=["endpoint", "parameter"],
    ),
    "sqli_detector": ExecutorSpec(
        name="sqli_detector",
        vuln_class="sqli",
        module_path="sentinel_v2.executors.sqli_detector",
        class_name="SQLiDetector",
        description="Tests for SQL injection using time-based, boolean, and error-based techniques",
        input_types=["endpoint", "parameter"],
    ),
    "ssrf_tester": ExecutorSpec(
        name="ssrf_tester",
        vuln_class="ssrf",
        module_path="sentinel_v2.executors.ssrf_tester",
        class_name="SSRFTester",
        description="Tests for server-side request forgery using internal URLs and metadata endpoints",
        input_types=["endpoint", "parameter"],
    ),
    "race_detector": ExecutorSpec(
        name="race_detector",
        vuln_class="race",
        module_path="sentinel_v2.executors.race_detector",
        class_name="RaceDetector",
        description="Tests for race conditions by sending concurrent requests to state-changing endpoints",
        requires_auth=True,
        input_types=["endpoint"],
    ),
    "info_disclosure_detector": ExecutorSpec(
        name="info_disclosure_detector",
        vuln_class="info_disclosure",
        module_path="sentinel_v2.executors.info_disclosure_detector",
        class_name="InfoDisclosureDetector",
        description="Tests for information disclosure via error messages, headers, and verbose responses",
        input_types=["endpoint"],
    ),
    "csrf_tester": ExecutorSpec(
        name="csrf_tester",
        vuln_class="csrf",
        module_path="sentinel_v2.executors.csrf_tester",
        class_name="CSRFTester",
        description="Tests for cross-site request forgery by sending state-changing requests without tokens",
        requires_auth=True,
        input_types=["endpoint"],
    ),
    "upload_tester": ExecutorSpec(
        name="upload_tester",
        vuln_class="file_upload",
        module_path="sentinel_v2.executors.upload_tester",
        class_name="UploadTester",
        description="Tests file upload endpoints for unrestricted file types, path traversal, and webshell upload",
        input_types=["endpoint"],
    ),
    "ssti_detector": ExecutorSpec(
        name="ssti_detector",
        vuln_class="ssti",
        module_path="sentinel_v2.executors.ssti_detector",
        class_name="SSTIDetector",
        description="Tests for server-side template injection using template syntax payloads",
        input_types=["endpoint", "parameter"],
    ),
    "xxe_detector": ExecutorSpec(
        name="xxe_detector",
        vuln_class="xxe",
        module_path="sentinel_v2.executors.xxe_detector",
        class_name="XXEDetector",
        description="Tests for XML external entity injection using DTD payloads",
        input_types=["endpoint"],
    ),
    "redirect_tester": ExecutorSpec(
        name="redirect_tester",
        vuln_class="open_redirect",
        module_path="sentinel_v2.executors.redirect_tester",
        class_name="RedirectTester",
        description="Tests for open redirect using various redirect parameter patterns",
        input_types=["endpoint", "parameter"],
    ),
    "logic_tester": ExecutorSpec(
        name="logic_tester",
        vuln_class="business_logic",
        module_path="sentinel_v2.executors.logic_tester",
        class_name="LogicTester",
        description="Tests for business logic flaws (negative quantities, price manipulation, step skipping)",
        requires_auth=True,
        input_types=["endpoint", "workflow"],
    ),
}


def get_executor_spec(vuln_class: str) -> ExecutorSpec | None:
    for spec in EXECUTOR_REGISTRY.values():
        if spec.vuln_class == vuln_class:
            return spec
    return None


def get_executor_by_name(name: str) -> ExecutorSpec | None:
    return EXECUTOR_REGISTRY.get(name)


def list_executors() -> list[ExecutorSpec]:
    return list(EXECUTOR_REGISTRY.values())


def get_vuln_class_for_executor(executor_name: str) -> str | None:
    spec = EXECUTOR_REGISTRY.get(executor_name)
    return spec.vuln_class if spec else None
