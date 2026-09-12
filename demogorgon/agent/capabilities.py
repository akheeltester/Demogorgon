"""Capability Registry — capability-based tool abstraction.

Tools are registered by what they CAN DO (capabilities), not by name.
The LLM discovers available capabilities and selects the best tool.
MCP servers and built-in tools share the same capability interface.

Usage:
    registry = CapabilityRegistry()
    registry.register_tool("subfinder", capabilities=["subdomain_enum"])
    registry.register_tool("amass", capabilities=["subdomain_enum", "dns_recon"])

    # Find tools that can do subdomain enumeration
    tools = registry.find_tools_for_capability("subdomain_enum")
    # Returns both subfinder and amass, ranked by reliability

    # Get all available capabilities
    caps = registry.get_available_capabilities()
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class CapabilityCategory(Enum):
    """High-level capability categories."""
    RECON = "recon"
    DISCOVERY = "discovery"
    SCANNING = "scanning"
    FUZZING = "fuzzing"
    CRAWLING = "crawling"
    EXPLOITATION = "exploitation"
    VALIDATION = "validation"
    REPORTING = "reporting"
    PROXY = "proxy"
    DNS = "dns"
    HTTP = "http"
    BROWSER = "browser"
    ANALYSIS = "analysis"


# All known capabilities with descriptions
KNOWN_CAPABILITIES: dict[str, dict[str, Any]] = {
    # Recon
    "subdomain_enum": {
        "description": "Enumerate subdomains for a domain",
        "category": CapabilityCategory.RECON,
        "input_types": ["domain"],
        "output_types": ["subdomains"],
    },
    "dns_recon": {
        "description": "DNS reconnaissance and record enumeration",
        "category": CapabilityCategory.DNS,
        "input_types": ["domain"],
        "output_types": ["dns_records", "ips"],
    },
    "port_scan": {
        "description": "Scan ports on a target",
        "category": CapabilityCategory.SCANNING,
        "input_types": ["ip", "domain"],
        "output_types": ["open_ports", "services"],
    },
    "tech_detect": {
        "description": "Detect technologies used by a web application",
        "category": CapabilityCategory.ANALYSIS,
        "input_types": ["url"],
        "output_types": ["technologies", "headers"],
    },

    # Discovery
    "url_discovery": {
        "description": "Discover URLs and endpoints",
        "category": CapabilityCategory.DISCOVERY,
        "input_types": ["url", "domain"],
        "output_types": ["urls", "endpoints"],
    },
    "param_discovery": {
        "description": "Discover hidden parameters",
        "category": CapabilityCategory.DISCOVERY,
        "input_types": ["url"],
        "output_types": ["parameters"],
    },
    "js_analysis": {
        "description": "Analyze JavaScript for secrets and endpoints",
        "category": CapabilityCategory.ANALYSIS,
        "input_types": ["url", "js_content"],
        "output_types": ["endpoints", "secrets", "api_keys"],
    },

    # Scanning
    "vuln_scan": {
        "description": "Scan for known vulnerabilities",
        "category": CapabilityCategory.SCANNING,
        "input_types": ["url", "target"],
        "output_types": ["vulnerabilities"],
    },
    "dir_scan": {
        "description": "Directory and file brute-forcing",
        "category": CapabilityCategory.FUZZING,
        "input_types": ["url"],
        "output_types": ["directories", "files"],
    },
    "param_fuzz": {
        "description": "Parameter fuzzing",
        "category": CapabilityCategory.FUZZING,
        "input_types": ["url"],
        "output_types": ["parameters", "values"],
    },

    # HTTP
    "http_request": {
        "description": "Make HTTP requests",
        "category": CapabilityCategory.HTTP,
        "input_types": ["url"],
        "output_types": ["response"],
    },
    "http_method_test": {
        "description": "Test different HTTP methods",
        "category": CapabilityCategory.HTTP,
        "input_types": ["url"],
        "output_types": ["response", "allowed_methods"],
    },

    # Browser
    "browser_render": {
        "description": "Render JavaScript-heavy pages",
        "category": CapabilityCategory.BROWSER,
        "input_types": ["url"],
        "output_types": ["rendered_html", "dom"],
    },
    "browser_interact": {
        "description": "Interact with web pages (click, fill forms)",
        "category": CapabilityCategory.BROWSER,
        "input_types": ["url"],
        "output_types": ["dom", "cookies", "responses"],
    },

    # Exploitation
    "sqli_test": {
        "description": "Test for SQL injection",
        "category": CapabilityCategory.EXPLOITATION,
        "input_types": ["url", "parameter"],
        "output_types": ["vulnerability", "evidence"],
    },
    "xss_test": {
        "description": "Test for cross-site scripting",
        "category": CapabilityCategory.EXPLOITATION,
        "input_types": ["url", "parameter"],
        "output_types": ["vulnerability", "evidence"],
    },
    "ssrf_test": {
        "description": "Test for server-side request forgery",
        "category": CapabilityCategory.EXPLOITATION,
        "input_types": ["url", "parameter"],
        "output_types": ["vulnerability", "evidence"],
    },
    "idor_test": {
        "description": "Test for insecure direct object references",
        "category": CapabilityCategory.EXPLOITATION,
        "input_types": ["url", "parameter"],
        "output_types": ["vulnerability", "evidence"],
    },
    "open_redirect_test": {
        "description": "Test for open redirect vulnerabilities",
        "category": CapabilityCategory.EXPLOITATION,
        "input_types": ["url", "parameter"],
        "output_types": ["vulnerability", "evidence"],
    },
    "auth_bypass_test": {
        "description": "Test for authentication bypass",
        "category": CapabilityCategory.EXPLOITATION,
        "input_types": ["url"],
        "output_types": ["vulnerability", "evidence"],
    },
    "file_upload_test": {
        "description": "Test for file upload vulnerabilities",
        "category": CapabilityCategory.EXPLOITATION,
        "input_types": ["url"],
        "output_types": ["vulnerability", "evidence"],
    },
    "ssti_test": {
        "description": "Test for server-side template injection",
        "category": CapabilityCategory.EXPLOITATION,
        "input_types": ["url", "parameter"],
        "output_types": ["vulnerability", "evidence"],
    },

    # Validation
    "vuln_validate": {
        "description": "Validate a reported vulnerability",
        "category": CapabilityCategory.VALIDATION,
        "input_types": ["vulnerability_report"],
        "output_types": ["validated", "confidence"],
    },
    "fp_check": {
        "description": "Check if a finding is a false positive",
        "category": CapabilityCategory.VALIDATION,
        "input_types": ["finding"],
        "output_types": ["is_fp", "reason"],
    },
}


@dataclass
class ToolCapabilityBinding:
    """A tool's capability registration."""
    tool_name: str
    capability: str
    reliability: float = 0.5  # 0-1, how reliable this tool is for this capability
    speed: float = 0.5  # 0-1, how fast this tool is
    cost: float = 0.0  # 0-1, resource cost (0 = free)
    last_used: float = 0.0
    success_count: int = 0
    failure_count: int = 0
    mcp_server: str = ""  # empty = built-in tool

    @property
    def success_rate(self) -> float:
        total = self.success_count + self.failure_count
        if total == 0:
            return 0.5
        return self.success_count / total

    def to_dict(self) -> dict:
        return {
            "tool_name": self.tool_name,
            "capability": self.capability,
            "reliability": self.reliability,
            "speed": self.speed,
            "cost": self.cost,
            "success_rate": self.success_rate,
            "success_count": self.success_count,
            "failure_count": self.failure_count,
            "mcp_server": self.mcp_server,
        }


@dataclass
class CapabilityRequest:
    """A request for a capability."""
    capability: str
    input_type: str = ""
    context: dict[str, Any] = field(default_factory=dict)
    prefer_fast: bool = False
    prefer_reliable: bool = True
    exclude_tools: list[str] = field(default_factory=list)


class CapabilityRegistry:
    """Capability-based tool registry.

    Tools are registered by what they CAN DO (capabilities).
    The agent discovers capabilities and selects the best tool.

    Usage:
        registry = CapabilityRegistry()

        # Register built-in tools
        registry.register_tool("subfinder", capabilities=["subdomain_enum"])
        registry.register_tool("httpx", capabilities=["http_request", "tech_detect"])

        # Register MCP tools
        registry.register_tool("burp_scan", capabilities=["vuln_scan"], mcp_server="burp")

        # Find best tool for a capability
        best = registry.find_best_tool(CapabilityRequest(capability="subdomain_enum"))
    """

    def __init__(self):
        self._bindings: dict[str, list[ToolCapabilityBinding]] = {}  # capability -> bindings
        self._tools: dict[str, list[str]] = {}  # tool_name -> capabilities
        self._tool_metadata: dict[str, dict[str, Any]] = {}

    def register_tool(
        self,
        tool_name: str,
        capabilities: list[str],
        reliability: float = 0.5,
        speed: float = 0.5,
        cost: float = 0.0,
        mcp_server: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Register a tool with its capabilities."""
        self._tools[tool_name] = capabilities
        if metadata:
            self._tool_metadata[tool_name] = metadata

        for cap in capabilities:
            if cap not in self._bindings:
                self._bindings[cap] = []

            # Check if already registered
            existing = [b for b in self._bindings[cap] if b.tool_name == tool_name]
            if existing:
                # Update
                existing[0].reliability = reliability
                existing[0].speed = speed
                existing[0].cost = cost
                existing[0].mcp_server = mcp_server
            else:
                binding = ToolCapabilityBinding(
                    tool_name=tool_name,
                    capability=cap,
                    reliability=reliability,
                    speed=speed,
                    cost=cost,
                    mcp_server=mcp_server,
                )
                self._bindings[cap].append(binding)

    def unregister_tool(self, tool_name: str) -> None:
        """Remove a tool from all capabilities."""
        if tool_name in self._tools:
            del self._tools[tool_name]

        for cap, bindings in self._bindings.items():
            self._bindings[cap] = [b for b in bindings if b.tool_name != tool_name]

    def find_tools_for_capability(self, capability: str) -> list[ToolCapabilityBinding]:
        """Find all tools that provide a capability, ranked by score."""
        bindings = self._bindings.get(capability, [])
        return sorted(bindings, key=lambda b: self._score_binding(b), reverse=True)

    def find_best_tool(self, request: CapabilityRequest) -> ToolCapabilityBinding | None:
        """Find the best tool for a capability request."""
        bindings = self.find_tools_for_capability(request.capability)

        # Filter excluded tools
        bindings = [b for b in bindings if b.tool_name not in request.exclude_tools]

        if not bindings:
            return None

        # Score and rank
        scored = [(b, self._score_binding(b, request)) for b in bindings]
        scored.sort(key=lambda x: x[1], reverse=True)

        return scored[0][0]

    def find_tools_for_capabilities(self, capabilities: list[str]) -> dict[str, list[ToolCapabilityBinding]]:
        """Find tools for multiple capabilities."""
        result = {}
        for cap in capabilities:
            result[cap] = self.find_tools_for_capability(cap)
        return result

    def get_available_capabilities(self) -> list[str]:
        """Get all capabilities with at least one registered tool."""
        return [cap for cap, bindings in self._bindings.items() if bindings]

    def get_capability_info(self, capability: str) -> dict[str, Any] | None:
        """Get info about a capability."""
        info = KNOWN_CAPABILITIES.get(capability, {})
        bindings = self._bindings.get(capability, [])
        return {
            "name": capability,
            "description": info.get("description", ""),
            "category": info.get("category", CapabilityCategory.ANALYSIS).value,
            "input_types": info.get("input_types", []),
            "output_types": info.get("output_types", []),
            "available_tools": len(bindings),
            "tools": [b.tool_name for b in bindings],
        }

    def get_tools_for_mcp_server(self, server_name: str) -> list[ToolCapabilityBinding]:
        """Get all capabilities from a specific MCP server."""
        result = []
        for bindings in self._bindings.values():
            for b in bindings:
                if b.mcp_server == server_name:
                    result.append(b)
        return result

    def record_success(self, tool_name: str, capability: str) -> None:
        """Record a successful tool execution."""
        for bindings in self._bindings.values():
            for b in bindings:
                if b.tool_name == tool_name and b.capability == capability:
                    b.success_count += 1
                    b.last_used = time.time()

    def record_failure(self, tool_name: str, capability: str) -> None:
        """Record a failed tool execution."""
        for bindings in self._bindings.values():
            for b in bindings:
                if b.tool_name == tool_name and b.capability == capability:
                    b.failure_count += 1
                    b.last_used = time.time()

    def _score_binding(
        self,
        binding: ToolCapabilityBinding,
        request: CapabilityRequest | None = None,
    ) -> float:
        """Score a tool binding for ranking."""
        score = 0.0

        # Reliability (40%)
        score += binding.reliability * 0.4

        # Success rate (30%)
        score += binding.success_rate * 0.3

        # Speed (20%)
        if request and request.prefer_fast:
            score += binding.speed * 0.2
        else:
            score += binding.speed * 0.1

        # Recency (10%)
        if binding.last_used > 0:
            age = time.time() - binding.last_used
            recency = max(0, 1.0 - (age / 86400))  # Decay over 24h
            score += recency * 0.1

        # Cost penalty
        score -= binding.cost * 0.1

        return score

    def get_status(self) -> dict[str, Any]:
        """Get registry status."""
        return {
            "total_tools": len(self._tools),
            "total_capabilities": len(self._bindings),
            "available_capabilities": len(self.get_available_capabilities()),
            "tools": {
                name: caps for name, caps in self._tools.items()
            },
        }

    def to_llm_context(self) -> str:
        """Generate a capability summary for LLM context."""
        lines = ["Available Capabilities:"]
        for cap in self.get_available_capabilities():
            info = KNOWN_CAPABILITIES.get(cap, {})
            bindings = self._bindings[cap]
            tool_names = [b.tool_name for b in bindings]
            lines.append(f"  - {cap}: {info.get('description', '')}")
            lines.append(f"    Tools: {', '.join(tool_names)}")
        return "\n".join(lines)
