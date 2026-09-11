"""Tool Base — abstract interface for all tool adapters.

Every tool in DEMOGORGON follows this contract:
1. Discover whether it's available on the system
2. Execute actions through a structured interface
3. Return structured results

The LLM never executes arbitrary shell commands.
It proposes actions, and deterministic code validates and executes them.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ToolCategory(Enum):
    """Categories of tools available in DEMOGORGON."""
    RECON = "recon"
    CRAWL = "crawl"
    FUZZ = "fuzz"
    SCAN = "scan"
    BROWSER = "browser"
    PROXY = "proxy"
    DNS = "dns"
    HTTP = "http"
    ANALYSIS = "analysis"
    CUSTOM = "custom"


@dataclass
class ToolCapability:
    """Describes what a tool can do."""
    name: str
    description: str
    input_types: list[str] = field(default_factory=list)  # e.g., ["url", "domain", "ip"]
    output_types: list[str] = field(default_factory=list)  # e.g., ["subdomains", "endpoints"]
    requires_auth: bool = False
    rate_limit: float = 0.0  # requests per second, 0 = unlimited


@dataclass
class ToolResult:
    """Structured result from a tool execution."""
    success: bool
    data: dict[str, Any] = field(default_factory=dict)
    error: str = ""
    tool_name: str = ""
    action: str = ""
    duration: float = 0.0
    items: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "success": self.success,
            "data": self.data,
            "error": self.error,
            "tool_name": self.tool_name,
            "action": self.action,
            "duration": self.duration,
            "item_count": len(self.items),
        }


class Tool(ABC):
    """Abstract base class for all tool adapters.

    Every tool must implement:
    - name: unique identifier
    - category: tool category
    - discover(): check if tool is available
    - execute(): run a structured action
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique tool name, e.g., 'subfinder', 'nmap', 'burp'."""
        pass

    @property
    @abstractmethod
    def category(self) -> ToolCategory:
        """Tool category for classification."""
        pass

    @property
    @abstractmethod
    def capabilities(self) -> list[ToolCapability]:
        """List of what this tool can do."""
        pass

    @abstractmethod
    async def discover(self) -> bool:
        """Check if this tool is available on the system.

        Returns True if the tool is installed and accessible.
        This should be fast and non-destructive.
        """
        pass

    @abstractmethod
    async def execute(self, action: str, params: dict[str, Any]) -> ToolResult:
        """Execute a structured action through this tool.

        Args:
            action: The action to perform (e.g., 'enumerate_subdomains', 'scan_port')
            params: Action-specific parameters

        Returns:
            ToolResult with structured output

        The tool should NEVER:
        - Execute arbitrary shell commands from the LLM
        - Modify system state outside the engagement
        - Access resources outside scope
        """
        pass

    async def health_check(self) -> bool:
        """Quick health check. Override if needed."""
        try:
            return await self.discover()
        except Exception:
            return False

    def __repr__(self) -> str:
        return f"<Tool:{self.name} category={self.category.value}>"
