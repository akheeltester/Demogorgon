"""Tool Registry — unified registry for all available tools.

The registry:
1. Discovers which tools are installed
2. Maintains a registry of tool adapters
3. Provides a unified interface for tool access
4. Enforces policy-based access control

Usage:
    registry = ToolRegistry()
    await registry.discover_all()

    # Get available tools
    tools = registry.get_available_tools()

    # Execute a tool
    result = await registry.execute("subfinder", "enumerate_subdomains", {"domain": "example.com"})
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any

from .base import Tool, ToolCategory, ToolResult, ToolCapability
from .discovery import discover_all_tools, discover_tool, ToolInfo


@dataclass
class ToolEntry:
    """A registered tool with its adapter and metadata."""
    tool: Tool
    info: ToolInfo
    enabled: bool = True
    policy_allowed: bool = True  # from scope/policy

    @property
    def name(self) -> str:
        return self.tool.name

    @property
    def available(self) -> bool:
        return self.info.available and self.enabled and self.policy_allowed


class ToolRegistry:
    """Unified registry for all available tools.

    The registry is the single point of access for all tool operations.
    It discovers available tools, manages adapters, and enforces policy.
    """

    def __init__(self):
        self._tools: dict[str, ToolEntry] = {}
        self._discovered: dict[str, ToolInfo] = {}
        self._initialized = False

    async def discover_all(self) -> dict[str, bool]:
        """Discover all available tools on the system.

        Returns:
            Dict mapping tool name to availability status.
        """
        self._discovered = discover_all_tools()
        self._initialized = True

        # Update availability for registered tools
        for name, entry in self._tools.items():
            if name in self._discovered:
                entry.info = self._discovered[name]

        return {name: info.available for name, info in self._discovered.items()}

    def register(self, tool: Tool) -> None:
        """Register a tool adapter."""
        info = self._discovered.get(tool.name, ToolInfo(name=tool.name))
        self._tools[tool.name] = ToolEntry(tool=tool, info=info)

    def register_all(self, tools: list[Tool]) -> None:
        """Register multiple tool adapters."""
        for tool in tools:
            self.register(tool)

    def get_available_tools(self) -> list[str]:
        """Get list of available tool names."""
        return [name for name, entry in self._tools.items() if entry.available]

    def get_tool(self, name: str) -> Tool | None:
        """Get a tool adapter by name."""
        entry = self._tools.get(name)
        return entry.tool if entry else None

    def get_tool_info(self, name: str) -> ToolInfo | None:
        """Get tool info by name."""
        return self._discovered.get(name)

    def is_available(self, name: str) -> bool:
        """Check if a tool is available."""
        entry = self._tools.get(name)
        return entry.available if entry else False

    def is_allowed(self, tool_name: str, action: str) -> bool:
        """Check if a tool action is allowed by policy."""
        entry = self._tools.get(tool_name)
        if not entry:
            return False
        return entry.policy_allowed and entry.enabled

    def set_policy(self, tool_name: str, allowed: bool) -> None:
        """Set policy for a tool."""
        if tool_name in self._tools:
            self._tools[tool_name].policy_allowed = allowed

    def enable(self, tool_name: str) -> None:
        """Enable a tool."""
        if tool_name in self._tools:
            self._tools[tool_name].enabled = True

    def disable(self, tool_name: str) -> None:
        """Disable a tool."""
        if tool_name in self._tools:
            self._tools[tool_name].enabled = False

    async def execute(self, tool_name: str, action: str, params: dict[str, Any]) -> ToolResult:
        """Execute a tool action.

        Args:
            tool_name: Name of the tool to execute
            action: The action to perform
            params: Action-specific parameters

        Returns:
            ToolResult with structured output
        """
        entry = self._tools.get(tool_name)
        if not entry:
            return ToolResult(
                success=False,
                error=f"Tool '{tool_name}' not registered",
                tool_name=tool_name,
                action=action,
            )

        if not entry.available:
            return ToolResult(
                success=False,
                error=f"Tool '{tool_name}' not available on this system",
                tool_name=tool_name,
                action=action,
            )

        if not entry.policy_allowed:
            return ToolResult(
                success=False,
                error=f"Tool '{tool_name}' not allowed by policy",
                tool_name=tool_name,
                action=action,
            )

        try:
            result = await entry.tool.execute(action, params)
            result.tool_name = tool_name
            result.action = action
            return result
        except Exception as e:
            return ToolResult(
                success=False,
                error=f"Execution failed: {str(e)}",
                tool_name=tool_name,
                action=action,
            )

    def get_status(self) -> dict[str, Any]:
        """Get registry status."""
        return {
            "total_registered": len(self._tools),
            "available": len(self.get_available_tools()),
            "discovered": len(self._discovered),
            "tools": {
                name: {
                    "available": entry.available,
                    "enabled": entry.enabled,
                    "policy_allowed": entry.policy_allowed,
                    "category": entry.tool.category.value,
                }
                for name, entry in self._tools.items()
            },
            "discovered_tools": {
                name: info.available
                for name, info in self._discovered.items()
            },
        }

    def print_status(self) -> str:
        """Print a formatted status report."""
        lines = []
        lines.append("Tool Registry Status")
        lines.append("=" * 50)

        for name, entry in sorted(self._tools.items()):
            status = "OK" if entry.available else "--"
            policy = "" if entry.policy_allowed else " [BLOCKED]"
            lines.append(f"  [{status}] {name}{policy}")

        lines.append("")
        lines.append("Discovered on system:")
        for name, info in sorted(self._discovered.items()):
            if name not in self._tools:
                status = "OK" if info.available else "--"
                lines.append(f"  [{status}] {name} ({info.path or 'not found'})")

        return "\n".join(lines)
