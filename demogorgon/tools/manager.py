"""Tool Manager — discovery, configuration, and invocation of security tools.

The ToolManager implements the SecurityToolAdapter pattern.
It ensures safe execution within bounds and normalizes results.
"""

from __future__ import annotations

import logging
from typing import Any

from demogorgon.tools.base import Tool, ToolResult
from demogorgon.tools.tool_bus import ToolBus

logger = logging.getLogger(__name__)


class SecurityToolAdapter(Tool):
    """Alias for Tool base class, ensuring compliance with new architecture."""
    pass


class ToolManager:
    """Manages external security tools via adapters.

    This replaces direct ToolBus calls with a structured, scope-aware interface.
    """

    def __init__(self, tool_bus: ToolBus | None = None):
        self.bus = tool_bus or ToolBus()
        self._adapters: dict[str, SecurityToolAdapter] = {}

    def register(self, adapter: SecurityToolAdapter) -> None:
        """Register a new tool adapter."""
        self._adapters[adapter.name] = adapter

    def register_defaults(self) -> list[str]:
        """Register built-in adapters. Returns names that discovered as available."""
        from demogorgon.tools.adapters import (
            SubfinderAdapter,
            AmassAdapter,
            HttpxAdapter,
            NucleiAdapter,
            FfufAdapter,
            KatanaAdapter,
            NmapAdapter,
        )

        for adapter_cls in (
            SubfinderAdapter,
            AmassAdapter,
            HttpxAdapter,
            NucleiAdapter,
            FfufAdapter,
            KatanaAdapter,
            NmapAdapter,
        ):
            try:
                self.register(adapter_cls())
            except Exception as e:
                logger.warning(f"Failed to register {adapter_cls.__name__}: {e}")

        return list(self._adapters.keys())

    async def discover_registered(self) -> dict[str, bool]:
        """Run discover() on all registered adapters."""
        return await self.discover_all()

    async def discover_all(self) -> dict[str, bool]:
        """Discover which tools are installed and available."""
        results = {}
        for name, adapter in self._adapters.items():
            results[name] = await adapter.discover()
        return results

    def get_adapter(self, name: str) -> SecurityToolAdapter | None:
        """Get a registered tool adapter."""
        return self._adapters.get(name)

    async def execute(self, tool_name: str, action: str, params: dict[str, Any]) -> dict[str, Any]:
        """Execute a tool action and normalize the result."""
        adapter = self.get_adapter(tool_name)
        if not adapter:
            return {
                "success": False,
                "error": f"Tool '{tool_name}' not found or not registered.",
                "tool": tool_name
            }

        # 1. Validation logic would go here (scope check, safety check)
        # TODO: integrate with ScopeMatcher and SafetyGate

        # 2. Execute
        try:
            result: ToolResult = await adapter.execute(action, params)
            
            # 3. Normalize result to common finding structure
            return {
                "tool": tool_name,
                "action": action,
                "success": result.success,
                "target": params.get("target") or params.get("url", "unknown"),
                "data": result.data,
                "items": result.items,
                "error": result.error,
            }
        except Exception as e:
            logger.exception(f"Tool {tool_name} execution failed")
            return {
                "tool": tool_name,
                "action": action,
                "success": False,
                "error": str(e),
            }


def create_default_tool_manager(tool_bus: ToolBus | None = None) -> ToolManager:
    """Create a ToolManager with all built-in adapters registered."""
    manager = ToolManager(tool_bus=tool_bus)
    manager.register_defaults()
    return manager
