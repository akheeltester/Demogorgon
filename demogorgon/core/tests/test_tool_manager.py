"""Unit tests for the ToolManager and Tool Adapter abstraction."""

import asyncio
import pytest
from typing import Any

from demogorgon.tools.manager import ToolManager, SecurityToolAdapter
from demogorgon.tools.base import ToolResult, ToolCategory, ToolCapability

class MockSecurityTool(SecurityToolAdapter):
    """A mock tool for testing ToolManager integration."""
    
    def __init__(self, name: str, should_fail: bool = False, timeout_delay: float = 0.0):
        self._name = name
        self.should_fail = should_fail
        self.timeout_delay = timeout_delay
        self.executed_actions = []

    @property
    def name(self) -> str:
        return self._name

    @property
    def category(self) -> ToolCategory:
        return ToolCategory.RECON

    @property
    def capabilities(self) -> list[ToolCapability]:
        return [ToolCapability(name="test_action", description="Mock capability")]

    async def discover(self) -> bool:
        return True

    async def execute(self, action: str, params: dict[str, Any]) -> ToolResult:
        self.executed_actions.append((action, params))
        
        if self.timeout_delay > 0:
            await asyncio.sleep(self.timeout_delay)
            
        if self.should_fail:
            return ToolResult(
                tool_name=self.name,
                action=action,
                success=False,
                error="Mocked failure"
            )
            
        return ToolResult(
            tool_name=self.name,
            action=action,
            success=True,
            data={"result": "mock_data"},
            items=[{"finding": "test_vuln"}]
        )

@pytest.mark.asyncio
async def test_tool_manager_registration():
    """Verify tools can be registered and discovered."""
    manager = ToolManager()
    manager.register(MockSecurityTool("mock_tool_1"))
    manager.register(MockSecurityTool("mock_tool_2"))
    
    adapter = manager.get_adapter("mock_tool_1")
    assert adapter is not None
    assert adapter.name == "mock_tool_1"
    
    discovery = await manager.discover_all()
    assert discovery["mock_tool_1"] is True
    assert discovery["mock_tool_2"] is True

@pytest.mark.asyncio
async def test_tool_manager_execution_success():
    """Verify ToolManager successfully executes and normalizes results."""
    manager = ToolManager()
    manager.register(MockSecurityTool("mock_tool"))
    
    result = await manager.execute("mock_tool", "test_action", {"target": "http://127.0.0.1"})
    
    assert result["success"] is True
    assert result["tool"] == "mock_tool"
    assert result["target"] == "http://127.0.0.1"
    assert result["data"]["result"] == "mock_data"
    assert len(result["items"]) == 1

@pytest.mark.asyncio
async def test_tool_manager_execution_failure():
    """Verify ToolManager handles tool failures gracefully."""
    manager = ToolManager()
    manager.register(MockSecurityTool("fail_tool", should_fail=True))
    
    result = await manager.execute("fail_tool", "test_action", {"target": "http://127.0.0.1"})
    
    assert result["success"] is False
    assert result["error"] == "Mocked failure"

@pytest.mark.asyncio
async def test_tool_manager_missing_tool():
    """Verify ToolManager gracefully handles requests for missing tools."""
    manager = ToolManager()
    result = await manager.execute("nonexistent_tool", "test_action", {"target": "http://127.0.0.1"})
    
    assert result["success"] is False
    assert "not found" in result["error"]
