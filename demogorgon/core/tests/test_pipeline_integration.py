"""Integration tests for the Demogorgon pipeline using synthetic local observations."""

import pytest
import asyncio
from typing import Any

from demogorgon.core.config import DemogorgonConfig, SafetyConfig, LayaConfig
from demogorgon.core.scope_legacy import ScopeValidator
from demogorgon.core.scope.safety import SafetyGate
from demogorgon.laya.engine import LayaEngine
from demogorgon.core.decision_trace import DecisionTrace
from demogorgon.tools.manager import ToolManager, SecurityToolAdapter
from demogorgon.tools.base import ToolResult, ToolCategory, ToolCapability

# Mock implementations
class MockPipelineTool(SecurityToolAdapter):
    @property
    def name(self) -> str: return "mock_pipeline_tool"
    
    @property
    def category(self) -> ToolCategory: return ToolCategory.RECON
    
    @property
    def capabilities(self) -> list[ToolCapability]:
        return [ToolCapability(name="test", description="")]

    async def discover(self) -> bool: return True

    async def execute(self, action: str, params: dict[str, Any]) -> ToolResult:
        if params.get("target") == "http://127.0.0.1/admin":
            return ToolResult(success=True, data={"finding": "idor_vuln"}, tool_name=self.name, action=action)
        return ToolResult(success=False, error="Target not found", tool_name=self.name, action=action)

class MockLLMForPipeline:
    def __init__(self):
        self.fast_model = "mock-fast"
        self.reasoning_model = "mock-reasoning"
        self.available = True
        
    async def generate(self, **kwargs):
        import json
        class Resp:
            error = None
            content = json.dumps({"selected": "http://127.0.0.1/admin", "confidence": 0.95, "reason": "Test target"})
        return Resp()

@pytest.fixture
def config():
    cfg = DemogorgonConfig(target_url="http://127.0.0.1")
    cfg.safety = SafetyConfig(strict_scope=True)
    cfg.laya = LayaConfig(enabled=True, confidence_threshold=0.8)
    return cfg

@pytest.mark.asyncio
async def test_pipeline_integration(config):
    """Test the complete flow: Scope -> Safety -> Laya -> Tool -> Trace."""
    
    # 1. Scope
    scope = ScopeValidator(config.target_url)
    assert scope.in_scope("http://127.0.0.1/admin") is True
    assert scope.in_scope("http://evil.com/admin") is False

    from demogorgon.core.engagement import ScopeAsset
    
    # 2. Safety Gate
    asset = ScopeAsset(pattern="127.0.0.1", asset_type="domain")
    gate = SafetyGate(in_scope_assets=[asset])
    
    # Action attempting out of scope
    out_of_scope_target = "http://evil.com/admin"
    check = gate.check_action("send_request", out_of_scope_target)
    assert check.allowed is False
    assert "scope" in check.reason.lower()

    # Action in scope
    in_scope_target = "http://127.0.0.1/admin"
    check = gate.check_action("send_request", in_scope_target)
    assert check.allowed is True

    # 3. Laya Decision Engine
    llm = MockLLMForPipeline()
    trace = DecisionTrace()
    laya = LayaEngine(llm_manager=llm, config=config.laya, trace=trace)
    
    # Synthetic observation
    candidates = [{"id": "http://127.0.0.1/admin"}, {"id": "http://127.0.0.1/test"}]
    decision = await laya.prioritize_target(candidates)
    
    assert decision["selected"] == "http://127.0.0.1/admin"
    assert decision["confidence"] == 0.95
    assert decision["source"] == "laya"

    # 4. Tool Execution (Executor abstraction)
    tool_manager = ToolManager()
    tool_manager.register(MockPipelineTool())
    
    # Only execute if safety gate allows (we proved it does above)
    tool_result = await tool_manager.execute("mock_pipeline_tool", "test", {"target": decision["selected"]})
    
    assert tool_result["success"] is True
    assert tool_result["data"]["finding"] == "idor_vuln"

    # 5. Decision Trace update
    trace.update_result(decision["decision_id"], tool_executed="mock_pipeline_tool", result="success", outcome="idor_vuln")
    
    traces = trace.get_traces()
    assert len(traces) == 1
    assert traces[0]["tool_executed"] == "mock_pipeline_tool"
    assert traces[0]["outcome"] == "idor_vuln"
    assert traces[0]["selected"] == "http://127.0.0.1/admin"
