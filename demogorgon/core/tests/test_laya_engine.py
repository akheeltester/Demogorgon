"""Unit tests for the Laya Decision Engine."""

import json
import pytest
from unittest.mock import AsyncMock, MagicMock

from demogorgon.laya.engine import LayaEngine
from demogorgon.core.config import LayaConfig
from demogorgon.llm.manager import AIProviderManager
from demogorgon.core.decision_trace import DecisionTrace

class MockLLMResponse:
    def __init__(self, content: str, error: str = ""):
        self.content = content
        self.error = error

@pytest.fixture
def mock_llm_manager():
    manager = MagicMock(spec=AIProviderManager)
    manager.fast_model = "mock-fast-model"
    manager.generate = AsyncMock()
    return manager

@pytest.fixture
def laya_engine(mock_llm_manager):
    config = LayaConfig(enabled=True, confidence_threshold=0.7)
    trace = DecisionTrace()
    return LayaEngine(llm_manager=mock_llm_manager, config=config, trace=trace)

@pytest.mark.asyncio
async def test_laya_strategy_selection_success(laya_engine, mock_llm_manager):
    """Verify Laya successfully selects a strategy using LLM."""
    mock_response = json.dumps({
        "selected": "recon",
        "confidence": 0.85,
        "reason": "Starting initial recon phase."
    })
    mock_llm_manager.generate.return_value = MockLLMResponse(content=mock_response)
    
    context = {"endpoints": 0, "tested_actions": 0}
    decision = await laya_engine.select_strategy(context)
    
    assert decision["selected"] == "recon"
    assert decision["confidence"] == 0.85
    assert decision["source"] == "laya"
    assert decision["fallback"] is False
    assert len(laya_engine.trace._decisions) == 1

@pytest.mark.asyncio
async def test_laya_fallback_low_confidence(laya_engine, mock_llm_manager):
    """Verify Laya falls back to deterministic logic on low confidence."""
    # Confidence 0.5 < threshold 0.7
    mock_response = json.dumps({
        "selected": "focused",
        "confidence": 0.5,
        "reason": "Not sure what to do."
    })
    mock_llm_manager.generate.return_value = MockLLMResponse(content=mock_response)
    
    context = {"endpoints": 2, "tested_actions": 0}
    decision = await laya_engine.select_strategy(context)
    
    # Fallback should select recon since endpoints < 10
    assert decision["selected"] == "recon"
    assert decision["source"] == "deterministic"
    assert decision["fallback"] is True
    assert "Fallback" in decision["reason_code"]

@pytest.mark.asyncio
async def test_laya_fallback_llm_error(laya_engine, mock_llm_manager):
    """Verify Laya falls back when LLM errors out."""
    mock_llm_manager.generate.return_value = MockLLMResponse(content="", error="API Timeout")
    
    context = {"endpoints": 20, "tested_actions": 5}
    decision = await laya_engine.select_strategy(context)
    
    # Fallback should select explore since tested < endpoints and endpoints >= 10
    assert decision["selected"] == "explore"
    assert decision["source"] == "deterministic"
    assert decision["fallback"] is True

@pytest.mark.asyncio
async def test_laya_target_prioritization(laya_engine, mock_llm_manager):
    """Verify Laya prioritizes targets properly."""
    mock_response = json.dumps({
        "selected": "http://127.0.0.1/admin",
        "confidence": 0.9,
        "reason": "Admin endpoints are high value."
    })
    mock_llm_manager.generate.return_value = MockLLMResponse(content=mock_response)
    
    candidates = [{"id": "http://127.0.0.1/admin"}, {"id": "http://127.0.0.1/home"}]
    decision = await laya_engine.prioritize_target(candidates)
    
    assert decision["selected"] == "http://127.0.0.1/admin"
    assert decision["source"] == "laya"

@pytest.mark.asyncio
async def test_laya_invalid_selection_fallback(laya_engine, mock_llm_manager):
    """Verify Laya falls back if LLM returns an option not in the list."""
    mock_response = json.dumps({
        "selected": "invalid_option",
        "confidence": 0.9,
        "reason": "Hallucinated option."
    })
    mock_llm_manager.generate.return_value = MockLLMResponse(content=mock_response)
    
    context = {"endpoints": 0, "tested_actions": 0}
    decision = await laya_engine.select_strategy(context)
    
    # Should fallback because 'invalid_option' is not in allowed strategies
    assert decision["fallback"] is True
    assert decision["source"] == "deterministic"
