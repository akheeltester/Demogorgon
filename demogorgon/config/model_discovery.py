"""Dynamic Model Discovery — fetch available models from providers.

Supports:
- OpenAI: GET /v1/models
- OpenRouter: GET /api/v1/models (with pricing metadata)
- Anthropic: hardcoded list (no public model listing API)
- Gemini: hardcoded list (no public model listing API)
- DeepSeek: hardcoded list
- Ollama: GET /api/tags (local models)

Usage:
    models = await discover_models("openrouter", api_key="sk-...")
    for m in models:
        print(f"{m['id']} — {m.get('context_length', '?')} tokens")
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)


# Fallback model lists when API listing is unavailable
FALLBACK_MODELS: dict[str, list[dict[str, Any]]] = {
    "anthropic": [
        {"id": "claude-sonnet-4-20250514", "name": "Claude Sonnet 4", "context_length": 200000},
        {"id": "claude-3-5-sonnet-20241022", "name": "Claude 3.5 Sonnet", "context_length": 200000},
        {"id": "claude-3-5-haiku-20241022", "name": "Claude 3.5 Haiku", "context_length": 200000},
        {"id": "claude-3-opus-20240229", "name": "Claude 3 Opus", "context_length": 200000},
    ],
    "gemini": [
        {"id": "gemini-2.5-pro", "name": "Gemini 2.5 Pro", "context_length": 1000000},
        {"id": "gemini-2.5-flash", "name": "Gemini 2.5 Flash", "context_length": 1000000},
        {"id": "gemini-2.0-flash", "name": "Gemini 2.0 Flash", "context_length": 1000000},
        {"id": "gemini-1.5-pro", "name": "Gemini 1.5 Pro", "context_length": 2000000},
        {"id": "gemini-1.5-flash", "name": "Gemini 1.5 Flash", "context_length": 1000000},
    ],
    "deepseek": [
        {"id": "deepseek-chat", "name": "DeepSeek V3", "context_length": 128000},
        {"id": "deepseek-reasoner", "name": "DeepSeek R1", "context_length": 128000},
    ],
}


async def discover_models(
    provider: str,
    api_key: str = "",
    base_url: str = "",
) -> list[dict[str, Any]]:
    """Discover available models for a provider.

    Returns list of dicts with keys: id, name, context_length, provider, pricing (optional).
    """
    try:
        if provider == "openai":
            return await _discover_openai(api_key, base_url)
        elif provider == "openrouter":
            return await _discover_openrouter(api_key, base_url)
        elif provider == "ollama":
            return await _discover_ollama(base_url)
        elif provider in FALLBACK_MODELS:
            return FALLBACK_MODELS[provider]
        else:
            return []
    except Exception as e:
        logger.warning(f"Model discovery failed for {provider}: {e}")
        return FALLBACK_MODELS.get(provider, [])


async def _discover_openai(api_key: str, base_url: str = "") -> list[dict[str, Any]]:
    """List models from OpenAI API."""
    url = (base_url.rstrip("/") if base_url else "https://api.openai.com") + "/v1/models"
    headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}

    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.get(url, headers=headers)
        resp.raise_for_status()
        data = resp.json()

    models = []
    for m in data.get("data", []):
        model_id = m.get("id", "")
        models.append({
            "id": model_id,
            "name": model_id,
            "context_length": _guess_context_length(model_id),
            "provider": "openai",
        })

    # Sort: GPT-4 models first, then others
    models.sort(key=lambda x: (not x["id"].startswith("gpt-4"), x["id"]))
    return models


async def _discover_openrouter(api_key: str, base_url: str = "") -> list[dict[str, Any]]:
    """List models from OpenRouter API (includes pricing)."""
    url = "https://openrouter.ai/api/v1/models"
    headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}

    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.get(url, headers=headers)
        resp.raise_for_status()
        data = resp.json()

    models = []
    for m in data.get("data", []):
        model_id = m.get("id", "")
        pricing = m.get("pricing", {})
        models.append({
            "id": model_id,
            "name": m.get("name", model_id),
            "context_length": m.get("context_length", 0),
            "provider": "openrouter",
            "pricing": {
                "prompt": float(pricing.get("prompt", 0)),
                "completion": float(pricing.get("completion", 0)),
            },
        })

    # Sort by name
    models.sort(key=lambda x: x.get("name", x["id"]))
    return models


async def _discover_ollama(base_url: str = "") -> list[dict[str, Any]]:
    """List locally installed Ollama models."""
    url = (base_url.rstrip("/") if base_url else "http://localhost:11434") + "/api/tags"

    async with httpx.AsyncClient(timeout=5) as client:
        resp = await client.get(url)
        resp.raise_for_status()
        data = resp.json()

    models = []
    for m in data.get("models", []):
        model_id = m.get("name", "")
        models.append({
            "id": model_id,
            "name": model_id,
            "context_length": 0,  # Ollama doesn't expose context length
            "provider": "ollama",
            "size": m.get("size", 0),
        })

    models.sort(key=lambda x: x["id"])
    return models


async def test_provider_connection(
    provider: str,
    api_key: str = "",
    base_url: str = "",
) -> dict[str, Any]:
    """Test if a provider is reachable and authenticated.

    Returns: {"success": bool, "error": str|None, "latency_ms": float|None, "model": str|None}
    """
    try:
        from ..llm.manager import LLMManager

        manager = LLMManager()
        manager.configure(provider=provider, api_key=api_key, base_url=base_url or None)

        # Health check
        latency = await manager.health_check()
        if not latency:
            return {"success": False, "error": "Provider not reachable", "latency_ms": None, "model": None}

        # Smoke test
        smoke = await manager.smoke_test()

        return {
            "success": True,
            "error": None,
            "latency_ms": latency,
            "model": manager._active_model,
            "structured_output": smoke,
        }
    except Exception as e:
        return {"success": False, "error": str(e), "latency_ms": None, "model": None}


def _guess_context_length(model_id: str) -> int:
    """Guess context length from model ID (best effort)."""
    model_lower = model_id.lower()
    if "gpt-4o" in model_lower:
        return 128000
    if "gpt-4.1" in model_lower:
        return 1000000
    if "gpt-4-turbo" in model_lower:
        return 128000
    if "gpt-4" in model_lower:
        return 8192
    if "gpt-3.5" in model_lower:
        return 16385
    if "o1" in model_lower or "o3" in model_lower:
        return 200000
    return 128000  # default guess
