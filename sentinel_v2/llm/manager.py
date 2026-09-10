"""LLM Manager — handles provider selection, configuration, and fallback.

Configuration via environment variables:
    LLM_PROVIDER=openai|ollama|deepseek|anthropic|openrouter
    LLM_MODEL=model_name
    LLM_API_KEY=api_key
    LLM_BASE_URL=base_url
"""

from __future__ import annotations

import os
from pathlib import Path

from sentinel_v2.llm.base import LLMProvider, LLMResponse


def _load_env() -> dict[str, str]:
    """Load config from .env file."""
    env_path = Path(__file__).parent.parent.parent / ".env"
    config = {}
    if env_path.exists():
        for line in env_path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                key, _, value = line.partition("=")
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                if " #" in value:
                    value = value[:value.index(" #")].strip()
                config[key] = value
    for key in config:
        os.environ.setdefault(key, config[key])
    return config


class LLMManager:
    """Manages LLM providers with automatic fallback."""

    def __init__(self):
        self._env = _load_env()
        self._providers: dict[str, LLMProvider] = {}
        self._active_provider: str = ""
        self._active_model: str = ""

    def configure(self) -> None:
        """Configure providers from environment variables."""
        provider_name = self._env.get("LLM_PROVIDER", "openai")
        model = self._env.get("LLM_MODEL", "")
        api_key = self._env.get("LLM_API_KEY", "")
        base_url = self._env.get("LLM_BASE_URL", "")

        if not api_key:
            api_key = self._env.get("OPENROUTER_API_KEY", "")
            base_url = self._env.get("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1")

        if provider_name == "openai" or provider_name == "openrouter":
            from sentinel_v2.llm.providers.openai import OpenAIProvider
            if not base_url:
                base_url = "https://api.openai.com/v1"
            if not model:
                model = "gpt-4o-mini"
            self._providers["openai"] = OpenAIProvider(
                api_key=api_key,
                base_url=base_url,
                default_model=model,
            )
            self._active_provider = "openai"
            self._active_model = model

        elif provider_name == "deepseek":
            from sentinel_v2.llm.providers.openai import OpenAIProvider
            self._providers["deepseek"] = OpenAIProvider(
                api_key=api_key,
                base_url="https://api.deepseek.com/v1",
                default_model=model or "deepseek-chat",
            )
            self._active_provider = "deepseek"
            self._active_model = model or "deepseek-chat"

        elif provider_name == "ollama":
            from sentinel_v2.llm.providers.openai import OpenAIProvider
            ollama_url = base_url or "http://localhost:11434/v1"
            self._providers["ollama"] = OpenAIProvider(
                api_key="ollama",
                base_url=ollama_url,
                default_model=model or "llama3.1:8b",
            )
            self._active_provider = "ollama"
            self._active_model = model or "llama3.1:8b"

        elif provider_name == "anthropic":
            try:
                from sentinel_v2.llm.providers.anthropic import AnthropicProvider
                self._providers["anthropic"] = AnthropicProvider(
                    api_key=api_key,
                    default_model=model or "claude-sonnet-4-20250514",
                )
                self._active_provider = "anthropic"
                self._active_model = model or "claude-sonnet-4-20250514"
            except ImportError:
                from sentinel_v2.llm.providers.openai import OpenAIProvider
                self._providers["openai"] = OpenAIProvider(
                    api_key=api_key,
                    base_url="https://openrouter.ai/api/v1",
                    default_model="anthropic/claude-sonnet-4-20250514",
                )
                self._active_provider = "openai"
                self._active_model = "anthropic/claude-sonnet-4-20250514"

        else:
            from sentinel_v2.llm.providers.openai import OpenAIProvider
            self._providers["openai"] = OpenAIProvider(
                api_key=api_key,
                base_url=base_url or "https://api.openai.com/v1",
                default_model=model or "gpt-4o-mini",
            )
            self._active_provider = "openai"
            self._active_model = model or "gpt-4o-mini"

    def get_provider(self) -> LLMProvider:
        if not self._active_provider:
            self.configure()
        return self._providers[self._active_provider]

    async def generate(
        self,
        messages: list[dict[str, str]],
        model: str | None = None,
        temperature: float = 0.1,
        max_tokens: int = 4096,
        response_format: dict | None = None,
    ) -> LLMResponse:
        provider = self.get_provider()
        resp = await provider.generate(
            messages, model, temperature, max_tokens, response_format
        )
        if resp.error:
            for name, p in self._providers.items():
                if name != self._active_provider:
                    resp2 = await p.generate(
                        messages, model, temperature, max_tokens, response_format
                    )
                    if not resp2.error:
                        return resp2
        return resp

    def get_stats(self) -> dict[str, Any]:
        return {
            "active_provider": self._active_provider,
            "active_model": self._active_model,
            "available_providers": list(self._providers.keys()),
        }
