"""LLM Router — multi-provider LLM with automatic fallback.

Supports:
- OpenRouter (default)
- Ollama (local)
- OpenAI (direct)
- Anthropic (direct)

Fallback order: primary → secondary → tertiary
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from rich.console import Console

console = Console()


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


class LLMRouter:
    """Multi-provider LLM with automatic fallback.

    Usage:
        router = LLMRouter()
        response = await router.complete([
            {"role": "system", "content": "You are a security researcher."},
            {"role": "user", "content": "Analyze this endpoint..."}
        ])
    """

    def __init__(self):
        self._env = _load_env()
        self._providers: list[tuple[str, Any]] = []
        self._active_provider: str = ""
        self._active_model: str = ""
        self._configure()

    def _configure(self) -> None:
        """Configure providers from environment variables."""
        provider_name = self._env.get("LLM_PROVIDER", "openrouter")
        model = self._env.get("LLM_MODEL", "")
        api_key = self._env.get("LLM_API_KEY", "")
        base_url = self._env.get("LLM_BASE_URL", "")

        # OpenRouter (default)
        if not api_key:
            api_key = self._env.get("OPENROUTER_API_KEY", "")

        if provider_name == "openrouter" or (not provider_name and api_key):
            if not base_url:
                base_url = "https://openrouter.ai/api/v1"
            if not model:
                model = self._env.get("AI_MODELS", "mimo-v2.5-free").split(",")[0].strip()
            self._providers.append(("openrouter", self._create_openai_provider(api_key, base_url, model)))
            self._active_provider = "openrouter"
            self._active_model = model

        # Ollama (local)
        elif provider_name == "ollama":
            ollama_url = base_url or "http://localhost:11434/v1"
            if not model:
                model = "llama3.1:8b"
            self._providers.append(("ollama", self._create_openai_provider("ollama", ollama_url, model)))
            self._active_provider = "ollama"
            self._active_model = model

        # OpenAI direct
        elif provider_name == "openai":
            if not base_url:
                base_url = "https://api.openai.com/v1"
            if not model:
                model = "gpt-4o-mini"
            self._providers.append(("openai", self._create_openai_provider(api_key, base_url, model)))
            self._active_provider = "openai"
            self._active_model = model

        # Anthropic
        elif provider_name == "anthropic":
            if not model:
                model = "claude-sonnet-4-20250514"
            try:
                self._providers.append(("anthropic", self._create_anthropic_provider(api_key, model)))
                self._active_provider = "anthropic"
                self._active_model = model
            except ImportError:
                # Fallback to OpenRouter
                self._providers.append(("openrouter", self._create_openai_provider(
                    api_key, "https://openrouter.ai/api/v1", f"anthropic/{model}"
                )))
                self._active_provider = "openrouter"
                self._active_model = f"anthropic/{model}"

        # DeepSeek
        elif provider_name == "deepseek":
            if not model:
                model = "deepseek-chat"
            self._providers.append(("deepseek", self._create_openai_provider(
                api_key, "https://api.deepseek.com/v1", model
            )))
            self._active_provider = "deepseek"
            self._active_model = model

        # Also add fallback providers
        if api_key and self._active_provider != "openrouter":
            fallback_model = self._env.get("AI_MODELS", "mimo-v2.5-free").split(",")[0].strip()
            self._providers.append(("openrouter_fallback", self._create_openai_provider(
                api_key, "https://openrouter.ai/api/v1", fallback_model
            )))

        if self._active_provider != "ollama":
            self._providers.append(("ollama_fallback", self._create_openai_provider(
                "ollama", "http://localhost:11434/v1", "llama3.1:8b"
            )))

    def _create_openai_provider(self, api_key: str, base_url: str, model: str):
        """Create an OpenAI-compatible provider."""
        try:
            from openai import AsyncOpenAI
            client = AsyncOpenAI(
                api_key=api_key,
                base_url=base_url,
                timeout=120.0,
            )
            return {"client": client, "model": model, "type": "openai"}
        except ImportError:
            return None

    def _create_anthropic_provider(self, api_key: str, model: str):
        """Create an Anthropic provider."""
        try:
            import anthropic
            client = anthropic.AsyncAnthropic(api_key=api_key)
            return {"client": client, "model": model, "type": "anthropic"}
        except ImportError:
            raise ImportError("anthropic package required: pip install anthropic")

    async def complete(
        self,
        messages: list[dict],
        temperature: float = 0.1,
        max_tokens: int = 4096,
        response_format: dict | None = None,
    ) -> str:
        """Complete a chat request with automatic fallback.

        Tries each provider in order until one succeeds.
        """
        last_error = None

        for name, provider in self._providers:
            if provider is None:
                continue

            try:
                if provider["type"] == "openai":
                    result = await self._complete_openai(
                        provider["client"], provider["model"],
                        messages, temperature, max_tokens, response_format
                    )
                    self._active_provider = name
                    self._active_model = provider["model"]
                    return result

                elif provider["type"] == "anthropic":
                    result = await self._complete_anthropic(
                        provider["client"], provider["model"],
                        messages, temperature, max_tokens
                    )
                    self._active_provider = name
                    self._active_model = provider["model"]
                    return result

            except Exception as e:
                last_error = e
                console.print(f"[yellow]Provider {name} failed: {str(e)[:100]}[/yellow]")
                continue

        raise Exception(f"All LLM providers failed. Last error: {last_error}")

    async def _complete_openai(
        self, client, model: str, messages: list[dict],
        temperature: float, max_tokens: int, response_format: dict | None
    ) -> str:
        """Complete using OpenAI-compatible API."""
        kwargs: dict[str, Any] = {
            "model": model,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
        if response_format:
            kwargs["response_format"] = response_format

        response = await client.chat.completions.create(**kwargs)
        content = response.choices[0].message.content
        if not content or not content.strip():
            raise ValueError("Empty response from model")
        return content

    async def _complete_anthropic(
        self, client, model: str, messages: list[dict],
        temperature: float, max_tokens: int
    ) -> str:
        """Complete using Anthropic API."""
        # Convert messages to Anthropic format
        system_msg = ""
        user_messages = []
        for msg in messages:
            if msg["role"] == "system":
                system_msg = msg["content"]
            else:
                user_messages.append(msg)

        if not user_messages:
            user_messages = [{"role": "user", "content": "ping"}]

        response = await client.messages.create(
            model=model,
            max_tokens=max_tokens,
            temperature=temperature,
            system=system_msg,
            messages=user_messages,
        )

        content = response.content[0].text if response.content else ""
        if not content or not content.strip():
            raise ValueError("Empty response from model")
        return content

    def get_stats(self) -> dict[str, Any]:
        """Get provider statistics."""
        return {
            "active_provider": self._active_provider,
            "active_model": self._active_model,
            "available_providers": [name for name, p in self._providers if p is not None],
        }
