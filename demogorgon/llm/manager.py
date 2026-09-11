"""LLM Manager — provider selection, configuration, retry, and fallback.

Configuration via environment variables:
    DEMOGORGON_LLM_PROVIDER=openai|ollama|deepseek|anthropic|openrouter
    DEMOGORGON_API_KEY=api_key
    DEMOGORGON_MODEL=model_name
    DEMOGORGON_BASE_URL=base_url
    DEMOGORGON_FALLBACK_PROVIDER=provider_name
    DEMOGORGON_FALLBACK_MODEL=model_name
    DEMOGORGON_LLM_MAX_RETRIES=2
    DEMOGORGON_LLM_TIMEOUT=60

Also reads legacy env vars (LLM_PROVIDER, LLM_API_KEY, etc.) as fallback.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from pathlib import Path
from typing import Any

from demogorgon.llm.base import LLMProvider, LLMResponse

logger = logging.getLogger(__name__)


def _load_env() -> dict[str, str]:
    """Load config from .env file."""
    env_path = Path(__file__).parent.parent.parent / ".env"
    config: dict[str, str] = {}
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


def _mask_key(key: str) -> str:
    """Mask an API key for display."""
    if not key or len(key) < 8:
        return "NOT CONFIGURED"
    return f"{key[:4]}...{key[-4:]}"


class LLMManager:
    """Manages LLM providers with retry, fallback, and failure handling.

    Usage:
        manager = LLMManager()
        manager.configure()
        response = await manager.generate(messages)
        if response.error:
            # Handle failure
    """

    def __init__(self):
        self._env = _load_env()
        self._providers: dict[str, LLMProvider] = {}
        self._active_provider: str = ""
        self._active_model: str = ""
        self._fallback_provider: str = ""
        self._fallback_model: str = ""
        self._max_retries: int = 2
        self._timeout: float = 60.0

    def configure(self) -> None:
        """Configure providers from environment variables."""
        # DEMOGORGON_ prefix takes precedence, then legacy LLM_ prefix
        provider_name = (
            self._env.get("DEMOGORGON_LLM_PROVIDER")
            or self._env.get("LLM_PROVIDER", "openai")
        )
        model = (
            self._env.get("DEMOGORGON_MODEL")
            or self._env.get("LLM_MODEL", "")
        )
        api_key = (
            self._env.get("DEMOGORGON_API_KEY")
            or self._env.get("LLM_API_KEY", "")
        )
        base_url = (
            self._env.get("DEMOGORGON_BASE_URL")
            or self._env.get("LLM_BASE_URL", "")
        )
        self._fallback_provider = (
            self._env.get("DEMOGORGON_FALLBACK_PROVIDER", "")
        )
        self._fallback_model = (
            self._env.get("DEMOGORGON_FALLBACK_MODEL", "")
        )
        self._max_retries = int(
            self._env.get("DEMOGORGON_LLM_MAX_RETRIES", "2")
        )
        self._timeout = float(
            self._env.get("DEMOGORGON_LLM_TIMEOUT", "60")
        )

        # OpenRouter fallback
        if not api_key:
            api_key = self._env.get("OPENROUTER_API_KEY", "")
            if not base_url:
                base_url = self._env.get(
                    "OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1"
                )

        self._configure_provider(provider_name, api_key, base_url, model)

        # Configure fallback if specified
        if self._fallback_provider and self._fallback_provider != provider_name:
            fb_model = self._fallback_model or model
            fb_key = api_key  # Same key by default
            fb_url = base_url
            self._configure_provider(
                self._fallback_provider, fb_key, fb_url, fb_model, is_fallback=True
            )

    def _configure_provider(
        self,
        name: str,
        api_key: str,
        base_url: str,
        model: str,
        is_fallback: bool = False,
    ) -> None:
        """Configure a single provider."""
        if not api_key:
            logger.warning(f"No API key for provider '{name}'")
            return

        provider_key = f"fallback_{name}" if is_fallback else name

        try:
            if name in ("openai", "openrouter"):
                from demogorgon.llm.providers.openai import OpenAIProvider

                url = base_url or "https://api.openai.com/v1"
                mdl = model or "gpt-4o-mini"
                self._providers[provider_key] = OpenAIProvider(
                    api_key=api_key,
                    base_url=url,
                    default_model=mdl,
                )
            elif name == "deepseek":
                from demogorgon.llm.providers.openai import OpenAIProvider

                self._providers[provider_key] = OpenAIProvider(
                    api_key=api_key,
                    base_url="https://api.deepseek.com/v1",
                    default_model=model or "deepseek-chat",
                )
                mdl = model or "deepseek-chat"
            elif name == "ollama":
                from demogorgon.llm.providers.openai import OpenAIProvider

                url = base_url or "http://localhost:11434/v1"
                mdl = model or "llama3.1:8b"
                self._providers[provider_key] = OpenAIProvider(
                    api_key="ollama",
                    base_url=url,
                    default_model=mdl,
                )
            elif name == "anthropic":
                from demogorgon.llm.providers.anthropic import AnthropicProvider

                mdl = model or "claude-sonnet-4-20250514"
                self._providers[provider_key] = AnthropicProvider(
                    api_key=api_key,
                    default_model=mdl,
                )
            else:
                from demogorgon.llm.providers.openai import OpenAIProvider

                url = base_url or "https://api.openai.com/v1"
                mdl = model or "gpt-4o-mini"
                self._providers[provider_key] = OpenAIProvider(
                    api_key=api_key,
                    base_url=url,
                    default_model=mdl,
                )
        except ImportError as e:
            logger.warning(f"Cannot configure provider '{name}': {e}")
            return

        if not is_fallback:
            self._active_provider = provider_key
            self._active_model = model or "gpt-4o-mini"
        logger.info(
            f"Configured LLM provider: {name} (model: {model})"
            + (" [fallback]" if is_fallback else "")
        )

    def get_provider(self) -> LLMProvider:
        """Get the active LLM provider."""
        if not self._active_provider:
            self.configure()
        if self._active_provider not in self._providers:
            raise RuntimeError(
                f"No LLM provider configured. Set DEMOGORGON_LLM_PROVIDER and "
                f"DEMOGORGON_API_KEY in .env"
            )
        return self._providers[self._active_provider]

    @property
    def available(self) -> bool:
        """Check if a provider is configured."""
        if not self._active_provider:
            self.configure()
        return self._active_provider in self._providers

    async def generate(
        self,
        messages: list[dict[str, str]],
        model: str | None = None,
        temperature: float = 0.1,
        max_tokens: int = 4096,
        response_format: dict | None = None,
    ) -> LLMResponse:
        """Generate a response with retry and fallback.

        Flow:
        1. Try active provider (with retries)
        2. On failure, try fallback provider (with retries)
        3. On failure, return error response
        """
        if not self._active_provider:
            self.configure()

        # Try active provider
        resp = await self._generate_with_retry(
            provider_key=self._active_provider,
            messages=messages,
            model=model,
            temperature=temperature,
            max_tokens=max_tokens,
            response_format=response_format,
        )
        if not resp.error:
            return resp

        logger.warning(
            f"Active provider '{self._active_provider}' failed: {resp.error[:100]}"
        )

        # Try fallback
        fallback_key = f"fallback_{self._active_provider}"
        if fallback_key in self._providers:
            logger.info(f"Trying fallback provider: {fallback_key}")
            resp2 = await self._generate_with_retry(
                provider_key=fallback_key,
                messages=messages,
                model=model,
                temperature=temperature,
                max_tokens=max_tokens,
                response_format=response_format,
            )
            if not resp2.error:
                return resp2

        return resp

    async def _generate_with_retry(
        self,
        provider_key: str,
        messages: list[dict[str, str]],
        model: str | None,
        temperature: float,
        max_tokens: int,
        response_format: dict | None,
    ) -> LLMResponse:
        """Generate with exponential backoff retry."""
        provider = self._providers.get(provider_key)
        if not provider:
            return LLMResponse(content="", error=f"Provider '{provider_key}' not configured")

        last_error = ""
        for attempt in range(self._max_retries + 1):
            try:
                resp = await provider.generate(
                    messages, model, temperature, max_tokens, response_format
                )
                if not resp.error:
                    return resp
                last_error = resp.error

                # Don't retry on auth errors
                if any(
                    kw in resp.error.lower()
                    for kw in ("auth", "api_key", "unauthorized", "401", "403")
                ):
                    return resp

                # Don't retry on rate limits (just return the error)
                if any(kw in resp.error.lower() for kw in ("429", "rate limit")):
                    return resp

            except asyncio.TimeoutError:
                last_error = f"Timeout after {self._timeout}s"
            except Exception as e:
                last_error = str(e)

            # Exponential backoff
            if attempt < self._max_retries:
                delay = min(2 ** attempt, 10)
                logger.debug(f"Retry {attempt + 1}/{self._max_retries} in {delay}s")
                await asyncio.sleep(delay)

        return LLMResponse(content="", error=f"All retries failed: {last_error}")

    async def health_check(self) -> dict[str, Any]:
        """Run health check on the configured provider."""
        if not self._active_provider:
            self.configure()

        result: dict[str, Any] = {
            "provider": self._active_provider,
            "model": self._active_model,
            "configured": self.available,
        }

        if not self.available:
            result["status"] = "not_configured"
            result["api_key"] = "NOT CONFIGURED"
            return result

        provider = self._providers[self._active_provider]
        try:
            start = time.time()
            ok = await provider.health_check()
            latency = time.time() - start
            result["connectivity"] = "OK" if ok else "FAILED"
            result["latency"] = round(latency, 2)
            result["status"] = "healthy" if ok else "unhealthy"
        except Exception as e:
            result["connectivity"] = f"FAILED: {e}"
            result["status"] = "error"

        return result

    async def smoke_test(self) -> dict[str, Any]:
        """Run LLM smoke test: minimal harmless request.

        Returns provider, model, latency, structured output success/failure.
        """
        if not self.available:
            return {
                "provider": self._active_provider or "none",
                "model": self._active_model or "none",
                "status": "not_configured",
                "error": "No LLM provider configured",
            }

        messages = [
            {
                "role": "user",
                "content": (
                    'Return a JSON object with exactly these fields: '
                    '{"action": "observe", "target": "test", "reason": "smoke test", '
                    '"confidence": 0.5}. Return ONLY the JSON, nothing else.'
                ),
            }
        ]

        start = time.time()
        resp = await self.generate(
            messages,
            max_tokens=200,
            response_format={"type": "json_object"},
        )
        latency = time.time() - start

        result: dict[str, Any] = {
            "provider": self._active_provider,
            "model": self._active_model,
            "latency": round(latency, 2),
            "status": "error" if resp.error else "ok",
        }

        if resp.error:
            result["error"] = resp.error
            return result

        # Validate structured output
        import json

        try:
            data = json.loads(resp.content)
            required = {"action", "target", "reason", "confidence"}
            has_all = required.issubset(data.keys())
            result["structured_output"] = "OK" if has_all else "INCOMPLETE"
            if not has_all:
                result["missing_fields"] = list(required - data.keys())
        except (json.JSONDecodeError, TypeError):
            result["structured_output"] = "FAILED"
            result["raw_response"] = resp.content[:200]

        return result

    def get_stats(self) -> dict[str, Any]:
        """Get manager statistics (no secrets)."""
        return {
            "active_provider": self._active_provider,
            "active_model": self._active_model,
            "fallback_provider": self._fallback_provider,
            "available_providers": [
                k for k in self._providers.keys() if not k.startswith("fallback_")
            ],
            "max_retries": self._max_retries,
        }
