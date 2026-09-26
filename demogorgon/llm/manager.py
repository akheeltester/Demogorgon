"""AI Provider Manager — provider selection, configuration, retry, and fallback.

Class name: AIProviderManager (LLMManager is a backward-compatible alias).

Supports multiple configuration formats (highest priority first):

1. DEMOGORGON_* prefix (recommended):
    DEMOGORGON_LLM_PROVIDER=openai|openrouter|anthropic|deepseek|ollama
    DEMOGORGON_API_KEY=api_key
    DEMOGORGON_MODEL=model_name
    DEMOGORGON_FAST_MODEL=fast_model_name      # Laya decisions
    DEMOGORGON_REASONING_MODEL=reasoning_model # deep analysis
    DEMOGORGON_BASE_URL=base_url

2. LLM_* prefix (legacy):
    LLM_PROVIDER=openai
    LLM_API_KEY=api_key
    LLM_MODEL=model_name
    LLM_BASE_URL=base_url

3. Provider-specific prefix:
    OPENROUTER_API_KEY + OPENROUTER_BASE_URL
    NVIDIA_API_KEY + NVIDIA_BASE_URL
    OPENCODE_API_KEY + OPENCODE_BASE_URL

4. Model aliases:
    PRIMARY_MODEL=model_name (used if DEMOGORGON_MODEL/LLM_MODEL not set)
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from pathlib import Path
from typing import Any

from demogorgon.llm.base import LLMProvider, LLMResponse
from demogorgon.llm.errors import LLMErrorKind

logger = logging.getLogger(__name__)

# Known provider defaults
PROVIDER_DEFAULTS = {
    "openai": {"base_url": "https://api.openai.com/v1", "model": "gpt-4o-mini"},
    "openrouter": {"base_url": "https://openrouter.ai/api/v1", "model": "nvidia/nemotron-3-super-120b-a12b:free"},
    "anthropic": {"base_url": "", "model": "claude-sonnet-4-20250514"},
    "gemini": {"base_url": "", "model": "gemini-2.0-flash"},
    "deepseek": {"base_url": "https://api.deepseek.com/v1", "model": "deepseek-chat"},
    "ollama": {"base_url": "http://localhost:11434/v1", "model": "llama3.1:8b"},
}

# Provider detection from env vars
PROVIDER_ENV_MAP = {
    "OPENROUTER_API_KEY": "openrouter",
    "NVIDIA_API_KEY": "openrouter",      # NVIDIA uses OpenAI-compatible API
    "OPENCODE_API_KEY": "openai",        # OpenCode uses OpenAI-compatible API
    "GEMINI_API_KEY": "gemini",
    "GOOGLE_API_KEY": "gemini",
    "ANTHROPIC_API_KEY": "anthropic",
    "OPENAI_API_KEY": "openai",
    "DEEPSEEK_API_KEY": "deepseek",
}


# Env-var prefixes that configure an LLM provider (shell exports count too)
_PROVIDER_ENV_PREFIXES = (
    "DEMOGORGON_",
    "LLM_",
    "OPENAI_",
    "OPENROUTER_",
    "OPENCODE_",
    "ANTHROPIC_",
    "GEMINI_",
    "GOOGLE_",
    "DEEPSEEK_",
    "NVIDIA_",
    "PRIMARY_",
    "FALLBACK_",
)


def _provider_configured(config: dict[str, str]) -> bool:
    """Whether an LLM provider is configured via env vars / .env."""
    if config.get("DEMOGORGON_LLM_PROVIDER") or config.get("LLM_PROVIDER"):
        return True
    if config.get("DEMOGORGON_API_KEY") or config.get("LLM_API_KEY"):
        return True
    return any(config.get(k) for k in PROVIDER_ENV_MAP)


def _merge_saved_provider_env(config: dict[str, str]) -> dict[str, str]:
    """Merge provider config saved by the setup wizard (~/.demogorgon).

    Only fills gaps — keys already present in config are never overwritten.
    Mutates and returns config.
    """
    if _provider_configured(config):
        return config
    try:
        from ..config.provider_config import ProviderConfigManager

        saved = ProviderConfigManager().to_env_dict()
        for key, value in saved.items():
            if value and not config.get(key):
                config[key] = value
    except Exception:
        pass
    return config


def _load_env() -> dict[str, str]:
    """Load LLM config from process env, .env file, and saved wizard config.

    Precedence (highest first):
      1. .env file (repo root) — explicit project config
      2. process environment (shell exports)
      3. ~/.demogorgon/ — provider saved by `demogorgon setup` wizard
    """
    env_path = Path(__file__).parent.parent.parent / ".env"
    file_config: dict[str, str] = {}
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
                file_config[key] = value

    # Shell exports (only provider-relevant prefixes) — .env wins on conflict
    config: dict[str, str] = {
        k: v
        for k, v in os.environ.items()
        if v and k.startswith(_PROVIDER_ENV_PREFIXES)
    }
    config.update(file_config)

    # Fallback: provider saved by the `demogorgon setup` wizard (~/.demogorgon/)
    _merge_saved_provider_env(config)

    for key, value in config.items():
        os.environ.setdefault(key, value)
    return config


def _mask_key(key: str) -> str:
    """Mask an API key for display."""
    if not key or len(key) < 8:
        return "NOT CONFIGURED"
    return f"{key[:4]}...{key[-4:]}"


def _detect_provider_from_env(env: dict[str, str]) -> tuple[str, str, str, str]:
    """Auto-detect provider, api_key, base_url, model from any env format.

    Returns (provider_name, api_key, base_url, model).
    """
    # 1. Explicit DEMOGORGON_ vars (highest priority)
    provider = env.get("DEMOGORGON_LLM_PROVIDER", "")
    api_key = env.get("DEMOGORGON_API_KEY", "")
    base_url = env.get("DEMOGORGON_BASE_URL", "")
    model = env.get("DEMOGORGON_MODEL", "")

    # 2. Legacy LLM_ vars
    if not provider:
        provider = env.get("LLM_PROVIDER", "")
    if not api_key:
        api_key = env.get("LLM_API_KEY", "")
    if not base_url:
        base_url = env.get("LLM_BASE_URL", "")
    if not model:
        model = env.get("LLM_MODEL", "")

    # 3. PRIMARY_MODEL alias (common in older setups)
    if not model:
        model = env.get("PRIMARY_MODEL", "")

    # 4. Provider-specific env vars (auto-detect provider if not set)
    if not api_key:
        for env_prefix, detected_provider in PROVIDER_ENV_MAP.items():
            key = env.get(f"{env_prefix}", "")
            if key:
                api_key = key
                if not provider:
                    provider = detected_provider
                # Set base_url from provider-specific var
                base_url_key = env_prefix.replace("_API_KEY", "_BASE_URL")
                if not base_url:
                    base_url = env.get(base_url_key, "")
                break

    # 5. If still no provider but we have an API key, try to detect
    if not provider and api_key:
        if "sk-or-" in api_key:
            provider = "openrouter"
        elif "nvapi-" in api_key:
            provider = "openrouter"  # NVIDIA uses OpenAI-compatible
        else:
            provider = "openai"

    # 6. Default provider
    if not provider:
        provider = "openai"

    # 7. Apply provider defaults for missing values
    defaults = PROVIDER_DEFAULTS.get(provider, PROVIDER_DEFAULTS["openai"])
    if not base_url:
        base_url = defaults["base_url"]
    if not model:
        model = defaults["model"]

    return provider, api_key, base_url, model


class AIProviderManager:
    """Manages LLM providers with retry, fallback, and failure handling.

    Usage:
        manager = AIProviderManager()
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
        self._fast_model: str = ""
        self._reasoning_model: str = ""
        self._fallback_provider: str = ""
        self._fallback_model: str = ""
        self._max_retries: int = 2
        self._timeout: float = 60.0
        # Phase 5: ordered fallback chain + per-provider circuit breakers
        self._fallback_chain: list[str] = []
        self._circuit_open: dict[str, str] = {}  # provider_key -> reason

    def configure(self) -> None:
        """Configure providers from environment variables."""
        provider_name, api_key, base_url, model = _detect_provider_from_env(self._env)
        
        self._fast_model = self._env.get("DEMOGORGON_FAST_MODEL", model)
        self._reasoning_model = self._env.get("DEMOGORGON_REASONING_MODEL", model)

        self._max_retries = int(
            self._env.get("DEMOGORGON_LLM_MAX_RETRIES",
                          self._env.get("LLM_MAX_RETRIES", "2"))
        )
        self._timeout = float(
            self._env.get("DEMOGORGON_LLM_TIMEOUT",
                          self._env.get("LLM_TIMEOUT", "60"))
        )

        self._configure_provider(provider_name, api_key, base_url, model)

        # Configure fallback if specified
        fallback_provider = (
            self._env.get("DEMOGORGON_FALLBACK_PROVIDER", "")
            or self._env.get("LLM_FALLBACK_PROVIDER", "")
        )
        fallback_model = (
            self._env.get("DEMOGORGON_FALLBACK_MODEL", "")
            or self._env.get("LLM_FALLBACK_MODEL", "")
            or self._env.get("FALLBACK_MODEL", "")
        )
        if fallback_provider and fallback_provider != provider_name:
            fb_model = fallback_model or model
            fb_key = api_key
            fb_url = base_url
            self._configure_provider(
                fallback_provider, fb_key, fb_url, fb_model, is_fallback=True
            )

    def configure_from_params(
        self,
        provider: str,
        api_key: str = "",
        base_url: str = "",
        model: str = "",
        fast_model: str = "",
        reasoning_model: str = "",
        fallback_provider: str = "",
        fallback_api_key: str = "",
        fallback_base_url: str = "",
        fallback_model: str = "",
    ) -> None:
        """Configure from explicit parameters (for ProviderConfigManager integration).

        This bypasses env var detection and configures directly.
        """
        self._max_retries = int(
            self._env.get("DEMOGORGON_LLM_MAX_RETRIES", "2")
        )
        self._timeout = float(
            self._env.get("DEMOGORGON_LLM_TIMEOUT", "60")
        )

        # Apply provider defaults for missing values
        defaults = PROVIDER_DEFAULTS.get(provider, PROVIDER_DEFAULTS["openai"])
        if not base_url:
            base_url = defaults.get("base_url", "")
        if not model:
            model = defaults.get("model", "")
            
        self._fast_model = fast_model or model
        self._reasoning_model = reasoning_model or model

        self._configure_provider(provider, api_key, base_url, model)

        # Configure fallback if specified
        if fallback_provider and fallback_provider != provider:
            fb_defaults = PROVIDER_DEFAULTS.get(fallback_provider, PROVIDER_DEFAULTS["openai"])
            fb_url = fallback_base_url or fb_defaults.get("base_url", "")
            fb_model = fallback_model or fb_defaults.get("model", "")
            self._configure_provider(
                fallback_provider, fallback_api_key, fb_url, fb_model, is_fallback=True
            )

    def configure_from_profile(self, profile: Any) -> None:
        """Configure from a ProviderProfile object (from ProviderConfigManager)."""
        self.configure_from_params(
            provider=profile.provider,
            api_key=profile.api_key,
            base_url=profile.base_url,
            model=profile.selected_model,
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
        if not api_key and name != "ollama":
            logger.warning(f"No API key for provider '{name}'")
            return

        provider_key = f"fallback_{name}" if is_fallback else name

        try:
            if name in ("openai", "openrouter"):
                from demogorgon.llm.providers.openai import OpenAIProvider

                url = base_url or PROVIDER_DEFAULTS["openai"]["base_url"]
                mdl = model or PROVIDER_DEFAULTS["openai"]["model"]
                self._providers[provider_key] = OpenAIProvider(
                    api_key=api_key,
                    base_url=url,
                    default_model=mdl,
                )
            elif name == "deepseek":
                from demogorgon.llm.providers.openai import OpenAIProvider

                url = base_url or PROVIDER_DEFAULTS["deepseek"]["base_url"]
                mdl = model or PROVIDER_DEFAULTS["deepseek"]["model"]
                self._providers[provider_key] = OpenAIProvider(
                    api_key=api_key,
                    base_url=url,
                    default_model=mdl,
                )
            elif name == "ollama":
                from demogorgon.llm.providers.openai import OpenAIProvider

                url = base_url or PROVIDER_DEFAULTS["ollama"]["base_url"]
                mdl = model or PROVIDER_DEFAULTS["ollama"]["model"]
                self._providers[provider_key] = OpenAIProvider(
                    api_key="ollama",
                    base_url=url,
                    default_model=mdl,
                )
            elif name == "anthropic":
                from demogorgon.llm.providers.anthropic import AnthropicProvider

                mdl = model or PROVIDER_DEFAULTS["anthropic"]["model"]
                self._providers[provider_key] = AnthropicProvider(
                    api_key=api_key,
                    default_model=mdl,
                )
            elif name == "gemini":
                from demogorgon.llm.providers.gemini import GeminiProvider

                mdl = model or PROVIDER_DEFAULTS["gemini"]["model"]
                self._providers[provider_key] = GeminiProvider(
                    api_key=api_key,
                    default_model=mdl,
                )
            else:
                # Unknown provider — try OpenAI-compatible
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
            self._active_model = model or PROVIDER_DEFAULTS.get(name, {}).get("model", "gpt-4o-mini")
        else:
            if provider_key not in self._fallback_chain:
                self._fallback_chain.append(provider_key)
        logger.info(
            f"Configured LLM provider: {name} (model: {model})"
            + (" [fallback]" if is_fallback else "")
        )

    @property
    def fallback_chain(self) -> list[str]:
        """Ordered fallback provider keys (Phase 5)."""
        return list(self._fallback_chain)

    @property
    def open_circuits(self) -> dict[str, str]:
        """provider_key → reason for providers that must not be tried."""
        return dict(self._circuit_open)

    def reset_circuits(self) -> None:
        """Clear circuit-breaker state (used by tests / setup wizard retry)."""
        self._circuit_open.clear()

    def _candidate_providers(self) -> list[str]:
        """Active provider first, then configured fallbacks, skipping open circuits."""
        candidates: list[str] = []
        if self._active_provider:
            candidates.append(self._active_provider)
        # Legacy key convention: fallback_<active> … plus the explicit chain
        legacy = f"fallback_{self._active_provider}"
        if legacy in self._providers and legacy not in candidates:
            candidates.append(legacy)
        for key in self._fallback_chain:
            if key not in candidates:
                candidates.append(key)
        # any other registered fallbacks (safety net)
        for key in self._providers:
            if key.startswith("fallback_") and key not in candidates:
                candidates.append(key)
        return [
            k for k in candidates
            if k in self._providers and k not in self._circuit_open
        ]

    def _note_failure(self, provider_key: str, error: str) -> LLMErrorKind:
        """Classify an error, open the circuit if needed, return the kind."""
        from .errors import CIRCUIT_OPEN_KINDS, classify_llm_error

        kind = classify_llm_error(error)
        if kind in CIRCUIT_OPEN_KINDS:
            self._circuit_open[provider_key] = f"{kind.value}: {error[:200]}"
            logger.warning(
                f"Circuit OPEN for provider '{provider_key}' ({kind.value})"
            )
        return kind

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

    @property
    def fast_model(self) -> str:
        """Get the model configured for fast, structured tasks."""
        if not self._active_provider:
            self.configure()
        return self._fast_model or self._active_model

    @property
    def reasoning_model(self) -> str:
        """Get the model configured for deep reasoning tasks."""
        if not self._active_provider:
            self.configure()
        return self._reasoning_model or self._active_model

    async def generate(
        self,
        messages: list[dict[str, str]],
        model: str | None = None,
        temperature: float = 0.1,
        max_tokens: int = 4096,
        response_format: dict | None = None,
    ) -> LLMResponse:
        """Generate a response with retry and fallback (Phase 5 chain).

        Flow:
        1. Walk the candidate chain (active → fallbacks), skipping open circuits.
        2. Each candidate gets bounded retries per error classification.
        3. If nothing serves the request, return an error LLMResponse —
           callers that prefer exceptions use :meth:`generate_or_raise`.
        """
        if not self._active_provider:
            self.configure()

        candidates = self._candidate_providers()
        if not candidates:
            # everything is circuit-open or nothing configured
            reason = (
                f"All providers unavailable (circuits open: {self._circuit_open})"
                if self._circuit_open else "No LLM provider configured"
            )
            return LLMResponse(content="", error=reason)

        errors: list[str] = []
        for key in candidates:
            resp = await self._generate_with_retry(
                provider_key=key,
                messages=messages,
                model=model,
                temperature=temperature,
                max_tokens=max_tokens,
                response_format=response_format,
            )
            if not resp.error:
                if key != self._active_provider:
                    logger.info(f"Served by fallback provider: {key}")
                return resp
            errors.append(f"{key}: {resp.error[:200]}")

        return LLMResponse(
            content="",
            error=f"All retries failed: {'; '.join(errors)[:500]}",
        )

    async def generate_or_raise(
        self,
        messages: list[dict[str, str]],
        **kwargs: Any,
    ) -> LLMResponse:
        """Like :meth:`generate` but raises LLMUnavailableError on failure.

        Used by callers that must switch modes (LLM → deterministic) instead
        of silently receiving an error string.
        """
        resp = await self.generate(messages, **kwargs)
        if resp.error:
            from .errors import LLMUnavailableError, classify_llm_error

            raise LLMUnavailableError(resp.error, classify_llm_error(resp.error))
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
        """Generate with classification-driven retry (Phase 5).

        - TRANSIENT / RATE_LIMIT / UNKNOWN → bounded retries with backoff
        - AUTHENTICATION / DEPENDENCY_MISSING / INVALID_REQUEST / CONTENT_FILTER
          → no retry, circuit opens for auth + dependency failures
        """
        from .errors import RETRYABLE_KINDS, classify_llm_error

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
                kind = classify_llm_error(resp.error)
                if kind not in RETRYABLE_KINDS:
                    self._note_failure(provider_key, resp.error)
                    return resp

            except asyncio.TimeoutError:
                last_error = f"Timeout after {self._timeout}s"
                kind = classify_llm_error(last_error)
                if kind not in RETRYABLE_KINDS:
                    self._note_failure(provider_key, last_error)
                    return LLMResponse(content="", error=last_error)
            except ImportError as e:
                # dependency missing (e.g. google-genai not installed)
                last_error = str(e)
                self._note_failure(provider_key, last_error)
                return LLMResponse(content="", error=last_error)
            except Exception as e:
                last_error = str(e)
                kind = classify_llm_error(e)
                if kind not in RETRYABLE_KINDS:
                    self._note_failure(provider_key, last_error)
                    return LLMResponse(content="", error=last_error)

            # Exponential backoff
            if attempt < self._max_retries:
                delay = min(2 ** attempt, 10)
                logger.debug(f"Retry {attempt + 1}/{self._max_retries} in {delay}s")
                await asyncio.sleep(delay)

        final = f"All retries failed: {last_error}"
        self._note_failure(provider_key, final)
        return LLMResponse(content="", error=final)

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

LLMManager = AIProviderManager

