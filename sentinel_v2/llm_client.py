"""LLM Client — OpenRouter integration with retry and fallback.

Clean rewrite of the V1 ai_engine.py. Keeps the proven pattern:
- Model rotation on failure
- Rate limit handling
- Context window management
- Structured response parsing

Removes: HITL, ModelRouter, all dead code.
"""

from __future__ import annotations

import asyncio
import time

try:
    from openai import AsyncOpenAI
except ImportError:
    AsyncOpenAI = None

from rich.console import Console

console = Console()


def _load_config():
    """Load config from .env file."""
    import os
    from pathlib import Path

    env_path = Path(__file__).parent.parent / ".env"
    if env_path.exists():
        for line in env_path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                key, _, value = line.partition("=")
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                # Remove inline comments
                if " #" in value:
                    value = value[:value.index(" #")].strip()
                os.environ.setdefault(key, value)

    return {
        "api_key": os.environ.get("OPENROUTER_API_KEY", ""),
        "base_url": os.environ.get("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1"),
        "site_url": os.environ.get("YOUR_SITE_URL", ""),
        "app_name": os.environ.get("YOUR_APP_NAME", "SentinelV2"),
        "models": [
            m.strip() for m in os.environ.get(
                "AI_MODELS",
                "mimo-v2.5-free"
            ).split(",") if m.strip()
        ],
        "max_tokens": int(os.environ.get("MAX_TOKENS", "4096")),
    }


class LLMClient:
    """LLM client with model rotation and retry logic.

    Usage:
        client = LLMClient()
        response = await client.complete([
            {"role": "system", "content": "You are a security researcher."},
            {"role": "user", "content": "Analyze this endpoint..."}
        ])
    """

    def __init__(self):
        self._config = _load_config()
        self._current_model_index = 0
        self._stats: dict[str, dict] = {}

        if AsyncOpenAI is None:
            raise ImportError("openai package required: pip install openai")

        if not self._config["api_key"]:
            raise ValueError("OPENROUTER_API_KEY not set. Check .env file.")

        self._client = AsyncOpenAI(
            api_key=self._config["api_key"],
            base_url=self._config["base_url"],
            timeout=120.0,
            default_headers={
                "HTTP-Referer": self._config["site_url"],
                "X-Title": self._config["app_name"],
            },
        )

    @property
    def current_model(self) -> str:
        models = self._config["models"]
        return models[self._current_model_index % len(models)]

    async def complete(
        self,
        messages: list[dict],
        temperature: float = 0.1,
        max_tokens: int | None = None,
        response_format: dict | None = None,
    ) -> str:
        """Complete a chat request. Retries on failure, rotates models.

        Args:
            response_format: Optional, e.g. {"type": "json_object"} for JSON mode.
        """
        if max_tokens is None:
            max_tokens = self._config["max_tokens"]

        models = self._config["models"]

        for attempt in range(len(models)):
            model = self.current_model
            try:
                start = time.time()
                kwargs = {
                    "model": model,
                    "messages": messages,
                    "max_tokens": max_tokens,
                    "temperature": temperature,
                }
                if response_format:
                    kwargs["response_format"] = response_format
                response = await self._client.chat.completions.create(**kwargs)
                elapsed = time.time() - start

                content = response.choices[0].message.content
                if not content or not content.strip():
                    raise ValueError("Empty response from model")

                self._record_success(model, elapsed)
                return content

            except Exception as e:
                err = str(e)
                self._record_failure(model, err)

                # If response_format caused error, retry without it
                if response_format and ("response_format" in err.lower() or "unsupported" in err.lower()):
                    console.print(f"[yellow]Model {model} doesn't support response_format, retrying without...[/yellow]")
                    response_format = None
                    continue

                if any(code in err for code in ["429", "rate limit", "quota"]):
                    backoff = min(5 * (2 ** attempt), 60)
                    console.print(f"[yellow]Rate limit on {model}, retrying in {backoff}s (attempt {attempt+1}/{len(models)})...[/yellow]")
                    self._current_model_index += 1
                    await asyncio.sleep(backoff)
                    continue
                elif any(w in err.lower() for w in ["context", "token", "length"]):
                    messages = [messages[0]] + messages[-3:]
                    continue
                elif any(code in err for code in ["404", "503", "502", "timeout"]):
                    console.print(f"[yellow]Model {model} unavailable, trying next...[/yellow]")
                    self._current_model_index += 1
                    await asyncio.sleep(2)
                    continue
                elif "401" in err:
                    console.print("[red]Invalid API key. Check OPENROUTER_API_KEY in .env[/red]")
                    raise SystemExit(1)
                else:
                    console.print(f"[yellow]Model error: {err[:100]}[/yellow]")
                    self._current_model_index += 1
                    await asyncio.sleep(2)
                    continue

        raise Exception("All models exhausted. Check API key and connectivity.")

    def _record_success(self, model: str, elapsed: float):
        if model not in self._stats:
            self._stats[model] = {"success": 0, "fail": 0, "avg_time": 0.0}
        self._stats[model]["success"] += 1
        self._stats[model]["avg_time"] = elapsed

    def _record_failure(self, model: str, error: str):
        if model not in self._stats:
            self._stats[model] = {"success": 0, "fail": 0, "avg_time": 0.0}
        self._stats[model]["fail"] += 1

    async def try_complete(
        self,
        messages: list[dict],
        temperature: float = 0.1,
        max_tokens: int | None = None,
        response_format: dict | None = None,
    ) -> str | None:
        """Complete a chat request. Returns None on failure instead of raising."""
        try:
            return await self.complete(messages, temperature, max_tokens, response_format)
        except Exception:
            return None

    def get_stats(self) -> dict:
        return dict(self._stats)
