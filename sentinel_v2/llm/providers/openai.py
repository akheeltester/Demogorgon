"""OpenAI Provider — supports OpenAI, OpenRouter, OpenCode, and compatible APIs."""

from __future__ import annotations

import time

try:
    from openai import AsyncOpenAI
except ImportError:
    AsyncOpenAI = None

from sentinel_v2.llm.base import LLMProvider, LLMResponse


class OpenAIProvider(LLMProvider):
    """OpenAI-compatible provider (OpenAI, OpenRouter, OpenCode, etc.)."""

    def __init__(
        self,
        api_key: str,
        base_url: str = "https://api.openai.com/v1",
        default_model: str = "gpt-4o-mini",
        timeout: float = 120.0,
    ):
        if AsyncOpenAI is None:
            raise ImportError("openai package required: pip install openai")
        self._client = AsyncOpenAI(
            api_key=api_key,
            base_url=base_url,
            timeout=timeout,
        )
        self._default_model = default_model

    @property
    def name(self) -> str:
        return "openai"

    @property
    def models(self) -> list[str]:
        return [self._default_model]

    async def generate(
        self,
        messages: list[dict[str, str]],
        model: str | None = None,
        temperature: float = 0.1,
        max_tokens: int = 4096,
        response_format: dict | None = None,
    ) -> LLMResponse:
        model = model or self._default_model
        start = time.time()

        try:
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

            content = response.choices[0].message.content or ""
            usage = {}
            if response.usage:
                usage = {
                    "prompt_tokens": response.usage.prompt_tokens,
                    "completion_tokens": response.usage.completion_tokens,
                    "total_tokens": response.usage.total_tokens,
                }

            return LLMResponse(
                content=content,
                model=model,
                usage=usage,
                latency=elapsed,
            )
        except Exception as e:
            return LLMResponse(
                content="",
                model=model,
                latency=time.time() - start,
                error=str(e),
            )
