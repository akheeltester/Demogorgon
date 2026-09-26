"""LLM Base — provider abstraction for language models.

All providers implement this interface. The researcher only calls:
response = llm.generate(...)
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class LLMResponse:
    content: str
    model: str = ""
    usage: dict[str, int] = field(default_factory=dict)
    latency: float = 0.0
    error: str = ""


class LLMProvider(ABC):
    """Base class for LLM providers."""

    @property
    @abstractmethod
    def name(self) -> str:
        pass

    @property
    @abstractmethod
    def models(self) -> list[str]:
        pass

    @abstractmethod
    async def generate(
        self,
        messages: list[dict[str, str]],
        model: str | None = None,
        temperature: float = 0.1,
        max_tokens: int = 4096,
        response_format: dict | None = None,
    ) -> LLMResponse:
        pass

    async def health_check(self) -> str | None:
        """Return None when the provider answers, else the concrete reason.

        Returning the reason (rather than a bare ``False``) is what lets the
        setup wizard say ``google-genai package not installed`` instead of the
        useless ``Provider not reachable (FAILED)``.
        """
        try:
            resp = await self.generate(
                [{"role": "user", "content": "Say 'ok'"}],
                max_tokens=10,
            )
        except Exception as e:  # noqa: BLE001 - surface any provider failure
            return str(e) or type(e).__name__
        if resp.error:
            return resp.error
        return None
