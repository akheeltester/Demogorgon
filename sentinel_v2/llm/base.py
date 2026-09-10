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

    async def health_check(self) -> bool:
        try:
            resp = await self.generate(
                [{"role": "user", "content": "Say 'ok'"}],
                max_tokens=10,
            )
            return not resp.error
        except Exception:
            return False
