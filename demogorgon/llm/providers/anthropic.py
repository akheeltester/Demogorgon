"""Anthropic Claude provider for DEMOGORGON.

Requires: pip install anthropic
"""

from __future__ import annotations

from dataclasses import dataclass

from demogorgon.llm.base import LLMProvider, LLMResponse


@dataclass
class AnthropicProvider(LLMProvider):
    """Anthropic Claude provider."""

    api_key: str
    default_model: str = "claude-sonnet-4-20250514"

    @property
    def name(self) -> str:
        return "anthropic"

    @property
    def models(self) -> list[str]:
        return [
            "claude-sonnet-4-20250514",
            "claude-3-5-haiku-20241022",
            "claude-3-opus-20240229",
        ]

    async def generate(
        self,
        messages: list[dict[str, str]],
        model: str | None = None,
        temperature: float = 0.1,
        max_tokens: int = 4096,
        response_format: dict | None = None,
    ) -> LLMResponse:
        try:
            import anthropic
            import time

            client = anthropic.AsyncAnthropic(api_key=self.api_key)
            model = model or self.default_model

            # Convert OpenAI-style messages to Anthropic format
            system_msg = ""
            user_messages = []
            for msg in messages:
                if msg["role"] == "system":
                    system_msg = msg["content"]
                else:
                    user_messages.append(msg)

            start = time.time()
            kwargs = {
                "model": model,
                "messages": user_messages,
                "max_tokens": max_tokens,
                "temperature": temperature,
            }
            if system_msg:
                kwargs["system"] = system_msg

            response = await client.messages.create(**kwargs)
            latency = time.time() - start

            content = response.content[0].text if response.content else ""
            usage = {
                "prompt_tokens": response.usage.input_tokens,
                "completion_tokens": response.usage.output_tokens,
            }

            return LLMResponse(
                content=content,
                model=model,
                usage=usage,
                latency=latency,
            )
        except ImportError:
            return LLMResponse(
                content="",
                error="anthropic package not installed. Run: pip install anthropic",
            )
        except Exception as e:
            return LLMResponse(content="", error=str(e))
