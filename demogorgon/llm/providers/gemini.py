"""Google Gemini provider for DEMOGORGON.

Requires: pip install google-genai
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from demogorgon.llm.base import LLMProvider, LLMResponse


@dataclass
class GeminiProvider(LLMProvider):
    """Google Gemini provider."""

    api_key: str
    default_model: str = "gemini-2.0-flash"

    @property
    def name(self) -> str:
        return "gemini"

    @property
    def models(self) -> list[str]:
        return [
            "gemini-2.0-flash",
            "gemini-2.5-pro",
            "gemini-2.5-flash",
            "gemini-1.5-pro",
            "gemini-1.5-flash",
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
            from google import genai
            from google.genai import types

            client = genai.Client(api_key=self.api_key)
            model = model or self.default_model

            # Convert OpenAI-style messages to Gemini format
            contents = []
            for msg in messages:
                role = "user" if msg["role"] in ("user", "system") else "model"
                contents.append(types.Content(
                    role=role,
                    parts=[types.Part.from_text(text=msg["content"])],
                ))

            config = types.GenerateContentConfig(
                temperature=temperature,
                max_output_tokens=max_tokens,
            )

            # Request JSON output if response_format specified
            if response_format and response_format.get("type") == "json_object":
                config.response_mime_type = "application/json"

            start = time.time()
            response = await client.aio.models.generate_content(
                model=model,
                contents=contents,
                config=config,
            )
            latency = time.time() - start

            content = response.text or ""
            usage = {}
            if response.usage_metadata:
                usage = {
                    "prompt_tokens": response.usage_metadata.prompt_token_count or 0,
                    "completion_tokens": response.usage_metadata.candidates_token_count or 0,
                    "total_tokens": response.usage_metadata.total_token_count or 0,
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
                error="google-genai package not installed. Run: pip install google-genai",
            )
        except Exception as e:
            return LLMResponse(content="", error=str(e))
