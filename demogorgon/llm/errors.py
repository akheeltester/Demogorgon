"""LLM error classification (Phase 5).

Every provider error string / exception is mapped to one LLMErrorKind so the
manager can decide: retry, fall back, open the circuit, or surface as
DEPENDENCY_MISSING.  This replaces ad-hoc keyword checks scattered across
``_generate_with_retry``.
"""

from __future__ import annotations

import re
from enum import Enum


class LLMErrorKind(Enum):
    """Classification of an LLM provider failure."""

    TRANSIENT = "transient"                # 5xx, timeout, connection reset → retry
    RATE_LIMIT = "rate_limit"              # 429 → short retry, then fall back
    AUTHENTICATION = "authentication"      # 401/403/invalid key → no retry, fall back
    DEPENDENCY_MISSING = "dependency_missing"  # ImportError (e.g. google-genai) → never retry
    CONTENT_FILTER = "content_filter"      # 400 safety → no retry
    INVALID_REQUEST = "invalid_request"    # bad request → no retry
    UNKNOWN = "unknown"


#: Substrings checked per kind (lowercase matching).
_KIND_MARKERS: list[tuple[LLMErrorKind, tuple[str, ...]]] = [
    (LLMErrorKind.DEPENDENCY_MISSING, (
        "not installed", "no module named", "importerror", "package not",
        "missing dependency",
    )),
    (LLMErrorKind.AUTHENTICATION, (
        "unauthorized", "invalid api key", "invalid_api_key", "api_key",
        "authentication", "permission denied", " 401", "401 ", " 403", "403 ",
        "invalid x-api-key", "incorrect api key",
    )),
    (LLMErrorKind.RATE_LIMIT, (
        "rate limit", "rate_limit", "too many requests", " 429", "429 ",
        "quota exceeded", "resource exhausted",
    )),
    (LLMErrorKind.CONTENT_FILTER, (
        "content filter", "content_policy", "safety", "blocked by",
        "prohibited content",
    )),
    (LLMErrorKind.INVALID_REQUEST, (
        "invalid request", "bad request", " 400", "400 ", "model not found",
        "does not exist", "unsupported parameter",
    )),
    (LLMErrorKind.TRANSIENT, (
        "server error", "internal server", " 500", "500 ", " 502", "502 ",
        " 503", "503 ", " 504", "504 ", "bad gateway", "service unavailable",
        "timeout", "timed out", "connection reset", "connection aborted",
        "temporarily unavailable", "overloaded",
    )),
]


def classify_llm_error(error: str | BaseException | None) -> LLMErrorKind:
    """Classify an LLM error message/exception into an LLMErrorKind."""
    if error is None:
        return LLMErrorKind.UNKNOWN
    if isinstance(error, BaseException):
        import asyncio

        if isinstance(error, (asyncio.TimeoutError, TimeoutError)):
            return LLMErrorKind.TRANSIENT
        if isinstance(error, ImportError):
            return LLMErrorKind.DEPENDENCY_MISSING
        text = str(error)
    else:
        text = str(error)

    lowered = text.lower()
    for kind, markers in _KIND_MARKERS:
        for marker in markers:
            if marker in lowered:
                return kind
    return LLMErrorKind.UNKNOWN


#: `{'error': {'code': 400, 'message': 'API key not valid …'}}` and its
#: `{"error": {"message": "…"}}` twin — Google, Azure, OpenAI-style documents.
_MESSAGE_FIELD = re.compile(r"""['"]message['"]\s*:\s*['"](.+?)['"]""")


def summarize_llm_error(
    error: str | BaseException | None, limit: int = 300
) -> str:
    """Reduce a raw provider error to one readable line.

    Providers return a whole error document — Google's INVALID_ARGUMENT is a
    nested dict with `details`, `@type` and two copies of the message — which
    reads as noise when the setup wizard prints it.  Extract the human
    ``message`` field when present, then cap the length.
    """
    if error is None:
        return ""
    text = str(error).strip()
    if not text:
        return ""
    match = _MESSAGE_FIELD.search(text)
    if match:
        text = match.group(1).strip()
    if len(text) > limit:
        text = text[: limit - 1].rstrip() + "…"
    return text


#: Which kinds the manager should retry (same provider).
RETRYABLE_KINDS = {
    LLMErrorKind.TRANSIENT,
    LLMErrorKind.RATE_LIMIT,
    LLMErrorKind.UNKNOWN,  # unknown errors get the benefit of the doubt, bounded
}

#: Which kinds should immediately move to the fallback provider.
FALLBACK_KINDS = {
    LLMErrorKind.AUTHENTICATION,
    LLMErrorKind.RATE_LIMIT,
    LLMErrorKind.TRANSIENT,
    LLMErrorKind.UNKNOWN,
    LLMErrorKind.INVALID_REQUEST,
    LLMErrorKind.CONTENT_FILTER,
}

#: Which kinds should open the circuit (stop trying this provider entirely).
CIRCUIT_OPEN_KINDS = {
    LLMErrorKind.AUTHENTICATION,
    LLMErrorKind.DEPENDENCY_MISSING,
}


class LLMUnavailableError(RuntimeError):
    """Raised when no LLM provider can serve a request.

    Callers (research loop) must treat this as "run deterministic mode",
    not as a crash.
    """

    def __init__(self, message: str, kind: LLMErrorKind = LLMErrorKind.UNKNOWN):
        super().__init__(message)
        self.kind = kind
