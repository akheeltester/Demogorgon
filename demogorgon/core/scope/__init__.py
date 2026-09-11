"""Scope Intelligence Engine — the scope subsystem.

Provides:
- Parser: Parse program policies from text
- Normalizer: Normalize asset patterns
- Matcher: Match targets against scope
- Safety: Enforce safety rules

Usage:
    from demogorgon.core.scope import parse_program_policy, ScopeMatcher, SafetyGate
"""

from .parser import parse_program_policy
from .normalizer import normalize_asset, normalize_assets
from .matcher import ScopeMatcher, MatchResult
from .safety import SafetyGate, SafetyCheck

__all__ = [
    "parse_program_policy",
    "normalize_asset",
    "normalize_assets",
    "ScopeMatcher",
    "MatchResult",
    "SafetyGate",
    "SafetyCheck",
]
