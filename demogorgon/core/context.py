"""ContextBuilder — structured LLM context assembly with budget management.

Replaces naive `[:MAX_CHARS]` truncation with priority-aware, section-budgeted
context building that never cuts mid-JSON or mid-sentence.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ContextSection:
    """A named section of context with content and priority."""
    name: str
    content: str
    priority: int = 0  # Higher = more important, included first
    _char_count: int = field(default=0, repr=False)

    def __post_init__(self):
        self._char_count = len(self.content)


class ContextBuilder:
    """Builds structured LLM context within a character budget.

    Usage:
        cb = ContextBuilder(budget=8000)
        cb.add_section("target", "TARGET: https://example.com", priority=100)
        cb.add_section("model", "Product: SaaS\nRoles: admin, user", priority=90)
        cb.add_section("findings", "Found XSS in /search", priority=80)
        context = cb.build()

    The builder:
    - Includes sections in priority order (highest first)
    - Truncates individual sections to fit the budget
    - Never cuts mid-line (cuts at line boundaries)
    - Tracks what was included/excluded for debugging
    - Adds a summary line showing budget usage
    """

    def __init__(self, budget: int = 8000):
        self.budget = budget
        self._sections: list[ContextSection] = []
        self._used = 0

    @property
    def remaining(self) -> int:
        return max(0, self.budget - self._used)

    @property
    def usage_percent(self) -> float:
        return (self._used / self.budget * 100) if self.budget > 0 else 0

    def add_section(self, name: str, content: str, priority: int = 0) -> ContextBuilder:
        """Add a section. Returns self for chaining."""
        if not content or not content.strip():
            return self
        self._sections.append(ContextSection(name=name, content=content.strip(), priority=priority))
        return self

    def build(self) -> str:
        """Build the final context string, respecting budget.

        Sections are included in priority order. Within a section,
        lines are included until the budget is exhausted — no partial lines.
        """
        if not self._sections:
            return ""

        # Sort by priority (highest first), then by insertion order for ties
        sorted_sections = sorted(
            self._sections,
            key=lambda s: (-s.priority, self._sections.index(s)),
        )

        included: list[str] = []
        excluded: list[str] = []
        used = 0

        # Reserve space for the summary line at the end
        summary_overhead = 80
        effective_budget = self.budget - summary_overhead

        for section in sorted_sections:
            if used >= effective_budget:
                excluded.append(section.name)
                continue

            section_text = f"\n{section.name}:\n{section.content}"
            section_lines = section_text.split("\n")

            # Try to fit the entire section
            section_chars = len(section_text)
            if used + section_chars <= effective_budget:
                included.append(section_text)
                used += section_chars
            else:
                # Include as many complete lines as possible
                partial_lines: list[str] = []
                partial_used = 0
                for line in section_lines:
                    line_len = len(line) + 1  # +1 for newline
                    if used + partial_used + line_len <= effective_budget:
                        partial_lines.append(line)
                        partial_used += line_len
                    else:
                        break
                if partial_lines:
                    included.append("\n".join(partial_lines))
                    used += partial_used
                excluded.append(f"{section.name} (partial)")

        self._used = used

        # Build final context
        context = "".join(included)

        # Add budget summary
        if excluded:
            context += f"\n\n[Context: {used}/{self.budget} chars, excluded: {', '.join(excluded)}]"

        return context.strip()
