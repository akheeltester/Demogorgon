"""Research Memory — persistent cross-session knowledge.

Stores and retrieves learned information across sessions:
- Which vuln classes work on which tech stacks
- Which endpoints are high-value
- Which tools are most effective for specific targets
- Past findings and their patterns
- Target-specific intelligence

This enables the agent to learn from previous engagements.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class MemoryEntry:
    """A single memory entry."""
    key: str
    category: str  # "vuln_pattern", "tool_effectiveness", "target_intel", "finding_pattern"
    content: str
    data: dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.5
    source: str = ""  # which engagement/session produced this
    created_at: float = field(default_factory=time.time)
    last_accessed: float = 0.0
    access_count: int = 0

    def to_dict(self) -> dict:
        return {
            "key": self.key,
            "category": self.category,
            "content": self.content,
            "data": self.data,
            "confidence": self.confidence,
            "source": self.source,
            "created_at": self.created_at,
            "last_accessed": self.last_accessed,
            "access_count": self.access_count,
        }

    @classmethod
    def from_dict(cls, d: dict) -> MemoryEntry:
        return cls(**d)


class ResearchMemory:
    """Persistent cross-session research memory.

    Usage:
        memory = ResearchMemory("/path/to/workspace")

        # Store a memory
        memory.store("xss_works_on_search", "vuln_pattern",
                     "XSS payloads work on /search?q= parameter",
                     data={"endpoint": "/search", "param": "q"})

        # Retrieve memories
        entries = memory.retrieve(category="vuln_pattern")
        entries = memory.retrieve(query="xss")

        # Get context for LLM
        context = memory.get_llm_context(target="https://example.com")
    """

    def __init__(self, workspace_dir: str = ""):
        self._workspace_dir = workspace_dir
        self._memory_file = os.path.join(workspace_dir, "research_memory.json") if workspace_dir else ""
        self._entries: dict[str, MemoryEntry] = {}

        if self._memory_file and os.path.exists(self._memory_file):
            self._load()

    def store(
        self,
        key: str,
        category: str,
        content: str,
        data: dict[str, Any] | None = None,
        confidence: float = 0.5,
        source: str = "",
        overwrite: bool = False,
    ) -> MemoryEntry:
        """Store a memory entry."""
        if key in self._entries and not overwrite:
            # Update existing
            existing = self._entries[key]
            existing.content = content
            existing.data = data or existing.data
            existing.confidence = max(existing.confidence, confidence)
            existing.last_accessed = time.time()
            return existing

        entry = MemoryEntry(
            key=key,
            category=category,
            content=content,
            data=data or {},
            confidence=confidence,
            source=source,
        )
        self._entries[key] = entry
        self._save()
        return entry

    def retrieve(
        self,
        category: str = "",
        query: str = "",
        limit: int = 20,
        min_confidence: float = 0.0,
    ) -> list[MemoryEntry]:
        """Retrieve memory entries by category or query."""
        entries = list(self._entries.values())

        if category:
            entries = [e for e in entries if e.category == category]

        if query:
            query_lower = query.lower()
            entries = [
                e for e in entries
                if query_lower in e.key.lower()
                or query_lower in e.content.lower()
                or query_lower in json.dumps(e.data).lower()
            ]

        if min_confidence > 0:
            entries = [e for e in entries if e.confidence >= min_confidence]

        # Sort by confidence and recency
        entries.sort(key=lambda e: (e.confidence, e.last_accessed), reverse=True)

        # Update access counts
        for entry in entries[:limit]:
            entry.access_count += 1
            entry.last_accessed = time.time()

        return entries[:limit]

    def get_for_target(self, target: str, limit: int = 20) -> list[MemoryEntry]:
        """Get memories relevant to a specific target."""
        return self.retrieve(query=target, limit=limit)

    def get_for_vuln_class(self, vuln_class: str) -> list[MemoryEntry]:
        """Get memories about a specific vulnerability class."""
        return self.retrieve(category="vuln_pattern", query=vuln_class)

    def get_tool_effectiveness(self, tool_name: str) -> list[MemoryEntry]:
        """Get memories about tool effectiveness."""
        return self.retrieve(category="tool_effectiveness", query=tool_name)

    def get_finding_patterns(self) -> list[MemoryEntry]:
        """Get all finding pattern memories."""
        return self.retrieve(category="finding_pattern")

    def forget(self, key: str) -> bool:
        """Remove a memory entry."""
        if key in self._entries:
            del self._entries[key]
            self._save()
            return True
        return False

    def get_llm_context(self, target: str = "", max_entries: int = 15) -> str:
        """Generate a memory summary for LLM context."""
        entries = []

        # Target-specific memories
        if target:
            target_entries = self.get_for_target(target, limit=5)
            entries.extend(target_entries)

        # Recent finding patterns
        finding_entries = self.get_finding_patterns()[:3]
        entries.extend(finding_entries)

        # High-confidence memories
        high_conf = self.retrieve(min_confidence=0.7, limit=5)
        entries.extend(high_conf)

        # Deduplicate
        seen_keys = set()
        unique_entries = []
        for e in entries:
            if e.key not in seen_keys:
                seen_keys.add(e.key)
                unique_entries.append(e)

        if not unique_entries:
            return "No prior research memories."

        lines = [f"Research Memory ({len(unique_entries)} entries):"]
        for entry in unique_entries[:max_entries]:
            lines.append(f"  [{entry.category}] {entry.content[:100]}")
            if entry.data:
                # Show key data points
                for k, v in list(entry.data.items())[:2]:
                    lines.append(f"    {k}: {str(v)[:50]}")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        """Get memory statistics."""
        categories = {}
        for entry in self._entries.values():
            categories[entry.category] = categories.get(entry.category, 0) + 1

        return {
            "total_entries": len(self._entries),
            "categories": categories,
            "avg_confidence": (
                sum(e.confidence for e in self._entries.values()) / len(self._entries)
                if self._entries else 0
            ),
        }

    def _save(self) -> None:
        """Save memory to disk."""
        if not self._memory_file:
            return

        Path(self._memory_file).parent.mkdir(parents=True, exist_ok=True)
        data = {key: entry.to_dict() for key, entry in self._entries.items()}
        Path(self._memory_file).write_text(json.dumps(data, indent=2))

    def _load(self) -> None:
        """Load memory from disk."""
        if not self._memory_file or not os.path.exists(self._memory_file):
            return

        try:
            data = json.loads(Path(self._memory_file).read_text())
            self._entries = {key: MemoryEntry.from_dict(d) for key, d in data.items()}
        except Exception:
            pass

    def clear(self) -> None:
        """Clear all memories."""
        self._entries.clear()
        self._save()
