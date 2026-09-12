"""Natural Language Interface — user instructions → agent context.

Parses free-form user input and converts it to structured agent context.
Handles instructions like "focus on XSS", "scan for IDOR", "skip subdomains",
"check for SQLi on /api/users", etc.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class InstructionType(Enum):
    """Types of user instructions."""
    FOCUS = "focus"                  # Focus on specific area
    DIRECT = "direct"                # Direct action command
    CONSTRAINT = "constraint"        # Add a constraint
    QUERY = "query"                  # Ask about state
    OVERRIDE = "override"            # Override safety/behavior
    HINT = "hint"                    # Provide a hint to the brain
    IGNORE = "ignore"                # Ignore something
    PRIORITY = "priority"            # Change priority


@dataclass
class ParsedInstruction:
    """A parsed user instruction."""
    type: InstructionType
    raw_text: str
    vuln_class: str = ""
    target: str = ""
    endpoint: str = ""
    parameter: str = ""
    tool: str = ""
    constraint: str = ""
    priority: float = 0.5
    confidence: float = 0.5
    data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "type": self.type.value,
            "raw_text": self.raw_text,
            "vuln_class": self.vuln_class,
            "target": self.target,
            "endpoint": self.endpoint,
            "parameter": self.parameter,
            "tool": self.tool,
            "constraint": self.constraint,
            "priority": self.priority,
            "confidence": self.confidence,
            "data": self.data,
        }


# Vulnerability class patterns
VULN_CLASS_PATTERNS: dict[str, list[str]] = {
    "xss": ["xss", "cross-site scripting", "cross site", "reflected", "stored xss", "dom xss"],
    "sqli": ["sqli", "sql injection", "sql inj", "sql insert", "blind sqli", "union based"],
    "ssrf": ["ssrf", "server-side request forgery", "server side request"],
    "idor": ["idor", "insecure direct object", "object reference", "authorization bypass"],
    "csrf": ["csrf", "cross-site request forgery", "cross site request"],
    "open_redirect": ["open redirect", "redirect", "url redirect", "forward"],
    "ssti": ["ssti", "server-side template injection", "template injection", "template inj"],
    "xxe": ["xxe", "xml external entity", "xml injection"],
    "auth_bypass": ["auth bypass", "authentication bypass", "bypass auth", "login bypass"],
    "file_upload": ["file upload", "upload", "unrestricted upload"],
    "info_disclosure": ["info disclosure", "information disclosure", "data leak", "leak"],
    "race_condition": ["race condition", "race", "concurrent"],
    "mass_assignment": ["mass assignment", "parameter pollution"],
    "business_logic": ["business logic", "logic flaw", "logic bug"],
    "lfi": ["lfi", "local file inclusion", "file inclusion"],
    "rfi": ["rfi", "remote file inclusion"],
    "cmd_injection": ["command injection", "cmd injection", "rce", "remote code execution"],
    "nosql": ["nosql injection", "nosql", "mongodb injection"],
}

# Action patterns
ACTION_PATTERNS: dict[str, list[str]] = {
    "scan": ["scan", "scan for", "check for", "test for", "look for"],
    "test": ["test", "try", "attempt", "probe"],
    "exploit": ["exploit", "take advantage", "leverage"],
    "validate": ["validate", "confirm", "verify", "double check"],
    "ignore": ["ignore", "skip", "don't", "don't test", "exclude"],
    "focus": ["focus on", "concentrate on", "prioritize", "focus"],
    "stop": ["stop", "halt", "pause", "enough"],
    "report": ["report", "generate report", "show findings"],
}

# Constraint patterns
CONSTRAINT_PATTERNS: dict[str, list[str]] = {
    "rate_limit": ["slow down", "rate limit", "don't flood", "be careful"],
    "no_active": ["passive only", "no active", "don't exploit", "observation only"],
    "scope_only": ["in scope only", "stay in scope", "don't go out of scope"],
    "auth_only": ["with auth", "using credentials", "authenticated"],
}


class NaturalLanguageParser:
    """Parses natural language user instructions.

    Usage:
        parser = NaturalLanguageParser()
        instruction = parser.parse("focus on XSS in /search endpoint")
        # ParsedInstruction(type=FOCUS, vuln_class="xss", endpoint="/search")
    """

    def parse(self, text: str) -> ParsedInstruction:
        """Parse a natural language instruction."""
        text = text.strip()
        if not text:
            return ParsedInstruction(
                type=InstructionType.QUERY,
                raw_text=text,
                confidence=0.0,
            )

        lower = text.lower()

        # Detect instruction type
        inst_type = self._detect_type(lower)

        # Extract vuln class
        vuln_class = self._extract_vuln_class(lower)

        # Extract endpoint/URL
        endpoint = self._extract_endpoint(text)

        # Extract parameter
        parameter = self._extract_parameter(lower)

        # Extract tool preference
        tool = self._extract_tool(lower)

        # Extract constraint
        constraint = self._extract_constraint(lower)

        # Compute confidence
        confidence = self._compute_confidence(text, inst_type, vuln_class)

        return ParsedInstruction(
            type=inst_type,
            raw_text=text,
            vuln_class=vuln_class,
            endpoint=endpoint,
            parameter=parameter,
            tool=tool,
            constraint=constraint,
            confidence=confidence,
        )

    def _detect_type(self, text: str) -> InstructionType:
        """Detect the type of instruction."""
        # Check for queries
        if any(text.startswith(q) for q in ["what", "how", "show", "list", "status", "findings"]):
            return InstructionType.QUERY

        # Check for stop/pause
        if any(p in text for p in ACTION_PATTERNS["stop"]):
            return InstructionType.DIRECT

        # Check for report
        if any(p in text for p in ACTION_PATTERNS["report"]):
            return InstructionType.DIRECT

        # Check for focus
        if any(p in text for p in ACTION_PATTERNS["focus"]):
            return InstructionType.FOCUS

        # Check for ignore/skip
        if any(p in text for p in ACTION_PATTERNS["ignore"]):
            return InstructionType.IGNORE

        # Check for constraints
        for cap_patterns in CONSTRAINT_PATTERNS.values():
            if any(p in text for p in cap_patterns):
                return InstructionType.CONSTRAINT

        # Check for scan/test
        if any(p in text for p in ACTION_PATTERNS["scan"] + ACTION_PATTERNS["test"]):
            return InstructionType.DIRECT

        # Default to hint
        return InstructionType.HINT

    def _extract_vuln_class(self, text: str) -> str:
        """Extract vulnerability class from text."""
        for vuln_class, patterns in VULN_CLASS_PATTERNS.items():
            for pattern in patterns:
                if pattern in text:
                    return vuln_class
        return ""

    def _extract_endpoint(self, text: str) -> str:
        """Extract endpoint/URL from text."""
        # Match /path patterns
        match = re.search(r'(/[\w/\-_?=&{}%.]+)', text)
        if match:
            return match.group(1)

        # Match full URLs
        match = re.search(r'(https?://[^\s]+)', text)
        if match:
            return match.group(1)

        return ""

    def _extract_parameter(self, text: str) -> str:
        """Extract parameter name from text."""
        # Match param=X patterns
        match = re.search(r'(?:param|parameter|field|input)[=:]\s*(\w+)', text)
        if match:
            return match.group(1)

        # Match "in <param>" patterns
        match = re.search(r'\bin\s+(\w+)\b', text)
        if match and match.group(1) not in ("scope", "total", "general", "case", "fact"):
            return match.group(1)

        return ""

    def _extract_tool(self, text: str) -> str:
        """Extract tool preference from text."""
        tool_names = [
            "subfinder", "httpx", "nuclei", "ffuf", "katana", "nmap",
            "amass", "dnsx", "naabu", "gau", "sqlmap", "burp",
        ]
        for tool in tool_names:
            if tool in text:
                return tool
        return ""

    def _extract_constraint(self, text: str) -> str:
        """Extract constraint from text."""
        for constraint_type, patterns in CONSTRAINT_PATTERNS.items():
            for pattern in patterns:
                if pattern in text:
                    return constraint_type
        return ""

    def _compute_confidence(self, text: str, inst_type: InstructionType, vuln_class: str) -> float:
        """Compute confidence in the parsed instruction."""
        confidence = 0.5

        # Longer, more specific = higher confidence
        if len(text.split()) > 5:
            confidence += 0.1

        # Has vuln class = higher confidence
        if vuln_class:
            confidence += 0.2

        # Has endpoint = higher confidence
        if self._extract_endpoint(text):
            confidence += 0.1

        # Query type = lower confidence (needs more context)
        if inst_type == InstructionType.QUERY:
            confidence -= 0.1

        return min(max(confidence, 0.0), 1.0)


class InstructionProcessor:
    """Processes parsed instructions into agent context updates.

    Usage:
        processor = InstructionProcessor()
        context_update = processor.process(instruction)
        # Returns dict with focus_vuln_class, constraints, hints, etc.
    """

    def process(self, instruction: ParsedInstruction) -> dict[str, Any]:
        """Process a parsed instruction into agent context updates."""
        update: dict[str, Any] = {
            "instruction_type": instruction.type.value,
            "raw_text": instruction.raw_text,
        }

        if instruction.type == InstructionType.FOCUS:
            update["focus_vuln_class"] = instruction.vuln_class
            update["focus_endpoint"] = instruction.endpoint
            update["priority_boost"] = 0.3

        elif instruction.type == InstructionType.IGNORE:
            update["ignore_vuln_class"] = instruction.vuln_class
            update["ignore_endpoint"] = instruction.endpoint

        elif instruction.type == InstructionType.CONSTRAINT:
            update["constraint"] = instruction.constraint
            if instruction.constraint == "rate_limit":
                update["rate_limit_multiplier"] = 0.5
            elif instruction.constraint == "no_active":
                update["passive_only"] = True
            elif instruction.constraint == "scope_only":
                update["strict_scope"] = True

        elif instruction.type == InstructionType.DIRECT:
            update["direct_action"] = True
            if instruction.tool:
                update["prefer_tool"] = instruction.tool

        elif instruction.type == InstructionType.HINT:
            update["hint"] = instruction.raw_text
            update["hint_vuln_class"] = instruction.vuln_class

        elif instruction.type == InstructionType.QUERY:
            update["query"] = instruction.raw_text

        elif instruction.type == InstructionType.PRIORITY:
            update["priority"] = instruction.priority

        # Always include raw instruction for LLM context
        update["user_instruction"] = instruction.raw_text

        return update
