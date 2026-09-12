"""Agent module — interactive autonomous security research agent.

Transforms DEMOGORGON from a CLI pipeline into a Claude Code/Codex-style
terminal agent with LLM in adaptive feedback loop.

Usage:
    python -m demogorgon agent           # Interactive agent session
    python -m demogorgon agent <target>  # Direct agent launch
"""

from .session import AgentSession, SessionConfig, SessionStatus
from .events import EventBus, AgentEvent, EventType
from .tokens import TokenTracker
from .budget import BudgetController, BudgetLimits
from .trace import ResearchTrace, TraceEntryType
from .strategies import StrategyEngine, AgentStrategy
from .commands import CommandProcessor
from .capabilities import CapabilityRegistry
from .natural_language import NaturalLanguageParser, InstructionProcessor, ParsedInstruction
from .memory import ResearchMemory
from .live_display import LiveDisplay
from .mcp import MCPClient, MCPManager, MCPServerConfig

__all__ = [
    # Session
    "AgentSession",
    "SessionConfig",
    "SessionStatus",
    # Events
    "EventBus",
    "AgentEvent",
    "EventType",
    # Tracking
    "TokenTracker",
    "BudgetController",
    "BudgetLimits",
    # Trace
    "ResearchTrace",
    "TraceEntryType",
    # Strategy
    "StrategyEngine",
    "AgentStrategy",
    # Commands
    "CommandProcessor",
    # Capabilities
    "CapabilityRegistry",
    # Natural Language
    "NaturalLanguageParser",
    "InstructionProcessor",
    "ParsedInstruction",
    # Memory
    "ResearchMemory",
    # Display
    "LiveDisplay",
    # MCP
    "MCPClient",
    "MCPManager",
    "MCPServerConfig",
]
