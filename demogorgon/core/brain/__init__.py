"""Research Brain — LLM-powered reasoning engine for autonomous bug bounty.

Components:
- LLMReasoner: Proposes next actions based on context
- ExperimentPlanner: Creates safe experiment plans
- Validator: Validates findings with LLM reasoning
- ResearchBrain: Orchestrates the observation → hypothesis → experiment cycle
"""

from .reasoner import LLMReasoner
from .planner import LLMExperimentPlanner
from .validator import LLMValidator
from .research_brain import ResearchBrain

__all__ = [
    "LLMReasoner",
    "LLMExperimentPlanner",
    "LLMValidator",
    "ResearchBrain",
]
