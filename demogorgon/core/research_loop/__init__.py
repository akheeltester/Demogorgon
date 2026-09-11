"""Research Loop — autonomous research orchestration.

Components:
- ResearchCase: Persistent reasoning trail (case.py)
- ExperimentExecutor: Runs experiment plans via tools
- EvidenceCollector: Captures and manages evidence
- ResearchLoop: Main orchestrator connecting brain, tools, and evidence
"""

from .case import (
    ResearchCase,
    CaseStatus,
    CaseObservation,
    CaseHypothesis,
    CaseExperiment,
    CaseFinding,
    NextBestAction,
    HypothesisStatus,
)
from .executor import PlanExecutor
from .evidence import EvidenceCollector
from .loop import ResearchLoop

__all__ = [
    "ResearchCase",
    "CaseStatus",
    "CaseObservation",
    "CaseHypothesis",
    "CaseExperiment",
    "CaseFinding",
    "NextBestAction",
    "HypothesisStatus",
    "PlanExecutor",
    "EvidenceCollector",
    "ResearchLoop",
]
