"""Adaptive Research Engine (ARE) — graph-based hunting.

Modules:
    attack_graph: Live model of the application
    research_memory: Hypothesis tracking, action logging
    mutation_intelligence: Type-aware payload generation
    trust_boundary: Role hierarchy and trust levels
    exploit_confidence: 5-dimensional finding scoring
    chain_finder: Multi-step attack chain discovery
    knowledge_base: Past hunt patterns
    engine: Orchestrator
"""

from demogorgon.are.attack_graph import AttackGraph, Node, Edge, NodeType, EdgeType
from demogorgon.are.research_memory import (
    ResearchMemory, Hypothesis, ResearchAction,
    HypothesisStatus, AttackFamily,
)
from demogorgon.are.mutation_intelligence import MutationIntelligence, TypeDetector
from demogorgon.are.trust_boundary import TrustBoundaryMapper, TrustLevel, TrustBoundary
from demogorgon.are.exploit_confidence import ExploitConfidenceEngine, FindingScore
from demogorgon.are.chain_finder import ChainFinder, Chain, ChainStep
from demogorgon.are.knowledge_base import KnowledgeBase, TechPattern, HuntResult
from demogorgon.are.engine import AdaptiveResearchEngine

__all__ = [
    "AttackGraph", "Node", "Edge", "NodeType", "EdgeType",
    "ResearchMemory", "Hypothesis", "ResearchAction", "HypothesisStatus", "AttackFamily",
    "MutationIntelligence", "TypeDetector",
    "TrustBoundaryMapper", "TrustLevel", "TrustBoundary",
    "ExploitConfidenceEngine", "FindingScore",
    "ChainFinder", "Chain", "ChainStep",
    "KnowledgeBase", "TechPattern", "HuntResult",
    "AdaptiveResearchEngine",
]
