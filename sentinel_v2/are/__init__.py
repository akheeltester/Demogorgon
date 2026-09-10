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

from sentinel_v2.are.attack_graph import AttackGraph, Node, Edge, NodeType, EdgeType
from sentinel_v2.are.research_memory import (
    ResearchMemory, Hypothesis, ResearchAction,
    HypothesisStatus, AttackFamily,
)
from sentinel_v2.are.mutation_intelligence import MutationIntelligence, TypeDetector
from sentinel_v2.are.trust_boundary import TrustBoundaryMapper, TrustLevel, TrustBoundary
from sentinel_v2.are.exploit_confidence import ExploitConfidenceEngine, FindingScore
from sentinel_v2.are.chain_finder import ChainFinder, Chain, ChainStep
from sentinel_v2.are.knowledge_base import KnowledgeBase, TechPattern, HuntResult
from sentinel_v2.are.engine import AdaptiveResearchEngine

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
