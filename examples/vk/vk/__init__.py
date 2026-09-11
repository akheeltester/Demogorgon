"""
VK Bug Bounty Program Module
=============================
Complete toolkit for hunting bugs in VK's bug bounty program.

Components:
    - scope: VKScope — Target prioritization, scope rules, exclusion filtering
    - report: VKReportGenerator — Submission-ready report generation
    - assistant: VKAssessmentEngine — Finding validation & bounty estimation
    - executors: VKAttackSuite — VK-specific attack pattern executors

Quick Start:
    from demogorgon.programs.vk import VKScope, VKReportGenerator, VKAssessmentEngine

    # Check if a target is in scope
    scope = VKScope()
    print(scope.in_scope("id.vk.com"))  # True
    print(scope.tier("id.vk.com"))      # VKTier.TIER_1_VK_ID

    # Assess a finding before submission
    engine = VKAssessmentEngine()
    result = engine.assess_raw("IDOR", "id.vk.com", endpoint="/api/profile/get")
    print(result.should_submit)        # True/False
    print(result.estimated_bounty)     # "MAX" / "HIGH" / "MEDIUM" / "LOW"

    # Generate a submission-ready report
    gen = VKReportGenerator()
    report = gen.generate(finding)
    gen.save(report, "vk_report.md")
"""

from .scope import VKScope, VKTier, VKVulnCategory, VK_BOUNTY_MATRIX, vk_scope
from .report import VKReportGenerator, VKFinding, VKReport
from .assistant import VKAssessmentEngine, VKAssessmentResult, VKVerdict
from .executors import VKAttackSuite, VKAttackResult

__all__ = [
    "VKScope",
    "VKTier",
    "VKVulnCategory",
    "VK_BOUNTY_MATRIX",
    "vk_scope",
    "VKReportGenerator",
    "VKFinding",
    "VKReport",
    "VKAssessmentEngine",
    "VKAssessmentResult",
    "VKVerdict",
    "VKAttackSuite",
    "VKAttackResult",
]
