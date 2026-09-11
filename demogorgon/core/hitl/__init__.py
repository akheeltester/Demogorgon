"""HITL — Human-in-the-loop for autonomous research.

Components:
- HITLGate: Decision gate that can require human approval
- ApprovalRequest: Request for human approval with context
- PauseController: Manages pause/resume state
"""

from .gate import HITLGate, ApprovalLevel
from .request import ApprovalRequest, RequestStatus, RequestPriority
from .controller import PauseController, PauseReason

__all__ = [
    "HITLGate",
    "ApprovalLevel",
    "ApprovalRequest",
    "RequestStatus",
    "RequestPriority",
    "PauseController",
    "PauseReason",
]
