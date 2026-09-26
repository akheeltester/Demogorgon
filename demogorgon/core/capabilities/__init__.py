"""Environment capability subsystem (Phase 4).

    from demogorgon.core.capabilities import (
        CapabilityRegistry, CapabilityStatus, build_environment_registry,
    )
"""

from .environment import build_environment_registry
from .registry import (
    Capability,
    CapabilityDiagnostic,
    CapabilityRegistry,
    CapabilityStatus,
)

__all__ = [
    "Capability",
    "CapabilityDiagnostic",
    "CapabilityRegistry",
    "CapabilityStatus",
    "build_environment_registry",
]
