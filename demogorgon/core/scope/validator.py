"""Policy Validator — validates a parsed ProgramPolicy before a hunt starts.

Answers three questions the flow must never guess at:

1. Is there anything explicitly authorized to test?  (blocker if not)
2. Which policy facts restrict us?  (out-of-scope, forbidden vulns, restrictions)
3. Which facts must be shown to the operator for confirmation?  (warnings)

Deliberately small (Phase 16): one dataclass, one validator, no plugin logic.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..engagement import ProgramPolicy
from .policy_ast import EXPLICIT_CONFIDENCE


@dataclass
class PolicyValidation:
    """Result of validating a ProgramPolicy."""

    ok: bool = True
    blockers: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    #: asset patterns explicitly authorized (confidence >= EXPLICIT_CONFIDENCE)
    explicit_targets: list[str] = field(default_factory=list)
    #: patterns that need operator confirmation before use
    conditional_targets: list[str] = field(default_factory=list)
    forbidden_vulns: list[str] = field(default_factory=list)
    restrictions: list[str] = field(default_factory=list)

    @property
    def requires_confirmation(self) -> bool:
        """True when conditional assets exist that the operator must review."""
        return bool(self.conditional_targets)

    def to_dict(self) -> dict:
        return {
            "ok": self.ok,
            "blockers": list(self.blockers),
            "warnings": list(self.warnings),
            "explicit_targets": list(self.explicit_targets),
            "conditional_targets": list(self.conditional_targets),
            "forbidden_vulns": list(self.forbidden_vulns),
            "restrictions": list(self.restrictions),
        }


class PolicyValidator:
    """Validates a parsed ProgramPolicy for hunt readiness."""

    def validate(self, policy: ProgramPolicy | None) -> PolicyValidation:
        result = PolicyValidation()

        if policy is None:
            result.ok = False
            result.blockers.append("No program policy was provided.")
            return result

        # ── explicitly authorized targets ────────────────────────────
        for asset in policy.in_scope:
            if asset.confidence >= EXPLICIT_CONFIDENCE:
                result.explicit_targets.append(asset.pattern)
            else:
                result.conditional_targets.append(asset.pattern)

        for rule in getattr(policy, "scope_rules", []) or []:
            if rule.confidence < EXPLICIT_CONFIDENCE and rule.canonical_pattern:
                if rule.canonical_pattern not in result.conditional_targets:
                    result.conditional_targets.append(rule.canonical_pattern)

        if not policy.in_scope and not result.conditional_targets:
            result.ok = False
            result.blockers.append(
                "No in-scope assets found — nothing is authorized to test. "
                "Provide a program document with an 'In scope' section, "
                "or add explicit scope patterns."
            )

        # ── facts the operator must see ──────────────────────────────
        result.forbidden_vulns = list(policy.forbidden_vulnerabilities)
        if result.forbidden_vulns:
            result.warnings.append(
                "Vulnerability classes excluded by policy: "
                + ", ".join(result.forbidden_vulns)
            )

        if not policy.account_creation_allowed:
            result.warnings.append("Account creation is NOT allowed by this program.")

        for restriction in policy.restrictions:
            result.restrictions.append(
                f"{restriction.category}: {restriction.description}"
            )
        if result.restrictions:
            result.warnings.append(
                f"{len(result.restrictions)} testing restriction(s) apply "
                "(see policy.restrictions)."
            )

        if getattr(policy, "target_only", False):
            result.warnings.append(
                "Target-only mode: no program document was parsed — scope "
                "falls back to the target you provided."
            )

        if result.conditional_targets:
            result.warnings.append(
                f"{len(result.conditional_targets)} asset(s) are only "
                "conditionally in scope and need confirmation."
            )

        # a policy with blockers is never ok
        if result.blockers:
            result.ok = False
        return result
