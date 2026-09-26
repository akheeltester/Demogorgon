"""Section-aware program policy parser (Phase 2).

Replaces naive whole-text domain scraping with a structural parse:

- The policy is split into labelled sections (In scope, Out of scope,
  Submission types, Program rules, Safe harbor, Known issues, …).
- Assets are only created from explicit scope sections or explicit inline
  ``In scope: …`` / ``Out of scope: …`` labels — never from prose.
- Every asset carries provenance: source_section, source_text, confidence.
- Excluded vulnerability classes are recorded as forbidden, never allowed.
- Low-confidence assets (< EXPLICIT_CONFIDENCE) land in scope_rules with
  inclusion_state=CONDITIONALLY_IN_SCOPE and are NOT added to the legacy
  ``in_scope`` list, so they can never silently authorize targets.
- The raw policy text is preserved verbatim in ProgramPolicy.raw_policy.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable

from ..engagement import ProgramPolicy, ScopeAsset, TestingRestriction
from .policy_ast import (
    EXPLICIT_CONFIDENCE,
    AccountConstraint,
    AllowedVulnerability,
    EvidenceRequirement,
    ExclusionRule,
    ForbiddenVulnerability,
    InclusionState,
    KnownIssue,
    PolicyMetadata,
    RequiredHeader,
    SafeHarbor,
    ScopeRule,
    TestingConstraint,
)

# ─── Platform / program name (moved here to avoid import cycles) ─────────

PLATFORM_PATTERNS = {
    "hackerone": [r"hackerone\.com", r"hackerone", r"program\s+page"],
    "bugcrowd": [r"bugcrowd\.com", r"bugcrowd", r"crowdstream"],
    "intigriti": [r"intigriti\.com", r"intigriti"],
    "yeswehack": [r"yeswehack\.com", r"yeswehack"],
    "immunefi": [r"immunefi\.com", r"immunefi"],
    "manual": [r"^manual$", r"platform:\s*manual"],
}


def detect_platform(text: str) -> str:
    """Detect the bug bounty platform from the program text."""
    text_lower = text.lower()
    for platform, patterns in PLATFORM_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, text_lower, re.MULTILINE):
                return platform
    return "custom"


def extract_program_name(text: str) -> str:
    """Extract the program/organization name from the policy text."""
    for line in text.strip().split("\n")[:5]:
        line = line.strip()
        if 2 < len(line) < 100 and not line.startswith(("http", "#", "=", "-", "*")):
            return line
    return "Unknown Program"


# ─── Section splitting ───────────────────────────────────────────────────

@dataclass
class _Section:
    kind: str          # in_scope | out_of_scope | vuln_allowed | vuln_excluded |
                       # rules | safe_harbor | known_issues | account | evidence | other
    heading: str
    lines: list[str] = field(default_factory=list)


_HEADING_RULES: list[tuple[str, tuple[str, ...]]] = [
    # (kind, keyword substrings) — first match wins, so order matters
    ("out_of_scope", (
        "out of scope", "out-of-scope", "outofscope", "excluded",
        "exclusion", "not eligible", "not accepted", "not in scope",
        "out of programme", "out-of-programme",
    )),
    ("in_scope", (
        "in scope", "in-scope", "inscope", "targets", "target list",
        "assets", "scope",
    )),
    ("vuln_excluded", (
        "excluded submission", "not eligible submission", "excluded vulnerab",
        "disallowed", "ineligible",
    )),
    ("vuln_allowed", (
        "submission type", "eligible submission", "accepted vulnerab",
        "vulnerability type", "in scope submission", "eligible",
        "accepted findings",
    )),
    ("known_issues", (
        "known issue", "known issues", "previously reported", "accepted risk",
        "not eligible (known",
    )),
    ("safe_harbor", ("safe harbor", "safe-harbor", "safe harbour")),
    ("account", ("account", "credential", "login")),
    ("evidence", ("evidence", "proof of concept", "reporting requirement",
                  "report requirement")),
    ("rules", (
        "program rule", "program rules", "rule", "guideline", "guidelines",
        "restriction", "restrictions", "testing", "policy", "terms",
        "code of conduct", "disclosure",
    )),
]

_MD_HEADING = re.compile(r"^\s*#{1,6}\s+(?P<title>.+?)\s*#*\s*$")
_LABEL_LINE = re.compile(r"^\s*(?P<title>[A-Za-z][A-Za-z0-9 /&_-]{0,60}?)\s*:\s*\S")
_INLINE_SCOPE = re.compile(
    r"^\s*(?P<label>in[\s-]?scope|out[\s-]?of[\s-]?scope)\s*[:\-]\s*(?P<rest>.+)$",
    re.IGNORECASE,
)
_LIST_ITEM = re.compile(r"^\s*(?:[-*+]|\d+[.)])\s+(?P<body>.+)$")
_MD_LINK = re.compile(r"\[([^\]]*)\]\((https?://[^)\s]+)\)")
_TABLE_SEP = re.compile(r"^\s*\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)*\|?\s*$")


def _classify_heading(title: str) -> str:
    norm = re.sub(r"[\s_]+", " ", title.strip().lower())
    norm = norm.rstrip(":").strip()
    for kind, keywords in _HEADING_RULES:
        for kw in keywords:
            if kw in norm:
                return kind
    return "other"


def _is_heading(line: str) -> str | None:
    """Return the heading title if this line starts a new section."""
    stripped = line.strip()
    if not stripped:
        return None
    m = _MD_HEADING.match(stripped)
    if m:
        return m.group("title")
    # ALL-CAPS short line: "OUT OF SCOPE", "SUBMISSION TYPES"
    if (
        0 < len(stripped) <= 60
        and stripped == stripped.upper()
        and any(c.isalpha() for c in stripped)
        and not stripped.endswith((".", ";", ","))
        and "|" not in stripped
        and not stripped.startswith(("-", "=", "*"))
    ):
        return stripped
    # Short label line ending with ':' : "In scope:", "Program rules:"
    if (
        0 < len(stripped) <= 60
        and stripped.endswith(":")
        and not stripped.startswith(("|", "-", "*"))
        and "://" not in stripped
    ):
        title = stripped[:-1].strip()
        if title and re.fullmatch(r"[A-Za-z][A-Za-z0-9 /&_-]*", title):
            return title
    return None


def _split_sections(text: str) -> list[_Section]:
    sections: list[_Section] = []
    current = _Section(kind="other", heading="(preamble)")
    for line in text.splitlines():
        title = _is_heading(line)
        if title is not None:
            sections.append(current)
            current = _Section(kind=_classify_heading(title), heading=title)
            # Inline label with content: "In scope: *.example.com, api.x.com"
            m = _INLINE_SCOPE.match(line)
            if m:
                rest = m.group("rest").strip()
                if rest:
                    current.lines.append(rest)
            continue
        current.lines.append(line)
    sections.append(current)
    return sections


# ─── Asset extraction ────────────────────────────────────────────────────

_URL_RE = re.compile(r"^https?://[^\s]+$", re.IGNORECASE)
_WILDCARD_RE = re.compile(r"^\*\.(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")
_IP_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?$")
_DOMAIN_RE = re.compile(
    r"^(?:\*\.)?(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)
_MOBILE_RE = re.compile(r"^(?:com|org|net|io|app|co|me|tv)\.(?:[a-z][a-z0-9_]*\.)+[a-z][a-z0-9_]*$")
_FALSE_POSITIVES = {
    "example.com", "localhost", "127.0.0.1", "0.0.0.0",
    "your.domain.com", "target.com", "company.com",
    "email.com", "http.com", "https.com",
}


def _classify_asset(token: str) -> tuple[str, str] | None:
    """Return (pattern, asset_type) if token is an explicit asset, else None."""
    token = token.strip().rstrip(".,;:)").strip()
    if not token or token.lower() in _FALSE_POSITIVES:
        return None
    if _URL_RE.match(token):
        return token.rstrip("/"), "url"
    if _WILDCARD_RE.match(token):
        return token.lower(), "subdomain"
    if _IP_RE.match(token):
        return token, "ip_range"
    if _DOMAIN_RE.match(token):
        lowered = token.lower().rstrip(".")
        if _MOBILE_RE.match(lowered):
            return lowered, "mobile_app"
        return lowered, "domain"
    return None


def _candidates_from_line(line: str) -> list[tuple[str, str]]:
    """Yield (token, description) asset candidates from one line of a scope section.

    Only structural rows count: markdown table cells, list items, or lines whose
    leading token is itself an asset. Prose sentences yield nothing.
    """
    out: list[tuple[str, str]] = []
    if "|" in line:
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        cells = [c for c in cells if c]
        if not cells or _TABLE_SEP.match(line):
            return out
        first = _MD_LINK.sub(r"\1", cells[0])
        token = first.split()[0] if first.split() else ""
        token = token.strip("`'\"")
        if token.startswith("**") and token.endswith("**") and len(token) > 4:
            token = token[2:-2]
        classified = _classify_asset(token)
        if classified:
            desc = cells[1] if len(cells) > 1 else ""
            out.append((token, _MD_LINK.sub(r"\1", desc)))
        return out

    m = _LIST_ITEM.match(line)
    body = m.group("body") if m else line.strip()
    body = _MD_LINK.sub(lambda mm: mm.group(1) or mm.group(2), body)

    if not m:
        # Plain line: only treat as a multi-asset list when every fragment
        # after a comma/"and" split is itself an asset ("a.x and b.y").
        frags = [f for f in re.split(r",|\band\b", body, flags=re.IGNORECASE) if f.strip()]
        if len(frags) > 1:
            for frag in frags:
                parts = frag.split(None, 1)
                token = parts[0].strip("`'\"")
                if _classify_asset(token):
                    out.append((token, parts[1].strip() if len(parts) > 1 else ""))
            if out:
                return out

    parts = body.split(None, 1)
    if not parts:
        return out
    token = parts[0].strip("`'\"")
    if token.startswith("**") and token.endswith("**") and len(token) > 4:
        token = token[2:-2]
    classified = _classify_asset(token)
    if classified:
        desc = parts[1] if len(parts) > 1 else ""
        # Structural rows only: bare asset, or asset followed by a separator.
        if m or len(parts) == 1 or desc[:1] in ("-", "—", "|", "("):
            out.append((token, desc.strip()))
    return out


def _inline_label_candidates(rest: str) -> list[tuple[str, str]]:
    """Parse the tail of an ``In scope: a, b and c`` label line."""
    out: list[tuple[str, str]] = []
    for frag in re.split(r",|\band\b|&|\n", rest, flags=re.IGNORECASE):
        frag = frag.strip()
        if not frag:
            continue
        parts = frag.split(None, 1)
        token = parts[0].strip("`'\"")
        if _classify_asset(token):
            out.append((token, parts[1] if len(parts) > 1 else ""))
    return out


def _make_asset(
    token: str,
    description: str,
    section_kind: str,
    source_text: str,
    confidence: float,
) -> ScopeAsset:
    classified = _classify_asset(token) or (token, "domain")
    pattern, asset_type = classified
    inclusion = section_kind == "in_scope"
    return ScopeAsset(
        pattern=pattern,
        asset_type=asset_type,
        description=description,
        in_scope=inclusion,
        source="program_policy",
        canonical_pattern=pattern,
        source_section=section_kind,
        source_text=source_text.strip()[:300],
        inclusion_state=(
            InclusionState.IN_SCOPE.value if inclusion
            else InclusionState.OUT_OF_SCOPE.value
        ),
        confidence=confidence,
    )


# ─── Vulnerability class extraction ──────────────────────────────────────

VULN_CLASS_KEYWORDS = {
    "xss": ["xss", "cross-site scripting", "reflected xss", "stored xss"],
    "sqli": ["sql injection", "sqli", "sql inject"],
    "ssrf": ["ssrf", "server-side request forgery"],
    "csrf": ["csrf", "cross-site request forgery"],
    "idor": ["idor", "insecure direct object reference", "broken access control"],
    "auth_bypass": ["authentication bypass", "auth bypass", "login bypass"],
    "privesc": ["privilege escalation", "privesc", "elevation of privilege"],
    "race_condition": ["race condition"],
    "file_upload": ["file upload", "unrestricted upload", "webshell"],
    "ssti": ["ssti", "server-side template injection"],
    "xxe": ["xxe", "xml external entity"],
    "open_redirect": ["open redirect", "url redirect", "forward redirect"],
    "information_disclosure": ["information disclosure", "information leak", "data exposure"],
    "business_logic": ["business logic", "logic flaw", "workflow bypass"],
    "jwt": ["jwt", "json web token"],
    "cors": ["cors", "cross-origin resource sharing"],
    "dos": ["denial of service", "dos", "ddos"],
    "clickjacking": ["clickjacking", "ui redressing"],
    "subdomain_takeover": ["subdomain takeover", "subdomain hijack"],
    "auth_bypass_session": ["session fixation", "session hijacking"],
}

_NEGATION_RE = re.compile(
    r"(?:\bno\s+|\bnot\s+(?:allowed|accepted|eligible|supported)\b|"
    r"\bprohibited\b|\bexcluded?\b|\bdo\s+not\s+test\b|\bout\s+of\s+scope\b|"
    r"\bforbidden\b|\bdisallowed\b|\bnot\s+permitted\b|\bnot\s+tested\b)",
    re.IGNORECASE,
)
_POSITIVE_RE = re.compile(
    r"(?:\baccepts?\b|\baccepted\b|\bis\s+in\s+scope\b|\bin\s+scope\b|"
    r"\beligible\b|\brewarded\b|\bwe\s+welcome\b|\bvalid\b|"
    # "X is allowed" / "we allow X" — the most common in-scope phrasing
    r"\ballowed\b|\bare\s+allowed\b|\bmay\s+test\b|\bwelcome\s+to\s+test\b)",
    re.IGNORECASE,
)


def _vulns_in_text(text: str) -> list[tuple[str, str]]:
    """Return (vuln_class, matched_keyword) pairs present in text."""
    lower = text.lower()
    found: list[tuple[str, str]] = []
    for vuln_class, keywords in VULN_CLASS_KEYWORDS.items():
        for kw in keywords:
            if re.search(rf"(?<![a-z0-9]){re.escape(kw)}(?![a-z0-9])", lower):
                found.append((vuln_class, kw))
                break
    return found


# ─── Restrictions / rules extraction ─────────────────────────────────────

RESTRICTION_PATTERNS = {
    "dos": [r"no\s+dos", r"denial[\s-]of[\s-]service", r"do\s+not\s+dos",
            r"dos\s+prohibited", r"avoid\s+dos"],
    "social_engineering": [r"no\s+social\s+engineering", r"social\s+engineering\s+prohibited",
                           r"do\s+not\s+perform\s+social\s+engineering"],
    "automated_scanning": [r"no\s+automated\s+scanning", r"automated\s+scanning\s+prohibited",
                           r"do\s+not\s+use\s+automated", r"manual\s+testing\s+only",
                           r"no\s+automated\s+tools"],
    "physical": [r"no\s+physical\s+testing", r"physical\s+access\s+prohibited"],
    "spam": [r"no\s+spam", r"spamming\s+prohibited"],
    "rate_limit": [r"rate\s+limit[:\s]+(\d+)", r"maximum\s+(\d+)\s+requests",
                   r"do\s+not\s+exceed\s+(\d+)"],
}


def _extract_restrictions(
    sections: Iterable[_Section], full_text: str
) -> list[TestingRestriction]:
    restrictions: list[TestingRestriction] = []
    seen: set[str] = set()
    for section in sections:
        text = "\n".join(section.lines)
        if not text.strip():
            continue
        lower = text.lower()
        for category, patterns in RESTRICTION_PATTERNS.items():
            if category in seen:
                continue
            for pattern in patterns:
                match = re.search(pattern, lower)
                if match:
                    seen.add(category)
                    rate_limit = None
                    if category == "rate_limit" and match.lastindex:
                        try:
                            rate_limit = float(match.group(1))
                        except (ValueError, IndexError):
                            pass
                    restrictions.append(TestingRestriction(
                        category=category,
                        allowed=False,
                        description=match.group(0),
                        rate_limit=rate_limit,
                        source_section=section.heading,
                    ))
                    break
    # Fallback: whole-text scan (keeps legacy behaviour for unlabelled policies)
    if not restrictions:
        lower = full_text.lower()
        for category, patterns in RESTRICTION_PATTERNS.items():
            for pattern in patterns:
                match = re.search(pattern, lower)
                if match:
                    rate_limit = None
                    if category == "rate_limit" and match.lastindex:
                        try:
                            rate_limit = float(match.group(1))
                        except (ValueError, IndexError):
                            pass
                    restrictions.append(TestingRestriction(
                        category=category, allowed=False,
                        description=match.group(0), rate_limit=rate_limit,
                        source_section="(whole document)",
                    ))
                    break
    return restrictions


# ─── Main parser ─────────────────────────────────────────────────────────

_HEADER_RE = re.compile(
    r"\b([A-Z][A-Za-z0-9]*(?:-[A-Za-z0-9]+)+)\s*header\b|\bheader\s*[\"']?"
    r"(X-[A-Za-z0-9-]+)[\"']?",
    re.IGNORECASE,
)


def parse_policy(text: str) -> ProgramPolicy:
    """Parse raw program policy text into a section-aware ProgramPolicy."""
    platform = detect_platform(text)
    program_name = extract_program_name(text)
    sections = _split_sections(text)

    in_scope: list[ScopeAsset] = []
    out_of_scope: list[ScopeAsset] = []
    scope_rules: list[ScopeRule] = []
    exclusion_rules: list[ExclusionRule] = []
    allowed_rules: list[AllowedVulnerability] = []
    forbidden_rules: list[ForbiddenVulnerability] = []
    known_issues: list[KnownIssue] = []
    evidence_reqs: list[EvidenceRequirement] = []
    required_headers: list[RequiredHeader] = []
    testing_constraints: list[TestingConstraint] = []
    warnings: list[str] = []
    low_confidence: list[str] = []
    detected: list[str] = []
    seen_patterns: set[str] = set()

    saw_scope_section = False

    for section in sections:
        kind = section.kind
        if kind in ("in_scope", "out_of_scope"):
            saw_scope_section = True
            detected.append(section.heading)
        elif kind != "other":
            detected.append(section.heading)

        # ── assets from structural rows in explicit scope sections ──
        if kind in ("in_scope", "out_of_scope"):
            confidence = 0.95 if kind == "in_scope" else 0.95
            for line in section.lines:
                for token, desc in _candidates_from_line(line):
                    classified = _classify_asset(token)
                    if not classified:
                        continue
                    pattern = classified[0]
                    if pattern in seen_patterns:
                        continue
                    seen_patterns.add(pattern)
                    asset = _make_asset(token, desc, kind, line, confidence)
                    if kind == "in_scope":
                        in_scope.append(asset)
                    else:
                        out_of_scope.append(asset)
                    rule = ScopeRule(
                        canonical_pattern=asset.canonical_pattern,
                        asset_type=asset.asset_type,
                        source_section=kind,
                        source_text=line.strip()[:300],
                        inclusion_state=(
                            InclusionState.IN_SCOPE if kind == "in_scope"
                            else InclusionState.OUT_OF_SCOPE
                        ),
                        confidence=confidence,
                        description=desc,
                    )
                    scope_rules.append(rule)
                    if kind == "out_of_scope":
                        exclusion_rules.append(ExclusionRule(
                            canonical_pattern=asset.canonical_pattern,
                            source_section=kind,
                            source_text=line.strip()[:300],
                            reason=desc or f"Listed under {section.heading}",
                        ))

        # ── vulnerability classes per section ──
        body = "\n".join(section.lines)
        if body.strip() and kind in (
            "in_scope", "out_of_scope", "vuln_allowed", "vuln_excluded", "rules"
        ):
            for vuln_class, kw in _vulns_in_text(body):
                # negation in the same line beats section kind
                line_neg = any(
                    _NEGATION_RE.search(ln) and kw in ln.lower()
                    for ln in section.lines
                )
                line_pos = any(
                    _POSITIVE_RE.search(ln) and kw in ln.lower()
                    for ln in section.lines
                )
                if kind in ("out_of_scope", "vuln_excluded") and not line_pos:
                    target_forbidden = forbidden_rules
                    if not any(f.name == vuln_class for f in target_forbidden):
                        target_forbidden.append(ForbiddenVulnerability(
                            name=vuln_class, source_section=section.heading,
                            reason=f"Mentioned under {section.heading}",
                        ))
                    allowed_rules = [
                        a for a in allowed_rules if a.name != vuln_class
                    ]
                elif line_neg:
                    if not any(f.name == vuln_class for f in forbidden_rules):
                        forbidden_rules.append(ForbiddenVulnerability(
                            name=vuln_class, source_section=section.heading,
                            reason="Explicitly negated in policy text",
                        ))
                elif kind in ("in_scope", "vuln_allowed") or line_pos:
                    if not any(a.name == vuln_class for a in allowed_rules):
                        allowed_rules.append(AllowedVulnerability(
                            name=vuln_class, source_section=section.heading,
                            source_text=kw,
                        ))

        # ── rules / evidence / headers / known issues ──
        if kind in ("rules", "evidence", "other") and body.strip():
            for line in section.lines:
                if re.search(
                    r"proof of concept|steps to reproduce|screenshot|screen\s*record|"
                    r"video\s+proof|poc",
                    line, re.IGNORECASE,
                ) and len(line.strip()) > 10:
                    evidence_reqs.append(EvidenceRequirement(
                        description=line.strip()[:300], source_section=section.heading
                    ))
        if kind in ("rules", "evidence", "account", "other") and body.strip():
            for line in section.lines:
                for m in _HEADER_RE.finditer(line):
                    name = m.group(1) or m.group(2)
                    if name and name.upper().startswith("X-"):
                        required_headers.append(RequiredHeader(
                            name=name, source_section=section.heading,
                            purpose=line.strip()[:200],
                        ))
        if kind == "known_issues":
            for line in section.lines:
                item = _LIST_ITEM.match(line)
                desc = (item.group("body") if item else line).strip()
                if desc and len(desc) > 3:
                    known_issues.append(KnownIssue(
                        description=desc[:300], source_section=section.heading
                    ))

    # ── inline labels outside heading structure ──
    for line in text.splitlines():
        m = _INLINE_SCOPE.match(line)
        if not m or _is_heading(line):
            continue
        is_in = m.group("label").lower().startswith("in")
        for token, desc in _inline_label_candidates(m.group("rest")):
            classified = _classify_asset(token)
            if not classified or classified[0] in seen_patterns:
                continue
            seen_patterns.add(classified[0])
            kind = "in_scope" if is_in else "out_of_scope"
            asset = _make_asset(token, desc, kind, line, 0.95)
            if is_in:
                in_scope.append(asset)
            else:
                out_of_scope.append(asset)
            scope_rules.append(ScopeRule(
                canonical_pattern=asset.canonical_pattern,
                asset_type=asset.asset_type,
                source_section=f"inline {kind}",
                source_text=line.strip()[:300],
                inclusion_state=(
                    InclusionState.IN_SCOPE if is_in
                    else InclusionState.OUT_OF_SCOPE
                ),
                confidence=0.95,
                description=desc,
            ))
            if not is_in:
                exclusion_rules.append(ExclusionRule(
                    canonical_pattern=asset.canonical_pattern,
                    source_section="inline out_of_scope",
                    source_text=line.strip()[:300],
                    reason=desc or "Listed in inline Out of scope label",
                ))
        saw_scope_section = True

    # ── whole-document fallback for restrictions/account/safe harbor ──
    lower = text.lower()
    restrictions = _extract_restrictions(sections, text)
    for r in restrictions:
        testing_constraints.append(TestingConstraint(
            category=r.category, description=r.description,
            allowed=r.allowed, source_section=r.source_section,
        ))

    account_creation_allowed: bool | None = None
    if re.search(
        r"no\s+account\s+creation|account\s+creation\s+prohibited|"
        r"do\s+not\s+create\s+accounts|accounts?\s+may\s+not\s+be\s+created",
        lower,
    ):
        account_creation_allowed = False
    elif re.search(
        r"(?:may|allowed\s+to|feel\s+free\s+to|you\s+can)\s+create\s+accounts|"
        r"account\s+creation\s+(?:is\s+)?allowed|test\s+accounts?\s+(?:are\s+)?allowed",
        lower,
    ):
        account_creation_allowed = True

    safe_harbor_present = bool(re.search(
        r"safe\s+harbor|responsible\s+disclosure|safe\s+harbour", lower
    ))

    # ── low-confidence audit trail ──
    for rule in scope_rules:
        if rule.confidence < EXPLICIT_CONFIDENCE:
            low_confidence.append(rule.canonical_pattern)

    if not saw_scope_section and not in_scope:
        warnings.append(
            "No explicit scope section or inline 'In scope:' label found — "
            "no assets were authorized from this document."
        )
    if not in_scope and out_of_scope:
        warnings.append("Out-of-scope entries found but no in-scope assets.")

    metadata = PolicyMetadata(
        platform=platform,
        detected_sections=detected,
        parse_warnings=warnings,
        low_confidence_assets=low_confidence,
    )

    allowed_names = [a.name for a in allowed_rules]
    forbidden_names = [f.name for f in forbidden_rules]
    # forbidden always wins
    allowed_names = [n for n in allowed_names if n not in forbidden_names]

    policy = ProgramPolicy(
        program_name=program_name,
        platform=platform,
        in_scope=in_scope,
        out_of_scope=out_of_scope,
        restrictions=restrictions,
        allowed_vulnerabilities=allowed_names,
        forbidden_vulnerabilities=forbidden_names,
        account_creation_allowed=(
            True if account_creation_allowed is None else account_creation_allowed
        ),
        safe_harbor=safe_harbor_present,
        raw_policy=text,
        scope_rules=scope_rules,
        exclusion_rules=exclusion_rules,
        testing_constraints=testing_constraints,
        evidence_requirements=evidence_reqs,
        required_headers=required_headers,
        known_issues=known_issues,
        allowed_vuln_rules=allowed_rules,
        forbidden_vuln_rules=[
            f for f in forbidden_rules if f.name in forbidden_names
        ],
        account_constraint=AccountConstraint(
            creation_allowed=account_creation_allowed,
            description="Detected from policy text",
        ) if account_creation_allowed is not None else None,
        safe_harbor_rule=SafeHarbor(
            present=safe_harbor_present,
            text="Safe-harbor / responsible-disclosure language present",
        ) if safe_harbor_present else None,
        parse_metadata=metadata,
        target_only=not saw_scope_section and not in_scope,
    )
    return policy
