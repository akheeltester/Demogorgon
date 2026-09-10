"""
authcore/session.py — Core authentication primitives for Demogorgon.

Provides the foundational data structures that every AuthCore module depends on.
Designed for multi-account, multi-role, multi-organization testing.

Design Principles:
    1. Immutable where possible — mutations go through explicit methods
    2. Serializable — every object has to_dict() / from_dict()
    3. Validatable — every object has validate() returning (bool, List[str])
    4. Fingerprintable — sessions produce stable fingerprints for deduplication
    5. Backward compatible — AuthSession works as a drop-in for dict-based auth
"""

from __future__ import annotations

import hashlib
import json
import re
import time
import uuid
from copy import deepcopy
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple, Union


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class UserRole(Enum):
    """
    Role hierarchy for RBAC testing.
    
    Hierarchy: VIEWER < MEMBER < ADMIN < OWNER
    
    Used by:
        - RoleTester: tests access at each level
        - AccountBoundaryTester: detects privilege escalation
        - CrossUserIDORTester: tests cross-role object access
    """
    VIEWER = "viewer"
    MEMBER = "member"
    ADMIN = "admin"
    OWNER = "owner"

    @property
    def level(self) -> int:
        """Numeric level for comparison. Higher = more privileged."""
        return {
            UserRole.VIEWER: 0,
            UserRole.MEMBER: 1,
            UserRole.ADMIN: 2,
            UserRole.OWNER: 3,
        }[self]

    def is_higher_than(self, other: UserRole) -> bool:
        return self.level > other.level

    def is_lower_than(self, other: UserRole) -> bool:
        return self.level < other.level

    def includes(self, other: UserRole) -> bool:
        """Does this role include the permissions of other?"""
        return self.level >= other.level


class AuthType(Enum):
    """
    Authentication mechanism used by the session.
    
    Determines which headers/cookies are injected and how tokens are refreshed.
    """
    COOKIE = "cookie"           # Cookie-based session (most web apps)
    BEARER = "bearer"           # Bearer token (APIs, SPAs)
    JWT = "jwt"                 # JWT in Authorization header
    API_KEY = "api_key"         # API key in custom header
    OAUTH2 = "oauth2"           # OAuth2 access token
    BASIC = "basic"             # HTTP Basic auth
    CUSTOM = "custom"           # Custom auth scheme


# ---------------------------------------------------------------------------
# Containers
# ---------------------------------------------------------------------------

@dataclass
class CookieJar:
    """
    Cookie container with domain-scoping and expiry tracking.
    
    Replaces raw Dict[str, str] with structured cookie management.
    Domain filtering ensures cookies are only sent to matching hosts.
    """
    cookies: Dict[str, str] = field(default_factory=dict)
    domain: str = ""
    _domain_map: Dict[str, List[str]] = field(default_factory=dict, repr=False)
    _expiry_map: Dict[str, Optional[int]] = field(default_factory=dict, repr=False)
    _httponly: set = field(default_factory=set, repr=False)
    _secure: set = field(default_factory=set, repr=False)

    def set(
        self,
        name: str,
        value: str,
        domain: str = "",
        path: str = "/",
        httponly: bool = False,
        secure: bool = False,
        expires: Optional[int] = None,
    ) -> None:
        """Set a cookie with metadata."""
        self.cookies[name] = value
        d = domain or self.domain
        if d:
            key = f"{d}:{path}"
            if key not in self._domain_map:
                self._domain_map[key] = []
            if name not in self._domain_map[key]:
                self._domain_map[key].append(name)
        if expires is not None:
            self._expiry_map[name] = expires
        if httponly:
            self._httponly.add(name)
        if secure:
            self._secure.add(name)

    def get(self, name: str, default: str = "") -> str:
        return self.cookies.get(name, default)

    def delete(self, name: str) -> bool:
        if name in self.cookies:
            del self.cookies[name]
            self._expiry_map.pop(name, None)
            self._httponly.discard(name)
            self._secure.discard(name)
            for key in list(self._domain_map):
                if name in self._domain_map[key]:
                    self._domain_map[key].remove(name)
            return True
        return False

    def is_expired(self, name: str) -> bool:
        exp = self._expiry_map.get(name)
        if exp is None:
            return False
        return exp < time.time()

    def remove_expired(self) -> int:
        """Remove all expired cookies. Returns count removed."""
        now = time.time()
        expired = [n for n, e in self._expiry_map.items() if e is not None and e < now]
        for name in expired:
            self.delete(name)
        return len(expired)

    def filter_by_domain(self, domain: str) -> Dict[str, str]:
        """Return cookies matching the given domain."""
        result = {}
        for key, names in self._domain_map.items():
            cookie_domain = key.split(":")[0]
            if domain == cookie_domain or domain.endswith("." + cookie_domain):
                for name in names:
                    if name in self.cookies and not self.is_expired(name):
                        result[name] = self.cookies[name]
        return result

    def to_header_string(self) -> str:
        """Serialize to Cookie header value: 'name1=val1; name2=val2'."""
        return "; ".join(f"{k}={v}" for k, v in self.cookies.items() if not self.is_expired(k))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cookies": dict(self.cookies),
            "domain": self.domain,
            "expiry_map": dict(self._expiry_map),
            "httponly": list(self._httponly),
            "secure": list(self._secure),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> CookieJar:
        jar = cls(
            cookies=data.get("cookies", {}),
            domain=data.get("domain", ""),
        )
        jar._expiry_map = data.get("expiry_map", {})
        jar._httponly = set(data.get("httponly", []))
        jar._secure = set(data.get("secure", []))
        return jar

    def __len__(self) -> int:
        return len(self.cookies)

    def __contains__(self, name: str) -> bool:
        return name in self.cookies

    def __iter__(self):
        return iter(self.cookies)

    def items(self):
        return self.cookies.items()


@dataclass
class HeaderSet:
    """
    Header container with precedence rules and auth-specific handling.
    
    Headers are injected into every request. Auth headers (Authorization,
    X-CSRF-Token, etc.) take precedence over custom headers.
    """
    _headers: Dict[str, str] = field(default_factory=dict)
    _auth_headers: Dict[str, str] = field(default_factory=dict, repr=False)
    _case_map: Dict[str, str] = field(default_factory=dict, repr=False)

    def set(self, name: str, value: str, is_auth: bool = False) -> None:
        """Set a header. If is_auth, it cannot be overridden by custom headers."""
        lower = name.lower()
        self._case_map[lower] = name
        if is_auth:
            self._auth_headers[lower] = value
        else:
            self._headers[lower] = value

    def get(self, name: str, default: str = "") -> str:
        lower = name.lower()
        return self._auth_headers.get(lower, self._headers.get(lower, default))

    def delete(self, name: str) -> bool:
        lower = name.lower()
        changed = False
        if lower in self._auth_headers:
            del self._auth_headers[lower]
            changed = True
        if lower in self._headers:
            del self._headers[lower]
            changed = True
        self._case_map.pop(lower, None)
        return changed

    def merge(self, other: HeaderSet) -> None:
        """Merge another HeaderSet into this one. Auth headers take precedence."""
        for lower, value in other._auth_headers.items():
            self._auth_headers[lower] = value
            self._case_map[lower] = other._case_map.get(lower, lower)
        for lower, value in other._headers.items():
            if lower not in self._headers:
                self._headers[lower] = value
                self._case_map[lower] = other._case_map.get(lower, lower)

    def to_dict(self) -> Dict[str, str]:
        """Return merged headers dict (auth headers override custom)."""
        result = {}
        for lower, value in self._headers.items():
            canonical = self._case_map.get(lower, lower)
            result[canonical] = value
        for lower, value in self._auth_headers.items():
            canonical = self._case_map.get(lower, lower)
            result[canonical] = value
        return result

    def to_raw_headers(self) -> List[Tuple[str, str]]:
        """Return as list of (name, value) tuples for httpx."""
        return list(self.to_dict().items())

    @classmethod
    def from_dict(cls, data: Dict[str, str]) -> HeaderSet:
        hs = cls()
        for name, value in data.items():
            hs.set(name, value)
        return hs

    def __len__(self) -> int:
        return len(set(self._headers.keys()) | set(self._auth_headers.keys()))

    def __contains__(self, name: str) -> bool:
        lower = name.lower()
        return lower in self._headers or lower in self._auth_headers

    def __iter__(self):
        return iter(self.to_dict())


@dataclass
class JWTToken:
    """
    JWT token container with structured access to claims.
    
    Handles token storage, expiry detection, and claim extraction
    without requiring a JWT library for read operations.
    """
    token: str = ""
    token_type: str = "Bearer"
    header: Dict[str, Any] = field(default_factory=dict)
    payload: Dict[str, Any] = field(default_factory=dict)
    signature: str = ""
    raw: str = ""
    expires_at: Optional[int] = None
    issued_at: Optional[int] = None
    subject: str = ""
    issuer: str = ""
    audience: str = ""
    scopes: List[str] = field(default_factory=list)

    def __post_init__(self):
        if self.raw and not self.token:
            self.token = self.raw
        if self.token and not self.raw:
            self.raw = self.token
        if self.token and not self.payload:
            self._parse_token()

    def _parse_token(self) -> None:
        """Parse JWT without external library. Best-effort."""
        parts = self.token.split(".")
        if len(parts) < 2:
            return
        try:
            import base64
            # Decode header
            header_pad = parts[0] + "=" * (4 - len(parts[0]) % 4)
            self.header = json.loads(base64.urlsafe_b64decode(header_pad))
            # Decode payload
            payload_pad = parts[1] + "=" * (4 - len(parts[1]) % 4)
            self.payload = json.loads(base64.urlsafe_b64decode(payload_pad))
            # Extract claims
            self.expires_at = self.payload.get("exp")
            self.issued_at = self.payload.get("iat")
            self.subject = str(self.payload.get("sub", ""))
            self.issuer = str(self.payload.get("iss", ""))
            self.audience = str(self.payload.get("aud", ""))
            if isinstance(self.payload.get("scope"), str):
                self.scopes = self.payload["scope"].split()
            elif isinstance(self.payload.get("scope"), list):
                self.scopes = self.payload["scope"]
            if len(parts) >= 3:
                self.signature = parts[2]
        except Exception:
            pass  # Best-effort parsing

    @property
    def is_expired(self) -> bool:
        if self.expires_at is None:
            return False
        return self.expires_at < time.time()

    @property
    def expires_in(self) -> Optional[int]:
        """Seconds until expiry. None if no expiry set."""
        if self.expires_at is None:
            return None
        remaining = self.expires_at - time.time()
        return max(0, int(remaining))

    @property
    def authorization_value(self) -> str:
        """Value for Authorization header."""
        return f"{self.token_type} {self.token}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "token": self.token,
            "token_type": self.token_type,
            "expires_at": self.expires_at,
            "issued_at": self.issued_at,
            "subject": self.subject,
            "issuer": self.issuer,
            "audience": self.audience,
            "scopes": self.scopes,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> JWTToken:
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


@dataclass
class CSRFToken:
    """
    CSRF token container with header name and value tracking.
    
    Different apps use different CSRF header names:
        - X-CSRF-Token (Rails, Django)
        - X-CSRFToken (Express)
        - X-XSRF-TOKEN (Angular, Spring)
        - _csrf (query parameter)
        - csrfmiddlewaretoken (Django form field)
    """
    token: str = ""
    header_name: str = "X-CSRF-Token"
    form_field: str = ""
    query_param: str = ""

    def to_header(self) -> Dict[str, str]:
        if not self.token:
            return {}
        return {self.header_name: self.token}

    def to_form_data(self) -> Dict[str, str]:
        if not self.token or not self.form_field:
            return {}
        return {self.form_field: self.token}

    def to_query_param(self) -> Dict[str, str]:
        if not self.token or not self.query_param:
            return {}
        return {self.query_param: self.token}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "token": self.token,
            "header_name": self.header_name,
            "form_field": self.form_field,
            "query_param": self.query_param,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> CSRFToken:
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


# ---------------------------------------------------------------------------
# Metadata containers
# ---------------------------------------------------------------------------

@dataclass
class AccountMeta:
    """
    Metadata about the user account this session belongs to.
    
    Enables cross-account testing by identifying users across sessions.
    """
    user_id: str = ""
    username: str = ""
    email: str = ""
    display_name: str = ""
    account_type: str = ""          # "free", "premium", "enterprise", etc.
    account_status: str = "active"  # "active", "suspended", "pending"
    created_at: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> AccountMeta:
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


@dataclass
class OrgMeta:
    """
    Metadata about the organization this session belongs to.
    
    Enables multi-org testing where users belong to different organizations.
    Critical for detecting cross-tenant IDOR.
    """
    org_id: str = ""
    org_name: str = ""
    org_slug: str = ""
    org_type: str = ""              # "personal", "team", "enterprise"
    plan: str = ""                  # "free", "pro", "enterprise"
    role_in_org: str = ""           # Member's role within the org
    member_count: Optional[int] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> OrgMeta:
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


@dataclass
class ScopeMeta:
    """
    Scope metadata for OAuth2 / OIDC sessions.
    
    Tracks what permissions this session has and what APIs it can access.
    Used by RoleTester to verify scope enforcement.
    """
    scopes: List[str] = field(default_factory=list)
    permissions: List[str] = field(default_factory=list)
    resource_limits: Dict[str, Any] = field(default_factory=dict)
    api_access: List[str] = field(default_factory=list)  # Endpoints accessible

    def has_scope(self, scope: str) -> bool:
        return scope in self.scopes or "*" in self.scopes

    def has_permission(self, perm: str) -> bool:
        return perm in self.permissions or "*" in self.permissions

    def can_access(self, endpoint: str) -> bool:
        if "*" in self.api_access:
            return True
        return endpoint in self.api_access

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ScopeMeta:
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


# ---------------------------------------------------------------------------
# AuthSession — The core primitive
# ---------------------------------------------------------------------------

@dataclass
class AuthSession:
    """
    Unified authentication context for a single user session.
    
    This is the foundational primitive that every AuthCore module consumes.
    It replaces the empty dict/list-based auth handling with a structured,
    queryable, serializable auth context.
    
    Usage:
        session = AuthSession(
            label="admin_user",
            role=UserRole.ADMIN,
            auth_type=AuthType.COOKIE,
            cookies=CookieJar(cookies={"session": "abc123"}),
        )
        
        # Build headers for a request
        headers = session.build_request_headers()
        
        # Check if session is valid
        ok, issues = session.validate()
        
        # Serialize for storage
        data = session.to_dict()
    """

    # ── Identity ────────────────────────────────────────────────────────
    session_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    label: str = ""                         # Human-readable ("admin_user", "victim")
    role: UserRole = UserRole.MEMBER
    auth_type: AuthType = AuthType.COOKIE

    # ── Auth data ───────────────────────────────────────────────────────
    cookies: CookieJar = field(default_factory=CookieJar)
    headers: HeaderSet = field(default_factory=HeaderSet)
    jwt: Optional[JWTToken] = None
    csrf: Optional[CSRFToken] = None
    api_key: str = ""
    api_key_header: str = "X-API-Key"
    basic_user: str = ""
    basic_pass: str = ""
    custom_auth: Dict[str, str] = field(default_factory=dict)

    # ── Metadata ────────────────────────────────────────────────────────
    target_domain: str = ""
    account: AccountMeta = field(default_factory=AccountMeta)
    org: OrgMeta = field(default_factory=OrgMeta)
    scope: ScopeMeta = field(default_factory=ScopeMeta)

    # ── Timestamps ──────────────────────────────────────────────────────
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    last_used: Optional[str] = None
    expires_at: Optional[str] = None
    last_validated_at: Optional[str] = None
    last_validation_status: Optional[int] = None

    # ── Source tracking ─────────────────────────────────────────────────
    source: str = ""                        # "cli", "browser_export", "burp", etc.
    source_file: str = ""                   # Path to imported file

    # ── State ───────────────────────────────────────────────────────────
    is_valid: bool = True
    validation_endpoint: Optional[str] = None

    def __post_init__(self):
        # Ensure cookie jar has the right domain
        if not self.cookies.domain and self.target_domain:
            self.cookies.domain = self.target_domain

    # ── Request building ────────────────────────────────────────────────

    def build_request_headers(
        self,
        extra_headers: Optional[Dict[str, str]] = None,
        include_cookies: bool = True,
        include_csrf: bool = True,
    ) -> Dict[str, str]:
        """
        Build complete header dict for an HTTP request.
        
        Merge order (later overrides earlier):
            1. Base auth headers (from auth_type)
            2. Custom headers from HeaderSet
            3. CSRF token header
            4. Extra headers (caller-provided)
        """
        result: Dict[str, str] = {}

        # 1. Auth-type specific headers
        if self.auth_type == AuthType.BEARER and self.jwt:
            result["Authorization"] = self.jwt.authorization_value
        elif self.auth_type == AuthType.JWT and self.jwt:
            result["Authorization"] = self.jwt.authorization_value
        elif self.auth_type == AuthType.BASIC and self.basic_user:
            import base64
            creds = base64.b64encode(f"{self.basic_user}:{self.basic_pass}".encode()).decode()
            result["Authorization"] = f"Basic {creds}"
        elif self.auth_type == AuthType.API_KEY and self.api_key:
            result[self.api_key_header] = self.api_key
        elif self.auth_type == AuthType.OAUTH2 and self.jwt:
            result["Authorization"] = f"Bearer {self.jwt.token}"
        elif self.auth_type == AuthType.CUSTOM:
            result.update(self.custom_auth)

        # 2. Cookie header
        if include_cookies and self.cookies:
            cookie_str = self.cookies.to_header_string()
            if cookie_str:
                result["Cookie"] = cookie_str

        # 3. Custom headers from HeaderSet
        for name, value in self.headers:
            result[name] = value

        # 4. CSRF token
        if include_csrf and self.csrf and self.csrf.token:
            result.update(self.csrf.to_header())

        # 5. Extra headers (override everything)
        if extra_headers:
            result.update(extra_headers)

        return result

    def build_cookie_dict(self, domain: str = "") -> Dict[str, str]:
        """Get cookies filtered by domain."""
        if domain:
            return self.cookies.filter_by_domain(domain)
        return dict(self.cookies.cookies)

    # ── Validation ──────────────────────────────────────────────────────

    def validate(self) -> Tuple[bool, List[str]]:
        """
        Validate session integrity.
        
        Returns:
            (is_valid, list of issues)
        """
        issues = []

        if not self.session_id:
            issues.append("session_id is empty")

        if not self.target_domain:
            issues.append("target_domain is empty")

        if not self.label:
            issues.append("label is empty (cosmetic, not critical)")

        # Check auth data presence
        has_auth = False
        if self.auth_type in (AuthType.COOKIE, AuthType.CUSTOM) and self.cookies:
            has_auth = True
        elif self.auth_type in (AuthType.BEARER, AuthType.JWT, AuthType.OAUTH2) and self.jwt and self.jwt.token:
            has_auth = True
        elif self.auth_type == AuthType.API_KEY and self.api_key:
            has_auth = True
        elif self.auth_type == AuthType.BASIC and self.basic_user:
            has_auth = True

        if not has_auth:
            issues.append(f"no auth data for auth_type={self.auth_type.value}")

        # Check expiry
        if self.is_expired():
            issues.append("session is expired")

        return (len(issues) == 0, issues)

    def is_expired(self) -> bool:
        """Check if session has expired."""
        if self.expires_at is None:
            return False
        try:
            exp_dt = datetime.fromisoformat(self.expires_at)
            return exp_dt < datetime.now(timezone.utc)
        except (ValueError, TypeError):
            return False

    def mark_used(self) -> None:
        """Update last_used timestamp."""
        self.last_used = datetime.now(timezone.utc).isoformat()

    def mark_validated(self, status_code: int) -> None:
        """Record validation attempt."""
        self.last_validated_at = datetime.now(timezone.utc).isoformat()
        self.last_validation_status = status_code
        self.is_valid = 200 <= status_code < 400

    # ── Fingerprinting ──────────────────────────────────────────────────

    def fingerprint(self) -> str:
        """
        Generate stable fingerprint for deduplication.
        
        Same credentials → same fingerprint, regardless of session_id.
        Uses: domain + role + sorted cookies + jwt sub/iss.
        """
        parts = [
            self.target_domain,
            self.role.value,
            self.auth_type.value,
        ]

        # Sorted cookies for stability
        for name in sorted(self.cookies.cookies.keys()):
            parts.append(f"cookie:{name}={self.cookies.cookies[name][:8]}")

        # JWT claims
        if self.jwt:
            if self.jwt.subject:
                parts.append(f"sub:{self.jwt.subject}")
            if self.jwt.issuer:
                parts.append(f"iss:{self.jwt.issuer}")

        # Account
        if self.account.user_id:
            parts.append(f"uid:{self.account.user_id}")
        if self.account.email:
            parts.append(f"email:{self.account.email}")

        # Org
        if self.org.org_id:
            parts.append(f"org:{self.org.org_id}")

        raw = "|".join(parts)
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    # ── Serialization ───────────────────────────────────────────────────

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to JSON-safe dict."""
        data = {
            "session_id": self.session_id,
            "label": self.label,
            "role": self.role.value,
            "auth_type": self.auth_type.value,
            "cookies": self.cookies.to_dict(),
            "headers": self.headers.to_dict(),
            "jwt": self.jwt.to_dict() if self.jwt else None,
            "csrf": self.csrf.to_dict() if self.csrf else None,
            "api_key": self.api_key,
            "api_key_header": self.api_key_header,
            "basic_user": self.basic_user,
            "basic_pass": self.basic_pass,
            "custom_auth": self.custom_auth,
            "target_domain": self.target_domain,
            "account": self.account.to_dict(),
            "org": self.org.to_dict(),
            "scope": self.scope.to_dict(),
            "created_at": self.created_at,
            "last_used": self.last_used,
            "expires_at": self.expires_at,
            "last_validated_at": self.last_validated_at,
            "last_validation_status": self.last_validation_status,
            "source": self.source,
            "source_file": self.source_file,
            "is_valid": self.is_valid,
            "validation_endpoint": self.validation_endpoint,
        }
        return data

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> AuthSession:
        """Deserialize from dict."""
        if not data:
            return cls()

        # Reconstruct containers
        cookies = CookieJar.from_dict(data.get("cookies", {}))
        headers = HeaderSet.from_dict(data.get("headers", {}))
        jwt = JWTToken.from_dict(data["jwt"]) if data.get("jwt") else None
        csrf = CSRFToken.from_dict(data["csrf"]) if data.get("csrf") else None
        account = AccountMeta.from_dict(data.get("account", {}))
        org = OrgMeta.from_dict(data.get("org", {}))
        scope = ScopeMeta.from_dict(data.get("scope", {}))

        # Parse enums
        role = UserRole(data.get("role", "member"))
        auth_type = AuthType(data.get("auth_type", "cookie"))

        return cls(
            session_id=data.get("session_id", str(uuid.uuid4())),
            label=data.get("label", ""),
            role=role,
            auth_type=auth_type,
            cookies=cookies,
            headers=headers,
            jwt=jwt,
            csrf=csrf,
            api_key=data.get("api_key", ""),
            api_key_header=data.get("api_key_header", "X-API-Key"),
            basic_user=data.get("basic_user", ""),
            basic_pass=data.get("basic_pass", ""),
            custom_auth=data.get("custom_auth", {}),
            target_domain=data.get("target_domain", ""),
            account=account,
            org=org,
            scope=scope,
            created_at=data.get("created_at", ""),
            last_used=data.get("last_used"),
            expires_at=data.get("expires_at"),
            last_validated_at=data.get("last_validated_at"),
            last_validation_status=data.get("last_validation_status"),
            source=data.get("source", ""),
            source_file=data.get("source_file", ""),
            is_valid=data.get("is_valid", True),
            validation_endpoint=data.get("validation_endpoint"),
        )

    @classmethod
    def from_json(cls, json_str: str) -> AuthSession:
        return cls.from_dict(json.loads(json_str))

    # ── Convenience constructors ────────────────────────────────────────

    @classmethod
    def from_cookies(
        cls,
        cookies: Dict[str, str],
        domain: str,
        label: str = "",
        role: UserRole = UserRole.MEMBER,
    ) -> AuthSession:
        """Create session from simple cookie dict."""
        jar = CookieJar(cookies=cookies, domain=domain)
        return cls(
            label=label or f"cookie_session@{domain}",
            role=role,
            auth_type=AuthType.COOKIE,
            cookies=jar,
            target_domain=domain,
        )

    @classmethod
    def from_bearer_token(
        cls,
        token: str,
        domain: str,
        label: str = "",
        role: UserRole = UserRole.MEMBER,
    ) -> AuthSession:
        """Create session from bearer token string."""
        jwt = JWTToken(token=token, token_type="Bearer")
        return cls(
            label=label or f"bearer_session@{domain}",
            role=role,
            auth_type=AuthType.BEARER,
            jwt=jwt,
            target_domain=domain,
        )

    @classmethod
    def from_jwt(
        cls,
        token: str,
        domain: str,
        label: str = "",
        role: UserRole = UserRole.MEMBER,
    ) -> AuthSession:
        """Create session from JWT token."""
        jwt = JWTToken(token=token)
        return cls(
            label=label or f"jwt_session@{domain}",
            role=role,
            auth_type=AuthType.JWT,
            jwt=jwt,
            target_domain=domain,
        )

    @classmethod
    def from_api_key(
        cls,
        api_key: str,
        header: str,
        domain: str,
        label: str = "",
        role: UserRole = UserRole.MEMBER,
    ) -> AuthSession:
        """Create session from API key."""
        return cls(
            label=label or f"apikey_session@{domain}",
            role=role,
            auth_type=AuthType.API_KEY,
            api_key=api_key,
            api_key_header=header,
            target_domain=domain,
        )

    @classmethod
    def from_basic_auth(
        cls,
        username: str,
        password: str,
        domain: str,
        label: str = "",
        role: UserRole = UserRole.MEMBER,
    ) -> AuthSession:
        """Create session from basic auth credentials."""
        return cls(
            label=label or f"basic_session@{domain}",
            role=role,
            auth_type=AuthType.BASIC,
            basic_user=username,
            basic_pass=password,
            target_domain=domain,
        )

    def __repr__(self) -> str:
        return (
            f"AuthSession(id={self.session_id[:8]}, label={self.label!r}, "
            f"role={self.role.value}, auth={self.auth_type.value}, "
            f"domain={self.target_domain})"
        )

    def __eq__(self, other) -> bool:
        if not isinstance(other, AuthSession):
            return False
        return self.session_id == other.session_id

    def __hash__(self) -> int:
        return hash(self.session_id)
