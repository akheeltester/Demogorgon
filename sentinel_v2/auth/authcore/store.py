"""
authcore/store.py — Multi-account session store with persistence.

Provides AuthSessionStore: the central registry for all authenticated sessions.
Supports multi-account, multi-role, multi-organization testing with:
    - In-memory cache for fast access
    - SQLite persistence for cross-session survival
    - Indexing by role, domain, org, fingerprint
    - Session search and filtering
    - Health checks and expiry management

Design:
    The store is a write-through cache. All mutations hit both memory and SQLite.
    Reads come from memory (O(1) lookup). SQLite is the source of truth.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from sentinel_v2.auth.authcore.session import AuthSession, UserRole, AuthType

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS auth_sessions (
    session_id TEXT PRIMARY KEY,
    label TEXT NOT NULL,
    role TEXT NOT NULL,
    auth_type TEXT NOT NULL,
    target_domain TEXT NOT NULL,
    account_user_id TEXT DEFAULT '',
    account_username TEXT DEFAULT '',
    account_email TEXT DEFAULT '',
    org_id TEXT DEFAULT '',
    org_name TEXT DEFAULT '',
    source TEXT DEFAULT '',
    fingerprint TEXT NOT NULL,
    is_valid INTEGER DEFAULT 1,
    created_at TEXT NOT NULL,
    last_used TEXT,
    expires_at TEXT,
    last_validated_at TEXT,
    last_validation_status INTEGER,
    session_data TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_auth_sessions_role
    ON auth_sessions(role);
CREATE INDEX IF NOT EXISTS idx_auth_sessions_domain
    ON auth_sessions(target_domain);
CREATE INDEX IF NOT EXISTS idx_auth_sessions_org
    ON auth_sessions(org_id);
CREATE INDEX IF NOT EXISTS idx_auth_sessions_fingerprint
    ON auth_sessions(fingerprint);
CREATE INDEX IF NOT EXISTS idx_auth_sessions_valid
    ON auth_sessions(is_valid);
CREATE INDEX IF NOT EXISTS idx_auth_sessions_user
    ON auth_sessions(account_user_id);
"""


# ---------------------------------------------------------------------------
# AuthSessionStore
# ---------------------------------------------------------------------------

class AuthSessionStore:
    """
    Central registry for authenticated sessions.
    
    Provides O(1) in-memory lookup with SQLite persistence.
    Supports multi-account, multi-role, multi-organization testing.
    
    Usage:
        store = AuthSessionStore()
        
        # Add sessions
        store.add_session(admin_session)
        store.add_session(member_session)
        
        # Query
        admin = store.get_best_session("target.com", UserRole.ADMIN)
        all_members = store.get_sessions_by_role(UserRole.MEMBER)
        
        # Cross-account
        users = store.get_sessions_by_org("org_123")
    """

    def __init__(self, db_path: Optional[str] = None):
        """
        Initialize store.
        
        Args:
            db_path: SQLite database path. None = memory-only mode.
        """
        self._sessions: Dict[str, AuthSession] = {}
        self._fingerprint_map: Dict[str, str] = {}  # fingerprint → session_id
        self._lock = threading.Lock()

        # Indexes ( rebuilt on load )
        self._by_role: Dict[str, Set[str]] = {}
        self._by_domain: Dict[str, Set[str]] = {}
        self._by_org: Dict[str, Set[str]] = {}
        self._by_user: Dict[str, Set[str]] = {}
        self._by_auth_type: Dict[str, Set[str]] = {}

        # SQLite persistence
        self._db_path = db_path
        self._conn: Optional[sqlite3.Connection] = None
        if db_path:
            self._init_sqlite()

    # ── SQLite lifecycle ────────────────────────────────────────────────

    def _init_sqlite(self) -> None:
        """Initialize SQLite connection and schema."""
        try:
            self._conn = sqlite3.connect(
                self._db_path,
                check_same_thread=False,
                timeout=5.0,
            )
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA busy_timeout=5000")
            self._conn.executescript(_SCHEMA_SQL)
            self._conn.commit()
            self._load_from_sqlite()
            logger.info(f"AuthSessionStore initialized with SQLite at {self._db_path}")
        except Exception as e:
            logger.error(f"SQLite init failed: {e}")
            self._conn = None

    def _load_from_sqlite(self) -> None:
        """Load all sessions from SQLite into memory."""
        if not self._conn:
            return
        try:
            cursor = self._conn.execute("SELECT session_data FROM auth_sessions")
            for row in cursor.fetchall():
                try:
                    data = json.loads(row["session_data"])
                    session = AuthSession.from_dict(data)
                    self._sessions[session.session_id] = session
                    self._rebuild_indexes_for(session)
                except Exception as e:
                    logger.warning(f"Failed to load session: {e}")
            logger.info(f"Loaded {len(self._sessions)} sessions from SQLite")
        except Exception as e:
            logger.error(f"Failed to load from SQLite: {e}")

    def _persist_to_sqlite(self, session: AuthSession) -> None:
        """Write a single session to SQLite."""
        if not self._conn:
            return
        try:
            data = json.dumps(session.to_dict(), default=str)
            self._conn.execute(
                """
                INSERT OR REPLACE INTO auth_sessions
                (session_id, label, role, auth_type, target_domain,
                 account_user_id, account_username, account_email,
                 org_id, org_name, source, fingerprint, is_valid,
                 created_at, last_used, expires_at,
                 last_validated_at, last_validation_status, session_data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session.session_id,
                    session.label,
                    session.role.value,
                    session.auth_type.value,
                    session.target_domain,
                    session.account.user_id,
                    session.account.username,
                    session.account.email,
                    session.org.org_id,
                    session.org.org_name,
                    session.source,
                    session.fingerprint(),
                    1 if session.is_valid else 0,
                    session.created_at,
                    session.last_used,
                    session.expires_at,
                    session.last_validated_at,
                    session.last_validation_status,
                    data,
                ),
            )
            self._conn.commit()
        except Exception as e:
            logger.error(f"SQLite persist failed for {session.session_id}: {e}")

    def _delete_from_sqlite(self, session_id: str) -> None:
        """Remove a session from SQLite."""
        if not self._conn:
            return
        try:
            self._conn.execute(
                "DELETE FROM auth_sessions WHERE session_id = ?",
                (session_id,),
            )
            self._conn.commit()
        except Exception as e:
            logger.error(f"SQLite delete failed for {session_id}: {e}")

    # ── Index management ────────────────────────────────────────────────

    def _rebuild_indexes_for(self, session: AuthSession) -> None:
        """Add a session to all in-memory indexes."""
        sid = session.session_id

        # Role index
        role_key = session.role.value
        self._by_role.setdefault(role_key, set()).add(sid)

        # Domain index
        domain_key = session.target_domain.lower()
        self._by_domain.setdefault(domain_key, set()).add(sid)

        # Org index
        if session.org.org_id:
            self._by_org.setdefault(session.org.org_id, set()).add(sid)

        # User index
        if session.account.user_id:
            self._by_user.setdefault(session.account.user_id, set()).add(sid)

        # Auth type index
        auth_key = session.auth_type.value
        self._by_auth_type.setdefault(auth_key, set()).add(sid)

        # Fingerprint index
        fp = session.fingerprint()
        self._fingerprint_map[fp] = sid

    def _remove_from_indexes(self, session: AuthSession) -> None:
        """Remove a session from all in-memory indexes."""
        sid = session.session_id

        role_key = session.role.value
        if role_key in self._by_role:
            self._by_role[role_key].discard(sid)

        domain_key = session.target_domain.lower()
        if domain_key in self._by_domain:
            self._by_domain[domain_key].discard(sid)

        if session.org.org_id and session.org.org_id in self._by_org:
            self._by_org[session.org.org_id].discard(sid)

        if session.account.user_id and session.account.user_id in self._by_user:
            self._by_user[session.account.user_id].discard(sid)

        auth_key = session.auth_type.value
        if auth_key in self._by_auth_type:
            self._by_auth_type[auth_key].discard(sid)

        fp = session.fingerprint()
        self._fingerprint_map.pop(fp, None)

    # ── Public API: Add / Remove ────────────────────────────────────────

    def add_session(self, session: AuthSession) -> str:
        """
        Register a session in the store.
        
        If a session with the same fingerprint exists, replaces it.
        If a session with the same session_id exists, updates it.
        
        Returns:
            session_id
        """
        with self._lock:
            # Check for existing session with same fingerprint
            fp = session.fingerprint()
            existing_sid = self._fingerprint_map.get(fp)
            if existing_sid and existing_sid != session.session_id:
                # Replace old session
                old = self._sessions.pop(existing_sid, None)
                if old:
                    self._remove_from_indexes(old)
                    self._delete_from_sqlite(existing_sid)
                    logger.info(f"Replaced session {existing_sid} with {session.session_id} (same fingerprint)")

            # Remove old indexes if updating
            old_session = self._sessions.get(session.session_id)
            if old_session:
                self._remove_from_indexes(old_session)

            # Store
            self._sessions[session.session_id] = session
            self._rebuild_indexes_for(session)
            self._persist_to_sqlite(session)

            return session.session_id

    def remove_session(self, session_id: str) -> bool:
        """Remove a session from the store. Returns True if removed."""
        with self._lock:
            session = self._sessions.pop(session_id, None)
            if not session:
                return False
            self._remove_from_indexes(session)
            self._delete_from_sqlite(session_id)
            return True

    def clear(self) -> int:
        """Remove all sessions. Returns count removed."""
        with self._lock:
            count = len(self._sessions)
            self._sessions.clear()
            self._fingerprint_map.clear()
            self._by_role.clear()
            self._by_domain.clear()
            self._by_org.clear()
            self._by_user.clear()
            self._by_auth_type.clear()
            if self._conn:
                self._conn.execute("DELETE FROM auth_sessions")
                self._conn.commit()
            return count

    # ── Public API: Lookup ──────────────────────────────────────────────

    def get_session(self, session_id: str) -> Optional[AuthSession]:
        """Get session by ID. O(1)."""
        return self._sessions.get(session_id)

    def get_by_fingerprint(self, fingerprint: str) -> Optional[AuthSession]:
        """Get session by fingerprint hash."""
        sid = self._fingerprint_map.get(fingerprint)
        if sid:
            return self._sessions.get(sid)
        return None

    def has_session(self, session_id: str) -> bool:
        return session_id in self._sessions

    def has_fingerprint(self, fingerprint: str) -> bool:
        return fingerprint in self._fingerprint_map

    # ── Public API: Query by role ───────────────────────────────────────

    def get_sessions_by_role(self, role: UserRole) -> List[AuthSession]:
        """Get all sessions with a specific role."""
        sids = self._by_role.get(role.value, set())
        return [self._sessions[sid] for sid in sids if sid in self._sessions]

    def get_highest_role_session(
        self,
        domain: str,
        exclude_expired: bool = True,
    ) -> Optional[AuthSession]:
        """Get the session with the highest role for a domain."""
        candidates = self.get_sessions_for_domain(domain, exclude_expired)
        if not candidates:
            return None
        return max(candidates, key=lambda s: s.role.level)

    # ── Public API: Query by domain ─────────────────────────────────────

    def get_sessions_for_domain(
        self,
        domain: str,
        exclude_expired: bool = True,
    ) -> List[AuthSession]:
        """Get all sessions valid for a domain."""
        domain_lower = domain.lower()
        sids = set()

        # Exact match
        sids.update(self._by_domain.get(domain_lower, set()))

        # Parent domain match (e.g., api.target.com matches target.com)
        parts = domain_lower.split(".")
        for i in range(1, len(parts)):
            parent = ".".join(parts[i:])
            sids.update(self._by_domain.get(parent, set()))

        # Subdomain match (e.g., target.com matches *.target.com)
        wildcard_key = f".{domain_lower}"
        for key, sid_set in self._by_domain.items():
            if key.startswith(wildcard_key):
                sids.update(sid_set)

        sessions = [self._sessions[sid] for sid in sids if sid in self._sessions]

        if exclude_expired:
            sessions = [s for s in sessions if not s.is_expired()]

        return sessions

    def get_best_session(
        self,
        domain: str,
        role: Optional[UserRole] = None,
        exclude_expired: bool = True,
    ) -> Optional[AuthSession]:
        """
        Get the best available session for a domain/role combo.
        
        Priority:
            1. Exact role match (highest level within role)
            2. Higher role (role includes lower permissions)
            3. Any session for domain
        
        If role is None, returns highest-role session for domain.
        """
        candidates = self.get_sessions_for_domain(domain, exclude_expired)
        if not candidates:
            return None

        if role is None:
            return max(candidates, key=lambda s: s.role.level)

        # Exact role match
        exact = [s for s in candidates if s.role == role]
        if exact:
            return max(exact, key=lambda s: s.role.level)

        # Higher role (includes lower permissions)
        higher = [s for s in candidates if s.role.includes(role)]
        if higher:
            return max(higher, key=lambda s: s.role.level)

        # Any session
        return max(candidates, key=lambda s: s.role.level)

    # ── Public API: Query by organization ───────────────────────────────

    def get_sessions_by_org(self, org_id: str) -> List[AuthSession]:
        """Get all sessions belonging to an organization."""
        sids = self._by_org.get(org_id, set())
        return [self._sessions[sid] for sid in sids if sid in self._sessions]

    def get_org_members(
        self,
        org_id: str,
        exclude_expired: bool = True,
    ) -> List[AuthSession]:
        """Get all members of an organization, sorted by role level."""
        sessions = self.get_sessions_by_org(org_id)
        if exclude_expired:
            sessions = [s for s in sessions if not s.is_expired()]
        return sorted(sessions, key=lambda s: s.role.level)

    def get_org_role_matrix(self, org_id: str) -> Dict[str, List[AuthSession]]:
        """Get sessions grouped by role within an org."""
        sessions = self.get_sessions_by_org(org_id)
        matrix: Dict[str, List[AuthSession]] = {}
        for s in sessions:
            matrix.setdefault(s.role.value, []).append(s)
        return matrix

    # ── Public API: Query by user ───────────────────────────────────────

    def get_sessions_by_user(self, user_id: str) -> List[AuthSession]:
        """Get all sessions for a specific user (multi-org/multi-domain)."""
        sids = self._by_user.get(user_id, set())
        return [self._sessions[sid] for sid in sids if sid in self._sessions]

    # ── Public API: Query by auth type ──────────────────────────────────

    def get_sessions_by_auth_type(self, auth_type: AuthType) -> List[AuthSession]:
        """Get all sessions using a specific auth mechanism."""
        sids = self._by_auth_type.get(auth_type.value, set())
        return [self._sessions[sid] for sid in sids if sid in self._sessions]

    # ── Public API: Search ──────────────────────────────────────────────

    def search(
        self,
        query: Optional[str] = None,
        role: Optional[UserRole] = None,
        domain: Optional[str] = None,
        org_id: Optional[str] = None,
        auth_type: Optional[AuthType] = None,
        is_valid: Optional[bool] = None,
        source: Optional[str] = None,
        exclude_expired: bool = True,
    ) -> List[AuthSession]:
        """
        Flexible session search with multiple filters.
        
        All filters are AND-combined. None = no filter.
        """
        results = list(self._sessions.values())

        if query:
            query_lower = query.lower()
            results = [
                s for s in results
                if query_lower in s.label.lower()
                or query_lower in s.target_domain.lower()
                or query_lower in s.account.username.lower()
                or query_lower in s.account.email.lower()
                or query_lower in s.org.org_name.lower()
            ]

        if role is not None:
            results = [s for s in results if s.role == role]

        if domain:
            domain_lower = domain.lower()
            results = [
                s for s in results
                if domain_lower in s.target_domain.lower()
            ]

        if org_id:
            results = [s for s in results if s.org.org_id == org_id]

        if auth_type is not None:
            results = [s for s in results if s.auth_type == auth_type]

        if is_valid is not None:
            results = [s for s in results if s.is_valid == is_valid]

        if source:
            results = [s for s in results if s.source == source]

        if exclude_expired:
            results = [s for s in results if not s.is_expired()]

        return results

    # ── Public API: Health & Maintenance ────────────────────────────────

    def validate_session(self, session_id: str, validation_url: str) -> bool:
        """
        Validate a session by sending a request to validation_url.
        
        Uses httpx for the validation request.
        Updates session.is_valid and last_validated_at.
        """
        session = self._sessions.get(session_id)
        if not session:
            return False

        try:
            import httpx
            headers = session.build_request_headers()
            response = httpx.get(
                validation_url,
                headers=headers,
                timeout=10.0,
                follow_redirects=True,
                verify=False,
            )
            session.mark_validated(response.status_code)
            self._persist_to_sqlite(session)
            return session.is_valid
        except Exception as e:
            logger.warning(f"Validation failed for {session_id}: {e}")
            session.is_valid = False
            self._persist_to_sqlite(session)
            return False

    def remove_expired(self) -> int:
        """Remove all expired sessions. Returns count removed."""
        with self._lock:
            expired_ids = [
                sid for sid, s in self._sessions.items()
                if s.is_expired()
            ]
            for sid in expired_ids:
                session = self._sessions.pop(sid)
                self._remove_from_indexes(session)
                self._delete_from_sqlite(sid)
            return len(expired_ids)

    def remove_invalid(self) -> int:
        """Remove all sessions marked as invalid. Returns count removed."""
        with self._lock:
            invalid_ids = [
                sid for sid, s in self._sessions.items()
                if not s.is_valid
            ]
            for sid in invalid_ids:
                session = self._sessions.pop(sid)
                self._remove_from_indexes(session)
                self._delete_from_sqlite(sid)
            return len(invalid_ids)

    def health_check(self, validation_url: str) -> Dict[str, Any]:
        """
        Validate all sessions and return health report.
        
        Returns:
            {
                "total": int,
                "valid": int,
                "invalid": int,
                "expired": int,
                "results": [{session_id, label, is_valid, status_code}]
            }
        """
        results = []
        valid_count = 0
        invalid_count = 0
        expired_count = 0

        for session in list(self._sessions.values()):
            if session.is_expired():
                expired_count += 1
                results.append({
                    "session_id": session.session_id,
                    "label": session.label,
                    "role": session.role.value,
                    "is_valid": False,
                    "status_code": None,
                    "reason": "expired",
                })
                continue

            ok = self.validate_session(session.session_id, validation_url)
            if ok:
                valid_count += 1
            else:
                invalid_count += 1

            results.append({
                "session_id": session.session_id,
                "label": session.label,
                "role": session.role.value,
                "is_valid": ok,
                "status_code": session.last_validation_status,
                "reason": "validated" if ok else "validation_failed",
            })

        return {
            "total": len(self._sessions),
            "valid": valid_count,
            "invalid": invalid_count,
            "expired": expired_count,
            "results": results,
        }

    # ── Public API: Bulk operations ─────────────────────────────────────

    def add_sessions(self, sessions: List[AuthSession]) -> int:
        """Add multiple sessions. Returns count added."""
        count = 0
        for session in sessions:
            self.add_session(session)
            count += 1
        return count

    def get_all_sessions(self, exclude_expired: bool = True) -> List[AuthSession]:
        """Get all sessions."""
        sessions = list(self._sessions.values())
        if exclude_expired:
            sessions = [s for s in sessions if not s.is_expired()]
        return sessions

    def get_session_count(self) -> int:
        return len(self._sessions)

    # ── Public API: Summary ─────────────────────────────────────────────

    def to_summary(self) -> Dict[str, Any]:
        """Summary for LLM context and debugging."""
        sessions = list(self._sessions.values())
        role_counts = {}
        domain_counts = {}
        org_counts = {}
        auth_type_counts = {}

        for s in sessions:
            role_counts[s.role.value] = role_counts.get(s.role.value, 0) + 1
            domain_counts[s.target_domain] = domain_counts.get(s.target_domain, 0) + 1
            if s.org.org_id:
                org_counts[s.org.org_id] = org_counts.get(s.org.org_id, 0) + 1
            auth_type_counts[s.auth_type.value] = auth_type_counts.get(s.auth_type.value, 0) + 1

        return {
            "total_sessions": len(sessions),
            "by_role": role_counts,
            "by_domain": domain_counts,
            "by_org": org_counts,
            "by_auth_type": auth_type_counts,
            "valid_count": sum(1 for s in sessions if s.is_valid),
            "expired_count": sum(1 for s in sessions if s.is_expired()),
        }

    def to_list(self, exclude_expired: bool = True) -> List[Dict[str, Any]]:
        """Serialize all sessions to list of dicts."""
        sessions = self.get_all_sessions(exclude_expired)
        return [
            {
                "session_id": s.session_id,
                "label": s.label,
                "role": s.role.value,
                "auth_type": s.auth_type.value,
                "target_domain": s.target_domain,
                "is_valid": s.is_valid,
                "fingerprint": s.fingerprint(),
            }
            for s in sessions
        ]

    # ── Persistence ─────────────────────────────────────────────────────

    def save_to_file(self, file_path: str) -> bool:
        """Save all sessions to a JSON file."""
        try:
            data = {
                "version": "1.0.0",
                "saved_at": datetime.now(timezone.utc).isoformat(),
                "sessions": [s.to_dict() for s in self._sessions.values()],
            }
            path = Path(file_path)
            tmp_path = path.with_suffix(".tmp")
            tmp_path.write_text(json.dumps(data, indent=2, default=str))
            tmp_path.rename(path)
            logger.info(f"Saved {len(self._sessions)} sessions to {file_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to save sessions: {e}")
            return False

    def load_from_file(self, file_path: str) -> int:
        """Load sessions from a JSON file. Returns count loaded."""
        try:
            path = Path(file_path)
            if not path.exists():
                return 0
            data = json.loads(path.read_text())
            sessions = data.get("sessions", [])
            count = 0
            for s_data in sessions:
                session = AuthSession.from_dict(s_data)
                self.add_session(session)
                count += 1
            logger.info(f"Loaded {count} sessions from {file_path}")
            return count
        except Exception as e:
            logger.error(f"Failed to load sessions: {e}")
            return 0

    # ── Context manager ─────────────────────────────────────────────────

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def close(self) -> None:
        """Close SQLite connection."""
        if self._conn:
            try:
                self._conn.close()
            except Exception:
                pass
            self._conn = None

    def __repr__(self) -> str:
        return (
            f"AuthSessionStore("
            f"sessions={len(self._sessions)}, "
            f"domains={len(self._by_domain)}, "
            f"orgs={len(self._by_org)}"
            f")"
        )
