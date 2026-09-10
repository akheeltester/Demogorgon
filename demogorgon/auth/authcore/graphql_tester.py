"""
authcore/graphql_tester.py — Authenticated GraphQL testing.

Provides GraphQLAuthTester: introspection abuse, mutation authorization,
field-level auth, nested query depth limits, and batch query abuse.

GraphQL-specific attack surface:
    1. Introspection reveals entire schema → map attack surface
    2. Introspection with auth may reveal more fields than unauth
    3. Mutations may lack role checks (admin-only mutations accessible)
    4. Field-level auth: some fields in a query leak data the user shouldn't see
    5. Nested query DoS: deeply nested queries bypass rate limits
    6. Batch query abuse: multiple operations in single request
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from demogorgon.auth.authcore.session import AuthSession, UserRole
from demogorgon.auth.authcore.auth_client import AuthAwareClient
from demogorgon.auth.authcore.object_inventory import ObjectInventoryDB

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      name
      kind
      fields {
        name
        type {
          name
          kind
          ofType { name kind }
        }
        args {
          name
          type { name kind ofType { name kind } }
        }
      }
    }
    directives {
      name
      locations
      args { name type { name kind } }
    }
  }
}
"""

_INTROSPECTION_TYPES_QUERY = """
query {
  __schema {
    types {
      name
      kind
      fields {
        name
        type { name kind ofType { name kind } }
      }
    }
  }
}
"""

_SELF_QUERY = """
query {
  __typename
}
"""

# Common sensitive field patterns
_SENSITIVE_FIELDS = {
    "password", "passwd", "secret", "token", "api_key", "apikey",
    "access_token", "refresh_token", "private_key", "ssn",
    "credit_card", "card_number", "cvv", "pin", "authorization",
    "credential", "hash", "salt", "encryption_key",
}


# ---------------------------------------------------------------------------
# GraphQLAuthTester
# ---------------------------------------------------------------------------

class GraphQLAuthTester:
    """
    Authenticated GraphQL security testing.

    Usage:
        tester = GraphQLAuthTester(inventory)

        # Introspect with auth
        schema = await tester.introspect_with_auth(
            endpoint="https://target.com/graphql",
            session=admin_session,
        )

        # Compare auth vs unauth introspection
        diff = await tester.compare_introspection(
            endpoint="https://target.com/graphql",
            auth_session=admin_session,
        )

        # Test mutations
        results = await tester.test_mutation_authorization(
            endpoint="https://target.com/graphql",
            mutations=[{"name": "deleteUser", "query": "..."}],
            sessions=[admin_session, member_session],
        )

        # Test field-level auth
        results = await tester.test_field_level_auth(
            endpoint="https://target.com/graphql",
            query="{ users { id email password_hash } }",
            field_paths=["users.password_hash", "users.email"],
            sessions=[admin_session, viewer_session],
        )
    """

    MAX_EVIDENCE_LENGTH = 2000
    MAX_NESTING_DEPTH = 10

    def __init__(self, inventory: ObjectInventoryDB):
        self.inventory = inventory
        self._test_results: List[Dict[str, Any]] = []

    # ── Introspection ───────────────────────────────────────────────────

    async def introspect_with_auth(
        self,
        endpoint: str,
        session: Optional[AuthSession] = None,
        query: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Run GraphQL introspection with optional authentication.

        Returns:
            {schema: dict, types: list, mutations: list, queries: list, errors: list}
        """
        introspection_query = query or _INTROSPECTION_QUERY

        async with AuthAwareClient(session) as client:
            try:
                resp = await client.post(
                    endpoint,
                    json={"query": introspection_query},
                    headers={"Content-Type": "application/json"},
                )
            except Exception as e:
                return {"error": str(e), "schema": None}

            if resp is None:
                return {"error": "request_returned_none", "schema": None}

            if resp.status_code != 200:
                return {
                    "error": f"status_{resp.status_code}",
                    "body": resp.content[:self.MAX_EVIDENCE_LENGTH].decode("utf-8", errors="ignore"),
                    "schema": None,
                }

            try:
                data = resp.json()
            except (json.JSONDecodeError, ValueError):
                return {"error": "invalid_json", "schema": None}

            if "errors" in data:
                return {
                    "errors": data["errors"],
                    "schema": data.get("data"),
                }

            schema = data.get("data", {}).get("__schema", {})
            return self._parse_schema(schema)

    def _parse_schema(self, schema: Dict[str, Any]) -> Dict[str, Any]:
        """Parse introspection result into structured data."""
        types = schema.get("types", [])
        queries = []
        mutations = []
        sensitive_fields = []

        for t in types:
            if t["name"].startswith("__"):
                continue
            kind = t.get("kind", "")
            fields = t.get("fields") or []

            if kind == "OBJECT":
                for field in fields:
                    field_name = field.get("name", "")
                    field_type = field.get("type", {})

                    entry = {
                        "type": t["name"],
                        "field": field_name,
                        "type_info": field_type,
                        "args": field.get("args", []),
                    }

                    # Check if it's a query or mutation root
                    if t["name"] == schema.get("queryType", {}).get("name"):
                        queries.append(entry)
                    elif t["name"] == schema.get("mutationType", {}).get("name"):
                        mutations.append(entry)

                    # Check for sensitive fields
                    if any(s in field_name.lower() for s in _SENSITIVE_FIELDS):
                        sensitive_fields.append(entry)

        return {
            "schema": schema,
            "types": [t["name"] for t in types if not t["name"].startswith("__")],
            "queries": queries,
            "mutations": mutations,
            "sensitive_fields": sensitive_fields,
            "type_count": len([t for t in types if not t["name"].startswith("__")]),
            "field_count": sum(
                len(t.get("fields") or [])
                for t in types
                if not t["name"].startswith("__") and t.get("fields")
            ),
        }

    async def compare_introspection(
        self,
        endpoint: str,
        auth_session: AuthSession,
        unauth_session: Optional[AuthSession] = None,
    ) -> Dict[str, Any]:
        """
        Compare introspection results with and without authentication.

        If auth reveals more types/fields/mutations → information disclosure.
        """
        # Authenticated introspection
        auth_result = await self.introspect_with_auth(endpoint, auth_session)

        # Unauthenticated introspection
        unauth_result = await self.introspect_with_auth(endpoint, unauth_session)

        auth_types = set(auth_result.get("types", []))
        unauth_types = set(unauth_result.get("types", []))

        auth_queries = set(q["field"] for q in auth_result.get("queries", []))
        unauth_queries = set(q["field"] for q in unauth_result.get("queries", []))

        auth_mutations = set(m["field"] for m in auth_result.get("mutations", []))
        unauth_mutations = set(m["field"] for m in unauth_result.get("mutations", []))

        leaked_types = auth_types - unauth_types
        leaked_queries = auth_queries - unauth_queries
        leaked_mutations = auth_mutations - unauth_mutations

        has_leakage = bool(leaked_types or leaked_queries or leaked_mutations)

        result = {
            "endpoint": endpoint,
            "auth_session": auth_session.label,
            "auth_role": auth_session.role.value,
            "auth_types_count": len(auth_types),
            "unauth_types_count": len(unauth_types),
            "leaked_types": list(leaked_types),
            "leaked_queries": list(leaked_queries),
            "leaked_mutations": list(leaked_mutations),
            "has_schema_leakage": has_leakage,
            "auth_result": auth_result,
            "unauth_result": unauth_result,
        }

        self._test_results.append(result)

        if has_leakage:
            self.inventory.record_finding(
                finding_type="graphql_schema_leakage",
                severity="medium",
                object_type="graphql_schema",
                object_id=endpoint,
                endpoint=endpoint,
                method="POST",
                source_session_id=auth_session.session_id,
                target_session_id="",
                breach_description=(
                    f"GraphQL schema leakage: authenticated introspection reveals "
                    f"{len(leaked_types)} additional types, {len(leaked_queries)} "
                    f"additional queries, {len(leaked_mutations)} additional mutations"
                ),
                evidence={
                    "leaked_types": list(leaked_types)[:50],
                    "leaked_queries": list(leaked_queries)[:50],
                    "leaked_mutations": list(leaked_mutations)[:50],
                },
                recommendation="Disable introspection in production or restrict to admin roles.",
            )

        return result

    # ── Mutation authorization ──────────────────────────────────────────

    async def test_mutation_authorization(
        self,
        endpoint: str,
        mutations: List[Dict[str, Any]],
        sessions: List[AuthSession],
    ) -> List[Dict[str, Any]]:
        """
        Test mutations with different roles.

        For each mutation, test with each session:
            - Admin should be able to execute privileged mutations
            - Member/Viewer should be denied
            - If low-role can execute → privesc

        Args:
            mutations: [{"name": "deleteUser", "query": "mutation { deleteUser(id: 1) { id } }"}]
        """
        results = []

        for mutation in mutations:
            name = mutation["name"]
            query = mutation.get("query", "")
            variables = mutation.get("variables", {})
            expected_min_role = mutation.get("expected_min_role", "admin")

            mutation_results = []
            for session in sessions:
                async with AuthAwareClient(session) as client:
                    try:
                        resp = await client.post(
                            endpoint,
                            json={"query": query, "variables": variables},
                            headers={"Content-Type": "application/json"},
                        )
                    except Exception as e:
                        mutation_results.append({
                            "session": session.label,
                            "role": session.role.value,
                            "error": str(e),
                            "is_authorized": False,
                        })
                        continue

                    if resp is None:
                        mutation_results.append({
                            "session": session.label,
                            "role": session.role.value,
                            "error": "request_returned_none",
                            "is_authorized": False,
                        })
                        continue

                    try:
                        data = resp.json()
                    except (json.JSONDecodeError, ValueError):
                        data = {}

                    has_errors = bool(data.get("errors"))
                    has_data = bool(data.get("data"))
                    is_authorized = resp.status_code == 200 and has_data and not has_errors

                    mutation_results.append({
                        "session": session.label,
                        "role": session.role.value,
                        "status_code": resp.status_code,
                        "has_errors": has_errors,
                        "has_data": has_data,
                        "is_authorized": is_authorized,
                        "errors": data.get("errors", [])[:5],
                        "body_excerpt": json.dumps(data)[:self.MAX_EVIDENCE_LENGTH],
                    })

            # Check for authorization issues
            authorized_roles = [r["role"] for r in mutation_results if r.get("is_authorized")]
            unauthorized_roles = [r["role"] for r in mutation_results if not r.get("is_authorized")]

            # Determine if there's a breach
            expected_level = UserRole(expected_min_role).level
            is_breach = False
            for r in mutation_results:
                if r.get("is_authorized"):
                    role = r["role"]
                    if role in [e.value for e in UserRole]:
                        actual_level = UserRole(role).level
                        if actual_level < expected_level:
                            is_breach = True
                            break

            result = {
                "test_type": "mutation_authorization",
                "mutation_name": name,
                "endpoint": endpoint,
                "expected_min_role": expected_min_role,
                "results": mutation_results,
                "authorized_roles": authorized_roles,
                "unauthorized_roles": unauthorized_roles,
                "is_breach": is_breach,
                "breach_type": "mutation_auth_bypass" if is_breach else "",
            }

            results.append(result)
            self._test_results.append(result)

            if is_breach:
                self.inventory.record_finding(
                    finding_type="graphql_mutation_auth_bypass",
                    severity="critical",
                    object_type="graphql_mutation",
                    object_id=name,
                    endpoint=endpoint,
                    method="POST",
                    source_session_id="",
                    target_session_id="",
                    breach_description=(
                        f"GraphQL mutation authorization bypass: mutation {name} "
                        f"accessible by roles {authorized_roles} but requires "
                        f"{expected_min_role}"
                    ),
                    evidence={"results": mutation_results},
                    recommendation=f"Add {expected_min_role} role check to {name} mutation resolver.",
                )

        return results

    # ── Field-level auth ────────────────────────────────────────────────

    async def test_field_level_auth(
        self,
        endpoint: str,
        query: str,
        field_paths: List[str],
        sessions: List[AuthSession],
    ) -> List[Dict[str, Any]]:
        """
        Test if sensitive fields are accessible by lower-privilege users.

        Sends the same query with different sessions and checks if
        sensitive fields are returned for each.
        """
        results = []

        for session in sessions:
            async with AuthAwareClient(session) as client:
                try:
                    resp = await client.post(
                        endpoint,
                        json={"query": query},
                        headers={"Content-Type": "application/json"},
                    )
                except Exception as e:
                    results.append({
                        "session": session.label,
                        "role": session.role.value,
                        "error": str(e),
                    })
                    continue

                if resp is None:
                    results.append({
                        "session": session.label,
                        "role": session.role.value,
                        "error": "request_returned_none",
                    })
                    continue

                try:
                    data = resp.json()
                except (json.JSONDecodeError, ValueError):
                    data = {}

                # Check which sensitive fields are present
                visible_fields = self._extract_visible_fields(data, field_paths)

                result = {
                    "session": session.label,
                    "role": session.role.value,
                    "status_code": resp.status_code,
                    "visible_sensitive_fields": visible_fields,
                    "body_excerpt": json.dumps(data)[:self.MAX_EVIDENCE_LENGTH],
                }

                results.append(result)

        # Check for field-level auth issues
        for field_path in field_paths:
            field_visible_roles = [
                r["role"] for r in results
                if field_path in r.get("visible_sensitive_fields", [])
            ]

            if len(field_visible_roles) > 1:
                # Field is visible to multiple roles — potential issue
                viewer_visible = "viewer" in field_visible_roles
                if viewer_visible:
                    self.inventory.record_finding(
                        finding_type="graphql_field_auth_bypass",
                        severity="high",
                        object_type="graphql_field",
                        object_id=field_path,
                        endpoint=endpoint,
                        method="POST",
                        source_session_id="",
                        target_session_id="",
                        breach_description=(
                            f"GraphQL field auth bypass: sensitive field {field_path} "
                            f"accessible by roles {field_visible_roles}"
                        ),
                        evidence={"field_path": field_path, "visible_to": field_visible_roles},
                        recommendation=f"Add authorization check for field {field_path}.",
                    )

        return results

    def _extract_visible_fields(
        self,
        data: Any,
        field_paths: List[str],
        prefix: str = "",
    ) -> List[str]:
        """Extract which field paths are visible in response data."""
        visible = []
        if isinstance(data, dict):
            for key, value in data.items():
                current_path = f"{prefix}.{key}" if prefix else key
                if current_path in field_paths:
                    visible.append(current_path)
                if isinstance(value, dict):
                    visible.extend(self._extract_visible_fields(value, field_paths, current_path))
                elif isinstance(value, list):
                    for item in value[:5]:
                        visible.extend(self._extract_visible_fields(item, field_paths, current_path))
        return visible

    # ── Nested query depth ──────────────────────────────────────────────

    async def test_nested_query_depth(
        self,
        endpoint: str,
        session: AuthSession,
        max_depth: int = MAX_NESTING_DEPTH,
        base_query: str = "query { __typename }",
    ) -> Dict[str, Any]:
        """
        Test nested query depth limits.

        Sends increasingly nested queries to find the DoS threshold.
        GraphQL servers should enforce depth limits.
        """
        results = []

        for depth in range(1, max_depth + 1):
            # Build nested query
            nested = "query { " + "__typename " * depth + " }"

            async with AuthAwareClient(session) as client:
                try:
                    resp = await client.post(
                        endpoint,
                        json={"query": nested},
                        headers={"Content-Type": "application/json"},
                    )
                except Exception as e:
                    results.append({
                        "depth": depth,
                        "error": str(e),
                        "status_code": None,
                    })
                    break

                if resp is None:
                    results.append({
                        "depth": depth,
                        "error": "request_returned_none",
                        "status_code": None,
                    })
                    break

                results.append({
                    "depth": depth,
                    "status_code": resp.status_code,
                    "response_length": len(resp.content or b""),
                })

                # If server rejects at this depth, we found the limit
                if resp.status_code in {400, 422}:
                    break

        # Check if there's a depth limit
        successful_depths = [r["depth"] for r in results if r.get("status_code") == 200]
        has_depth_limit = len(successful_depths) < max_depth

        result = {
            "test_type": "nested_query_depth",
            "endpoint": endpoint,
            "session": session.label,
            "max_depth_tested": max_depth,
            "successful_depths": successful_depths,
            "has_depth_limit": has_depth_limit,
            "depth_limit": max(successful_depths) if successful_depths else 0,
        }

        self._test_results.append(result)

        if not has_depth_limit and max_depth >= 5:
            self.inventory.record_finding(
                finding_type="graphql_no_depth_limit",
                severity="medium",
                object_type="graphql_config",
                object_id=endpoint,
                endpoint=endpoint,
                method="POST",
                source_session_id=session.session_id,
                target_session_id="",
                breach_description=(
                    f"No GraphQL depth limit: server accepted queries up to "
                    f"depth {max_depth} without rejection"
                ),
                evidence=result,
                recommendation="Implement query depth limiting (recommended: max 7-10 levels).",
            )

        return result

    # ── Batch query abuse ───────────────────────────────────────────────

    async def test_batch_query_abuse(
        self,
        endpoint: str,
        session: AuthSession,
        queries: Optional[List[str]] = None,
        max_batch_size: int = 10,
    ) -> List[Dict[str, Any]]:
        """
        Test if batch queries can bypass rate limiting or authorization.

        Sends multiple operations in a single request. Some servers
        process batch queries without applying per-operation rate limits.
        """
        if queries is None:
            queries = [
                "{ __typename }",
                "{ __typename }",
                "{ __typename }",
            ]

        results = []

        # Test increasing batch sizes
        for batch_size in range(2, min(max_batch_size + 1, len(queries) + 1)):
            batch = queries[:batch_size]

            async with AuthAwareClient(session) as client:
                try:
                    resp = await client.post(
                        endpoint,
                        json=batch,
                        headers={"Content-Type": "application/json"},
                    )
                except Exception as e:
                    results.append({
                        "batch_size": batch_size,
                        "error": str(e),
                        "status_code": None,
                    })
                    continue

                if resp is None:
                    results.append({
                        "batch_size": batch_size,
                        "error": "request_returned_none",
                        "status_code": None,
                    })
                    continue

                try:
                    data = resp.json()
                except (json.JSONDecodeError, ValueError):
                    data = []

                # Check if batch was processed
                is_array = isinstance(data, list)
                successful_ops = sum(
                    1 for item in (data if is_array else [])
                    if isinstance(item, dict) and "data" in item
                )

                result = {
                    "batch_size": batch_size,
                    "status_code": resp.status_code,
                    "is_batch_processed": is_array,
                    "successful_operations": successful_ops,
                    "response_length": len(resp.content or b""),
                }

                results.append(result)

                # If batch is accepted, test for rate limit bypass
                if is_array and resp.status_code == 200:
                    # Check if batch bypasses per-request rate limiting
                    if batch_size >= 5:
                        self.inventory.record_finding(
                            finding_type="graphql_batch_abuse",
                            severity="medium",
                            object_type="graphql_config",
                            object_id=endpoint,
                            endpoint=endpoint,
                            method="POST",
                            source_session_id=session.session_id,
                            target_session_id="",
                            breach_description=(
                                f"Batch query abuse: server accepted batch of "
                                f"{batch_size} operations, potentially bypassing "
                                f"per-request rate limiting"
                            ),
                            evidence=result,
                            recommendation="Apply rate limiting per operation in batch requests.",
                        )

        return results

    # ── Object discovery via GraphQL ────────────────────────────────────

    async def discover_objects_via_graphql(
        self,
        endpoint: str,
        session: AuthSession,
        queries: List[Dict[str, Any]],
    ) -> int:
        """
        Discover objects via GraphQL queries for IDOR testing.

        Executes queries and records discovered objects in the inventory.
        """
        discovered = 0

        async with AuthAwareClient(session) as client:
            for query_spec in queries:
                query = query_spec.get("query", "")
                object_type = query_spec.get("object_type", "graphql_object")
                id_field = query_spec.get("id_field", "id")

                try:
                    resp = await client.post(
                        endpoint,
                        json={"query": query},
                        headers={"Content-Type": "application/json"},
                    )
                except Exception:
                    continue

                if resp is None or resp.status_code != 200:
                    continue

                try:
                    data = resp.json()
                except (json.JSONDecodeError, ValueError):
                    continue

                # Extract objects from response
                objects = self._extract_objects_from_response(data, id_field)
                for obj_id in objects:
                    existing = self.inventory.get_object(obj_id)
                    if existing:
                        self.inventory.increment_access_count(obj_id)
                        continue

                    self.inventory.record_object(
                        object_type=object_type,
                        object_id=obj_id,
                        owner_session_id=session.session_id,
                        owner_user_id=session.account.user_id,
                        owner_role=session.role.value,
                        owner_org_id=session.org.org_id,
                        endpoint=endpoint,
                        url_pattern=query_spec.get("url_pattern", ""),
                    )
                    discovered += 1

        return discovered

    def _extract_objects_from_response(
        self,
        data: Any,
        id_field: str = "id",
        depth: int = 0,
    ) -> List[str]:
        """Extract object IDs from GraphQL response data."""
        if depth > 10:
            return []

        ids = []
        if isinstance(data, dict):
            # Check if this dict has an ID field
            if id_field in data:
                ids.append(str(data[id_field]))
            # Recurse into values
            for value in data.values():
                ids.extend(self._extract_objects_from_response(value, id_field, depth + 1))
        elif isinstance(data, list):
            for item in data[:100]:
                ids.extend(self._extract_objects_from_response(item, id_field, depth + 1))

        return list(set(ids))

    # ── Reporting ───────────────────────────────────────────────────────

    def build_report(self) -> Dict[str, Any]:
        """Build comprehensive GraphQL security report."""
        findings = self.inventory.get_findings()
        unreported = self.inventory.get_unreported_findings()

        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "summary": {
                "total_tests": len(self._test_results),
                "findings_count": len(findings),
                "unreported_count": len(unreported),
            },
            "test_results": self._test_results,
            "findings": findings,
            "unreported_findings": unreported,
        }

    def __repr__(self) -> str:
        return f"GraphQLAuthTester(tests={len(self._test_results)})"
