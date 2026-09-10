# TECHNICAL_DEBT.md — Dead Code and Duplicates

## Summary

- **Total dead code:** ~9,095 lines (73% of codebase)
- **Duplicate modules:** 5 modules that duplicate browser.py functionality
- **Unused packages:** 1 complete package (authcore) with 7,465 lines
- **Unused imports:** 2 dead imports in authcore

---

## Dead Modules (DELETE)

### 1. `auth/authcore/` — 7,465 lines

**Status:** COMPLETELY UNUSED. Zero imports from the main researcher.

**Why dead:** Was built as a standalone library. Never wired into the researcher.

**Contains:**
- `session.py` (940 lines): Production-quality AuthSession, CookieJar, JWTToken, CSRFToken
- `store.py` (778 lines): SQLite-backed session store
- `auth_client.py` (269 lines): HTTP client with auth injection
- `object_inventory.py` (922 lines): Object tracking for IDOR detection
- `idor_tester.py` (826 lines): Cross-user IDOR testing
- `boundary_tester.py` (622 lines): Account boundary testing
- `role_tester.py` (597 lines): Role-based access testing
- `graphql_tester.py` (840 lines): GraphQL auth testing
- `multi_org_tester.py` (551 lines): Multi-org isolation testing
- `tests/` (2,033 lines): Comprehensive test suite

**Decision:** INTEGRATE into researcher (replaces tools/auth.py and tools/replay.py auth testing)

---

### 2. `reasoning_trace.py` — 114 lines

**Status:** Imported and called, but adds zero value to finding vulnerabilities.

**Why dead:** Pure debugging overhead. `get_summary()` is printed to console every 5 iterations but never read by the LLM or any other module.

**Decision:** DELETE

---

### 3. `evidence_validator.py` — 164 lines

**Status:** Imported by researcher.py but NEVER CALLED. `self.evidence_validator` is created but no method is ever invoked.

**Why dead:** Was planned for finding validation but never integrated into the hunting loop.

**Decision:** DELETE

---

### 4. `browser_intel.py` — 450 lines

**Status:** Called in Stage 1 (`full_scan()`), but its functionality is duplicated by browser.py.

**Why duplicate:**
- `_scan_api_endpoints()` → duplicates `browser.get_api_endpoints()`
- `_scan_storage()` → duplicates `browser.get_tokens()`
- `_scan_ui_elements()` → duplicates `visual_explorer.explore()`
- `_scan_tokens()` → duplicates `browser.get_tokens()`

**Impact:** Adds 450 lines of indirection. The scan result is serialized to JSON and passed to the LLM, which could read the same data directly from browser.py.

**Decision:** DELETE — inline useful parts into researcher.py

---

### 5. `js_intel.py` — 301 lines

**Status:** Called in Stage 1 (`analyze_page()`), but its functionality is duplicated by browser.py's new methods.

**Why duplicate:**
- `_analyze_script()` regex patterns → duplicate of `extract_endpoints_from_js()`
- `_analyze_runtime()` framework detection → useful but should be in browser.py
- `_analyze_network_patterns()` → duplicate of `extract_api_from_network_entries()`

**Decision:** DELETE — inline framework detection into browser.py

---

### 6. `visual_explorer.py` — 162 lines

**Status:** Called in Stage 1 (`explore()`), but its functionality is duplicated by browser.py.

**Why duplicate:**
- Button/form/navigation extraction → duplicates `get_all_forms()` + DOM queries
- Table/upload detection → useful but should be in browser.py

**Decision:** DELETE — inline useful parts into browser.py

---

## Duplicate Code (within modules)

### 7. `tools/auth.py` (204 lines) vs `auth/authcore/session.py` (940 lines)

**Overlap:** Both implement session management, cookie handling, auth headers.

**auth.py has:**
- Basic AuthSession dataclass
- AuthManager with session creation/rotation
- Login via HTTP
- Credential storage

**authcore/session.py has:**
- Production-quality AuthSession with CookieJar, HeaderSet, JWTToken, CSRFToken
- Role-based access (UserRole enum with levels)
- Multiple auth types (cookie, bearer, JWT, API key, basic)
- Validation, fingerprinting, serialization

**Decision:** DELETE tools/auth.py, use authcore instead

---

### 8. `tools/replay.py` (344 lines) vs `auth/authcore/idor_tester.py` (826 lines)

**Overlap:** Both implement request mutation and IDOR testing.

**replay.py has:**
- 11 replay modes (baseline, no_auth, no_csrf, method_override, idor, etc.)
- Response diffing (status, length, content)
- GraphQL introspection

**idor_tester.py has:**
- Cross-user IDOR testing with object inventory
- Response fingerprinting
- Ownership bypass detection
- Finding generation

**Decision:** INTEGRATE idor_tester.py to replace replay.py's IDOR mode

---

### 9. BusinessObject duplication

**memory.py:** `BusinessObject` dataclass (lines 106-129)
**app_model.py:** `BusinessObject` dataclass (lines 48-75)

Different fields, same name, used in different contexts.

**Decision:** Consolidate into app_model.BusinessObject

---

### 10. get_idor_candidates() duplication

**memory.py:** `get_idor_candidates()` (lines 319-332)
**app_model.py:** `get_idor_candidates()` (lines 174-187)

Same logic, different data sources.

**Decision:** Keep app_model version (richer data), delete memory version

---

## Unused Methods (in live modules)

### browser.py
| Method | Lines | Why Unused |
|---|---|---|
| `extract_next_data()` | 35 | Never called from researcher |
| `extract_endpoints_from_js()` | 70 | Never called from researcher |
| `extract_api_from_network_entries()` | 25 | Never called from researcher |
| `extract_form_endpoints()` | 25 | Never called from researcher |
| `discover_admin_paths()` | 60 | Never called from researcher |

**Total:** 215 lines of useful code that is never executed.

### auth.py
| Method | Lines | Why Unused |
|---|---|---|
| `create_all_sessions()` | 10 | Never called from researcher |
| `rotate_sessions()` | 10 | Never called from researcher |

### replay.py
| Method | Lines | Why Unused |
|---|---|---|
| `graphql_introspect()` | 25 | Never called from researcher |
| `graphql_test_batching()` | 15 | Never called from researcher |
| `graphql_test_field_suggestion()` | 15 | Never called from researcher |

---

## Unused Imports (in live modules)

| File | Import | Line |
|---|---|---|
| researcher.py | `from sentinel_v2.reasoning_trace import ReasoningTrace` | 35 |
| researcher.py | `from sentinel_v2.evidence_validator import EvidenceValidator` | 36 |
| authcore/boundary_tester.py | `from authcore.store import AuthSessionStore` | 28 |

---

## Cleanup Summary

| Category | Lines to Delete | Lines to Integrate | Net Reduction |
|---|---|---|---|
| authcore (standalone) | 0 | 7,465 (integrate) | -7,465 if integrated |
| reasoning_trace.py | 114 | 0 | -114 |
| evidence_validator.py | 164 | 0 | -164 |
| browser_intel.py | 450 | 0 | -450 |
| js_intel.py | 301 | 0 | -301 |
| visual_explorer.py | 162 | 0 | -162 |
| tools/auth.py | 204 | 0 | -204 |
| Unused methods | 0 | 0 | -295 |
| **Total** | **1,395** | **7,465** | **-8,860** |

After cleanup: ~3,525 lines (down from 12,385)
