# MODULE_AUDIT.md — Demogorgon Capability Audit

## Executive Summary

Demogorgon has **32 Python files** totaling **~12,385 lines**.
- **Core demogorgon package:** 14 files, ~4,920 lines
- **auth/authcore sub-package:** 18 files, ~7,465 lines
- **Critical finding:** The authcore package is completely decoupled from the core researcher. Zero imports between them. 7,465 lines of production-quality auth testing code are never used.

---

## Module-by-Module Audit

### 1. `researcher.py` (1,421 lines) — THE BRAIN

| Attribute | Value |
|---|---|
| **Purpose** | Orchestrate the entire hunt: 8-stage pipeline from product understanding to intelligent testing |
| **Dependencies** | memory, app_model, http_client, auth, reasoning_trace, evidence_validator, browser, replay, browser_intel, js_intel, visual_explorer |
| **Called by** | main.py |
| **Integration** | FULL — all methods are wired and called |
| **Dead code** | `self.stage` attribute (set never read) |
| **Deterministic?** | No — LLM-dependent for all decisions |
| **Finds vulns?** | Only if LLM makes good choices AND execution pipeline works |
| **Decision** | **KEEP** — core orchestrator, needs fixes not rewrite |

**Critical issues:**
- LLM is the sole decision-maker for endpoint selection, action selection, and hypothesis generation
- `_build_hunting_context()` duplicates `memory.build_context_for_llm()` (which was deleted)
- No deterministic fallback when LLM fails to produce valid JSON
- `_act_replay()` has 11 replay modes but the LLM must choose the right one

---

### 2. `llm_client.py` (184 lines) — LLM INTERFACE

| Attribute | Value |
|---|---|
| **Purpose** | OpenRouter-compatible LLM client with model rotation and retry |
| **Dependencies** | openai (AsyncOpenAI), .env config |
| **Called by** | researcher.py |
| **Integration** | FULL |
| **Dead code** | None |
| **Deterministic?** | N/A — wraps non-deterministic API |
| **Finds vulns?** | Enables LLM decisions |
| **Decision** | **KEEP** — clean, minimal, works |

**Issues:**
- No streaming support (not critical)
- No token counting (could cause context overflow)
- `response_format` parameter added but models may not support it

---

### 3. `memory.py` (423 lines) — WORKING MEMORY

| Attribute | Value |
|---|---|
| **Purpose** | Store endpoints, hypotheses, findings, observations, business objects, evidence |
| **Dependencies** | None (leaf module) |
| **Called by** | researcher.py |
| **Integration** | FULL |
| **Dead code** | None after cleanup |
| **Deterministic?** | Yes — pure data storage |
| **Finds vulns?** | Indirectly — stores evidence for findings |
| **Decision** | **KEEP** — solid data layer |

**Issues:**
- `BusinessObject` in memory.py duplicates `BusinessObject` in app_model.py (different dataclasses)
- `get_idor_candidates()` exists in both memory.py and app_model.py
- No deduplication of endpoints (same URL with different params stored separately)

---

### 4. `app_model.py` (286 lines) — APPLICATION UNDERSTANDING

| Attribute | Value |
|---|---|
| **Purpose** | Build structured model: product type, roles, business objects, workflows, trust boundaries, attack surface, attack opportunities |
| **Dependencies** | None (leaf module) |
| **Called by** | researcher.py |
| **Integration** | FULL |
| **Dead code** | None |
| **Deterministic?** | Data structure only — LLM populates it |
| **Finds vulns?** | Directly — `attack_opportunities` drives testing |
| **Decision** | **KEEP** — well-structured, enables targeted testing |

**Issues:**
- All populated by LLM, not by deterministic analysis
- `get_summary()` produces 50+ line strings that consume LLM context
- `to_dict()` and `save()` are only called at end of hunt

---

### 5. `tools/browser.py` (712 lines) — BROWSER AUTOMATION

| Attribute | Value |
|---|---|
| **Purpose** | Persistent Playwright session with auto-capture of requests, responses, tokens, storage |
| **Dependencies** | playwright |
| **Called by** | researcher.py (via `_act_browser()`) |
| **Integration** | PARTIAL — many methods added but not all called from researcher |
| **Dead code** | `get_captured_responses()` — never called |
| **Deterministic?** | Yes — browser operations are deterministic |
| **Finds vulns?** | Enables discovery — captures endpoints, tokens, forms |
| **Decision** | **KEEP** — strongest module, needs tighter integration |

**Critical issues:**
- `extract_next_data()`, `extract_endpoints_from_js()`, `extract_api_from_network_entries()`, `extract_form_endpoints()`, `discover_admin_paths()` — ALL added but NEVER called from researcher.py
- The researcher uses `browser_intel.full_scan()` instead of these deterministic methods
- `get_api_endpoints()` only returns XHR/fetch — misses JS-embedded URLs
- No page interaction recording (click sequences, form submissions)

---

### 6. `tools/http_client.py` (121 lines) — HTTP CLIENT

| Attribute | Value |
|---|---|
| **Purpose** | Async HTTP with rate limiting, proxy, auth injection |
| **Dependencies** | httpx |
| **Called by** | researcher.py (via `_act_http()`), replay.py |
| **Integration** | FULL |
| **Dead code** | None after cleanup |
| **Deterministic?** | Yes |
| **Finds vulns?** | Executes HTTP requests |
| **Decision** | **KEEP** — clean, minimal |

**Issues:**
- Returns `{"status_code": 0}` on error instead of raising — caller must check
- No retry logic for transient failures
- No connection pooling optimization

---

### 7. `tools/replay.py` (344 lines) — HTTP REPLAY

| Attribute | Value |
|---|---|
| **Purpose** | Replay captured requests with mutations (auth bypass, CSRF, IDOR, method override, etc.) |
| **Dependencies** | http_client |
| **Called by** | researcher.py (via `_act_replay()`) |
| **Integration** | PARTIAL — 11 modes exist, LLM must choose |
| **Dead code** | `graphql_introspect()`, `graphql_test_batching()`, `graphql_test_field_suggestion()` — never called |
| **Deterministic?** | Yes — mutations are deterministic |
| **Finds vulns?** | Yes — replays with mutations to detect auth bypass, IDOR, etc. |
| **Decision** | **KEEP** — powerful, needs better integration |

**Issues:**
- GraphQL methods added but never wired into researcher
- `diff_responses()` compares status/length/content but doesn't compare timing
- `full_replay_analysis()` only runs 3 mutation types (auth, CSRF, method override)
- No automated "replay everything" mode

---

### 8. `tools/auth.py` (204 lines) — AUTH MANAGER

| Attribute | Value |
|---|---|
| **Purpose** | Multi-session auth management, credential storage, session rotation |
| **Dependencies** | httpx (for login) |
| **Called by** | researcher.py |
| **Integration** | PARTIAL — `create_all_sessions()` and `rotate_sessions()` never called |
| **Dead code** | `create_all_sessions()`, `rotate_sessions()` — never called from researcher |
| **Deterministic?** | Yes |
| **Finds vulns?** | Enables multi-user testing |
| **Decision** | **KEEP but simplify** — overlaps with authcore |

**Critical issue:**
- `auth.py` (204 lines) and `authcore/session.py` (940 lines) + `authcore/store.py` (778 lines) implement overlapping functionality
- The researcher uses `auth.py`, never touches `authcore`
- `authcore` is a complete, production-quality auth system that is completely wasted

---

### 9. `reasoning_trace.py` (114 lines) — REASONING LOG

| Attribute | Value |
|---|---|
| **Purpose** | Log researcher's reasoning steps for debugging |
| **Dependencies** | None |
| **Called by** | researcher.py |
| **Integration** | FULL |
| **Dead code** | None |
| **Deterministic?** | Yes — logging only |
| **Finds vulns?** | No — debugging aid |
| **Decision** | **DELETE** — adds no value to finding vulns, consumes context |

**Issues:**
- `get_summary()` is called every 5 iterations and printed to console
- Never read by the LLM or any other module
- Pure debugging overhead

---

### 10. `evidence_validator.py` (164 lines) — EVIDENCE VALIDATION

| Attribute | Value |
|---|---|
| **Purpose** | Validate findings before reporting (reproduction, independence, impact, false positive check) |
| **Dependencies** | None |
| **Called by** | researcher.py (imported but NEVER called) |
| **Integration** | **NOT INTEGRATED** |
| **Dead code** | Entire module — imported, never used |
| **Deterministic?** | Yes — rule-based validation |
| **Finds vulns?** | Could reduce false positives |
| **Decision** | **DELETE** — never called, adds complexity |

---

### 11. `browser_intel.py` (450 lines) — BROWSER INTELLIGENCE

| Attribute | Value |
|---|---|
| **Purpose** | Deep browser scanning: DOM, UI elements, API endpoints, JS state, tokens, storage |
| **Dependencies** | browser (composition) |
| **Called by** | researcher.py (Stage 1 only) |
| **Integration** | PARTIAL — only `full_scan()` called, results partially used |
| **Dead code** | `get_summary()` — never called |
| **Deterministic?** | Yes — DOM/JS analysis |
| **Finds vulns?** | Discovers endpoints, tokens, storage items |
| **Decision** | **DELETE** — duplicate of browser.py capabilities, adds indirection |

**Issues:**
- `_scan_api_endpoints()` is a static method that duplicates `browser.get_api_endpoints()`
- `_scan_storage()` duplicates `browser.get_tokens()`
- `_scan_ui_elements()` duplicates `visual_explorer.explore()`
- The `full_scan()` result is passed to LLM but much of it is redundant with what browser.py already provides

---

### 12. `js_intel.py` (301 lines) — JS INTELLIGENCE

| Attribute | Value |
|---|---|
| **Purpose** | Analyze JavaScript: framework detection, API patterns, feature flags, env vars |
| **Dependencies** | browser (composition) |
| **Called by** | researcher.py (Stage 1 only) |
| **Integration** | PARTIAL — `analyze_page()` called, results passed to LLM |
| **Dead code** | `get_summary()` — never called |
| **Deterministic?** | Yes — regex-based JS analysis |
| **Finds vulns?** | Could find exposed API keys, internal endpoints |
| **Decision** | **DELETE** — duplicate of browser.py's `extract_endpoints_from_js()` |

**Issues:**
- `_analyze_script()` does regex matching on JS source — same as `extract_endpoints_from_js()`
- `_analyze_runtime()` detects framework — useful but could be in browser.py
- `_analyze_network_patterns()` extracts API URLs — same as `extract_api_from_network_entries()`

---

### 13. `visual_explorer.py` (162 lines) — UI STRUCTURE

| Attribute | Value |
|---|---|
| **Purpose** | Extract UI structure: buttons, forms, navigation, tables, uploads, pagination |
| **Dependencies** | browser (composition) |
| **Called by** | researcher.py (Stage 1 only) |
| **Integration** | PARTIAL — `explore()` called, results passed to LLM |
| **Dead code** | None |
| **Deterministic?** | Yes — DOM query-based |
| **Finds vulns?** | Discovers forms and upload widgets |
| **Decision** | **DELETE** — duplicate of browser.py's `get_all_forms()` and `extract_form_endpoints()` |

---

### 14. `auth/authcore/` (7,465 lines) — AUTH TESTING LIBRARY

| Attribute | Value |
|---|---|
| **Purpose** | Complete auth testing: sessions, cookies, JWT, CSRF, IDOR, role testing, GraphQL auth, multi-org |
| **Dependencies** | httpx, sqlite3 |
| **Called by** | **NOTHING** — completely decoupled from main researcher |
| **Integration** | **ZERO** |
| **Dead code** | **ENTIRE PACKAGE** — 7,465 lines never used |
| **Deterministic?** | Yes — rule-based testing |
| **Finds vulns?** | Yes — production-quality auth testing |
| **Decision** | **INTEGRATE or DELETE** — cannot remain unused |

**Sub-modules:**
- `session.py` (940 lines): AuthSession, CookieJar, JWTToken, CSRFToken — production-quality
- `store.py` (778 lines): SQLite-backed session store with role/org queries
- `auth_client.py` (269 lines): HTTP client with auth injection
- `object_inventory.py` (922 lines): Object tracking for IDOR detection
- `idor_tester.py` (826 lines): Cross-user IDOR testing
- `boundary_tester.py` (622 lines): Account boundary testing
- `role_tester.py` (597 lines): Role-based access testing
- `graphql_tester.py` (840 lines): GraphQL auth testing
- `multi_org_tester.py` (551 lines): Multi-org isolation testing

---

## Dependency Graph

```
main.py
  └── researcher.py
        ├── memory.py (leaf)
        ├── app_model.py (leaf)
        ├── reasoning_trace.py (leaf) [DELETE]
        ├── evidence_validator.py (leaf) [DELETE — never called]
        ├── llm_client.py (leaf)
        ├── tools/http_client.py (leaf)
        ├── tools/auth.py (leaf)
        ├── tools/browser.py (leaf)
        ├── tools/replay.py → tools/http_client.py
        ├── browser_intel.py → tools/browser.py [DELETE — duplicate]
        ├── js_intel.py → tools/browser.py [DELETE — duplicate]
        └── visual_explorer.py → tools/browser.py [DELETE — duplicate]

auth/authcore/ (DISCONNECTED — zero imports from main package)
  ├── session.py (leaf)
  ├── store.py → session.py
  ├── auth_client.py → session.py
  ├── object_inventory.py → session.py
  ├── idor_tester.py → session.py, auth_client.py, object_inventory.py
  ├── boundary_tester.py → session.py, auth_client.py, object_inventory.py
  ├── role_tester.py → session.py, auth_client.py, object_inventory.py
  ├── graphql_tester.py → session.py, auth_client.py, object_inventory.py
  └── multi_org_tester.py → session.py, auth_client.py, object_inventory.py
```

---

## Summary Decisions

| Module | Lines | Decision | Reason |
|---|---|---|---|
| researcher.py | 1,421 | **KEEP** | Core orchestrator |
| llm_client.py | 184 | **KEEP** | Clean LLM interface |
| memory.py | 423 | **KEEP** | Solid data layer |
| app_model.py | 286 | **KEEP** | Application understanding |
| tools/browser.py | 712 | **KEEP** | Strongest module |
| tools/http_client.py | 121 | **KEEP** | Clean HTTP client |
| tools/replay.py | 344 | **KEEP** | Powerful mutations |
| tools/auth.py | 204 | **DELETE** | Superseded by authcore |
| reasoning_trace.py | 114 | **DELETE** | Debugging overhead |
| evidence_validator.py | 164 | **DELETE** | Never called |
| browser_intel.py | 450 | **DELETE** | Duplicate of browser.py |
| js_intel.py | 301 | **DELETE** | Duplicate of browser.py |
| visual_explorer.py | 162 | **DELETE** | Duplicate of browser.py |
| auth/authcore/* | 7,465 | **INTEGRATE** | Production-quality, zero usage |
