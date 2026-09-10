# IMPLEMENTATION_ROADMAP.md — Ranked Action Plan

## Guiding Principle

Every task must increase the probability of finding reportable vulnerabilities on real bug bounty targets. No architecture discussions. No theoretical improvements.

---

## P0 — Must Do (blocks finding any vulnerabilities)

### 1. Wire deterministic endpoint discovery into researcher

**Why:** Currently 0 endpoints discovered from JS source, 0 from admin paths, 0 from __NEXT_DATA__. The researcher visits 5-7 hardcoded URLs and relies on LLM to choose more. This is the #1 reason Sentinel finds 0 vulnerabilities.

**What:**
- Call `browser.extract_next_data()` after each navigation
- Call `browser.extract_endpoints_from_js()` after each navigation
- Call `browser.extract_api_from_network_entries()` after each navigation
- Call `browser.extract_form_endpoints()` after each navigation
- Call `browser.discover_admin_paths()` in Stage 1
- Add all discovered endpoints to `memory.endpoints`
- Remove browser_intel, js_intel, visual_explorer calls (they duplicate this)

**Expected improvement:** 10x more endpoints discovered (7 → 70+)

**Estimated LOC:** 80 lines (researcher.py modifications)

**Estimated time:** 2 hours

**Risk:** Low — methods already exist, just need wiring

**Success criteria:** `len(memory.endpoints)` > 30 after Stage 1 on any target

---

### 2. Integrate authcore into researcher

**Why:** 7,465 lines of production-quality auth testing exist but are never used. Multi-user IDOR testing, role testing, GraphQL auth testing are all implemented but disconnected.

**What:**
- Import authcore components in researcher.py
- Replace tools/auth.py with authcore.session + authcore.store
- Replace tools/replay.py IDOR mode with authcore.idor_tester
- Add authcore.role_tester for privilege escalation testing
- Add authcore.graphql_tester for GraphQL targets
- Wire authcore.object_inventory for object tracking

**Expected improvement:** Enable IDOR, privilege escalation, and multi-tenant testing

**Estimated LOC:** 200 lines (researcher.py modifications + authcore wiring)

**Estimated time:** 4 hours

**Risk:** Medium — authcore has different API than tools/auth.py

**Success criteria:** Multi-session replay works with 4+ auth contexts

---

### 3. Delete dead modules

**Why:** 1,395 lines of dead code add complexity, confusion, and maintenance burden. Every unused module is a trap for future developers.

**What:**
- Delete reasoning_trace.py (114 lines)
- Delete evidence_validator.py (164 lines)
- Delete browser_intel.py (450 lines)
- Delete js_intel.py (301 lines)
- Delete visual_explorer.py (162 lines)
- Delete tools/auth.py (204 lines) — replaced by authcore
- Remove unused imports from researcher.py

**Expected improvement:** Cleaner codebase, less confusion

**Estimated LOC:** -1,395 lines

**Estimated time:** 30 minutes

**Risk:** Low — verified these are unused

**Success criteria:** All imports resolve, no broken references

---

### 4. Add deterministic vulnerability detection patterns

**Why:** LLM cannot reliably detect SQL injection, XSS, or other known patterns. Deterministic pattern matching is needed.

**What:**
- Add SQL error pattern detection (MySQL, PostgreSQL, MSSQL, Oracle error messages)
- Add XSS reflection detection (input reflected in response)
- Add timing-based blind injection detection
- Add information disclosure detection (stack traces, debug info, version headers)
- Add WAF detection (common WAF headers/responses)
- Add technology fingerprinting (server headers, error pages)

**Expected improvement:** Detect 30-50% of known vulnerability patterns without LLM

**Estimated LOC:** 300 lines (new module: sentinel_v2/detectors.py)

**Estimated time:** 4 hours

**Risk:** Low — pattern matching is well-understood

**Success criteria:** Detects SQL injection on DVWA login page

---

## P1 — Should Do (significantly increases finding probability)

### 5. Add wordlist-based directory fuzzing

**Why:** ffuf discovers 200+ endpoints in 2 minutes. Sentinel discovers 7 in 5 minutes. Wordlist fuzzing is the fastest way to increase coverage.

**What:**
- Add `tools/fuzzer.py` with recursive directory fuzzing
- Use common wordlists (common.txt, directory-list-2.3-medium.txt)
- Support auth-injected fuzzing (fuzz with session cookies)
- Filter by response size/status to reduce noise
- Integrate into Stage 1 or as a separate reconnaissance phase

**Expected improvement:** 50-100 additional endpoints discovered

**Estimated LOC:** 200 lines

**Estimated time:** 3 hours

**Risk:** Low — fuzzer is straightforward

**Success criteria:** Discovers /admin, /api, /swagger on Juice Shop

---

### 6. Add parallel request execution

**Why:** Sequential testing is 10-50x slower than parallel. 30 iterations at 10s each = 5 minutes. Parallel could test 30 endpoints in 10 seconds.

**What:**
- Add `tools/parallel.py` for concurrent request batches
- Add async task pool for endpoint probing
- Add race condition detection via parallel replay
- Limit concurrency to avoid overwhelming targets

**Expected improvement:** 10-50x faster testing

**Estimated LOC:** 150 lines

**Estimated time:** 2 hours

**Risk:** Medium — rate limiting, connection management

**Success criteria:** Test 50 endpoints in under 60 seconds

---

### 7. Wire remaining browser extraction methods

**Why:** `extract_form_endpoints()`, `discover_admin_paths()` are implemented but never called.

**What:**
- Call `browser.discover_admin_paths()` in Stage 1
- Call `browser.extract_form_endpoints()` in Stage 2
- Store results in memory.endpoints
- Use during hypothesis generation

**Expected improvement:** 5-10 additional endpoints (admin panels, form actions)

**Estimated LOC:** 30 lines

**Estimated time:** 30 minutes

**Risk:** Low

**Success criteria:** Admin panels discovered on targets with /admin

---

### 8. Add timing-based detection

**Why:** Blind SQL injection, timing oracles, and race conditions require timing analysis. Current `diff_responses()` doesn't compare timing.

**What:**
- Add timing measurement to `http_client.request()`
- Add timing comparison to `diff_responses()`
- Add timing threshold detection (>2s difference = suspicious)
- Add race condition detection via parallel timing

**Expected improvement:** Detect blind injection and race conditions

**Estimated LOC:** 80 lines

**Estimated time:** 1 hour

**Risk:** Low

**Success criteria:** Detects time-based SQL injection on DVWA

---

### 9. Improve LLM JSON parsing

**Why:** 50-60% of LLM responses fail to parse as JSON. This wastes half of all iterations.

**What:**
- Add `response_format: {"type": "json_object"}` to all LLM calls (already done)
- Add fallback JSON extraction (find largest JSON object in response)
- Add retry with simplified prompt on parse failure
- Add max_tokens increase for complex responses
- Log parse failures for debugging

**Expected improvement:** Reduce parse failures from 50% to <10%

**Estimated LOC:** 50 lines (llm_client.py + researcher.py)

**Estimated time:** 1 hour

**Risk:** Low

**Success criteria:** >90% of LLM calls return valid JSON

---

### 10. Add OpenAPI/Swagger parsing

**Why:** Many APIs expose OpenAPI specs that list all endpoints, parameters, and schemas. This is the fastest way to discover API surface.

**What:**
- Check for /swagger.json, /openapi.json, /api-docs
- Parse OpenAPI spec to extract all endpoints
- Add endpoints to memory with parameter information
- Use schemas for IDOR testing (identify ID parameters)

**Expected improvement:** Discover all API endpoints from spec

**Estimated LOC:** 150 lines

**Estimated time:** 2 hours

**Risk:** Low

**Success criteria:** Extracts all endpoints from Juice Shop OpenAPI spec

---

## P2 — Nice-to-Have (improves coverage or quality)

### 11. Add subdomain enumeration

**Why:** Bug bounty scope often includes multiple subdomains. Current tool only tests single domain.

**What:**
- Integrate subfinder or assetfinder
- Add DNS resolution
- Add live host detection
- Scope filtering

**Estimated LOC:** 100 lines
**Estimated time:** 2 hours

---

### 12. Add WebSocket testing

**Why:** Real-time APIs (chat, notifications) are invisible to current tool.

**What:**
- Capture WebSocket connections from browser
- Test WebSocket auth
- Fuzz WebSocket messages

**Estimated LOC:** 150 lines
**Estimated time:** 3 hours

---

### 13. Add file upload testing

**Why:** Upload widgets detected but never tested.

**What:**
- Detect upload forms
- Test with malicious files (polyglots, web shells)
- Test content-type bypass
- Test path traversal in filenames

**Estimated LOC:** 100 lines
**Estimated time:** 2 hours

---

### 14. Add SSRF testing

**Why:** SSRF is a high-impact vulnerability class.

**What:**
- Detect URL parameters
- Test with internal URLs (localhost, 169.254.169.254)
- Test with redirect URLs
- Detect SSRF via response differences

**Estimated LOC:** 100 lines
**Estimated time:** 2 hours

---

### 15. Add report quality improvements

**Why:** Current report is basic Markdown. Bug bounty programs expect detailed, reproducible reports.

**What:**
- Add CVSS scoring
- Add automated PoC generation
- Add remediation suggestions
- Add HackerOne/Bugcrowd format templates

**Estimated LOC:** 100 lines
**Estimated time:** 2 hours

---

### 16. Add metrics collection

**Why:** No metrics are collected. Can't measure improvement.

**What:**
- Add metrics dict to researcher
- Track all discovery, testing, and finding counts
- Save metrics to JSON at end of hunt
- Add summary to report

**Estimated LOC:** 80 lines
**Estimated time:** 1 hour

---

## Implementation Order

| Phase | Tasks | Total LOC | Total Time | Expected Impact |
|---|---|---|---|---|
| **P0** | #1, #2, #3, #4 | 580 net | 11 hours | 10x coverage, auth testing enabled, pattern detection |
| **P1** | #5, #6, #7, #8, #9, #10 | 660 | 9.5 hours | Wordlist fuzzing, parallel testing, better LLM |
| **P2** | #11-#16 | 630 | 12 hours | Subdomains, WebSocket, file upload, SSRF |

**Total:** 1,870 net lines, 32.5 hours

---

## What NOT to Do

1. **Do not add new LLM reasoning layers** — The bottleneck is execution, not reasoning
2. **Do not add new dataclasses** — Existing ones are sufficient
3. **Do not add new prompt templates** — Existing prompts are adequate
4. **Do not refactor for "clean architecture"** — Working code beats clean code
5. **Do not add dependencies without validation** — Every new dependency must prove value
