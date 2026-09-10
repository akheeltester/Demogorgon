# VALIDATION_MATRIX.md — Capability Validation Suite

## Status Key

- **NOT TESTED** — Capability exists in code but has never been validated
- **PASS** — Tested and working correctly
- **FAIL** — Tested and broken
- **PARTIAL** — Works sometimes or with limitations

---

## Core Pipeline Validation

| # | Capability | Target | Expected Result | Actual | Status |
|---|---|---|---|---|---|
| 1 | Browser launch | any | Page loads, screenshots work | NOT TESTED | |
| 2 | Request capture | any | XHR/fetch captured in real-time | NOT TESTED | |
| 3 | Token extraction | any | JWT/CSRF/cookies extracted | NOT TESTED | |
| 4 | Product understanding | oda.com | Correct product type identified | 90% correct (Norwegian grocery) | PASS |
| 5 | Role discovery | oda.com | Guest, user, admin roles | 6 roles found | PASS |
| 6 | Endpoint discovery (browser) | oda.com | >10 endpoints | Only 7 (all homepage) | FAIL |
| 7 | Endpoint discovery (JS) | any | JS-embedded endpoints found | NEVER CALLED | FAIL |
| 8 | __NEXT_DATA__ extraction | Next.js app | Routes and props extracted | NEVER CALLED | FAIL |
| 9 | Admin path discovery | any | Hidden admin panels found | NEVER CALLED | FAIL |
| 10 | Business object discovery | oda.com | Products, users, orders | NOT TESTED | |
| 11 | Workflow reconstruction | oda.com | User journeys mapped | NOT TESTED | |
| 12 | Trust boundary mapping | oda.com | Auth boundaries identified | NOT TESTED | |
| 13 | Attack surface classification | oda.com | Endpoints categorized | NOT TESTED | |
| 14 | Attack opportunity generation | oda.com | Specific test plans | NOT TESTED | |

---

## Replay Engine Validation

| # | Capability | Target | Expected Result | Actual | Status |
|---|---|---|---|---|---|
| 15 | Baseline replay | DVWA | Same response as browser | NOT TESTED | |
| 16 | No-auth replay | DVWA | 401/403 response | NOT TESTED | |
| 17 | No-CSRF replay | DVWA | Response changes or stays same | NOT TESTED | |
| 18 | Method override | DVWA | PUT/PATCH/DELETE accepted? | NOT TESTED | |
| 19 | IDOR replay | crAPI | Different user data returned | NOT TESTED | |
| 20 | Full analysis | any | All mutations executed | NOT TESTED | |
| 21 | Multi-session replay | crAPI | Responses differ across users | NOT TESTED | |
| 22 | Negative ID replay | any | -1, 0, large IDs tested | NOT TESTED | |
| 23 | Null byte replay | any | Null byte appended | NOT TESTED | |
| 24 | Array injection | any | param[]=test injected | NOT TESTED | |
| 25 | Race condition | DVWA | Concurrent requests sent | NOT TESTED | |
| 26 | Response diff (status) | any | Status change detected | NOT TESTED | |
| 27 | Response diff (content) | any | JSON structure change detected | NOT TESTED | |
| 28 | Response diff (errors) | any | Error message changes detected | NOT TESTED | |

---

## Auth Validation

| # | Capability | Target | Expected Result | Actual | Status |
|---|---|---|---|---|---|
| 29 | Cookie-based auth | DVWA | Session maintained | NOT TESTED | |
| 30 | Token-based auth | Juice Shop | JWT injected in headers | NOT TESTED | |
| 31 | Multi-session creation | crAPI | 4 user sessions created | NOT TESTED | |
| 32 | Session rotation | any | Active session switches | NOT TESTED | |
| 33 | Login via HTTP | DVWA | POST login creates session | NOT TESTED | |
| 34 | Browser auth extraction | any | Cookies imported to manager | NOT TESTED | |

---

## GraphQL Validation

| # | Capability | Target | Expected Result | Actual | Status |
|---|---|---|---|---|---|
| 35 | Schema introspection | GraphQLGoat | Full schema returned | NEVER CALLED | FAIL |
| 36 | Query batching | GraphQLGoat | Multiple queries in one request | NEVER CALLED | FAIL |
| 37 | Field suggestion leak | GraphQLGoat | "Did you mean" detected | NEVER CALLED | FAIL |

---

## LLM Validation

| # | Capability | Target | Expected Result | Actual | Status |
|---|---|---|---|---|---|
| 38 | JSON response parsing | any | Valid JSON extracted | 50-60% failure rate | FAIL |
| 39 | response_format support | any | JSON mode enforced | Added but untested | NOT TESTED |
| 40 | Model rotation | any | Falls back to next model | NOT TESTED | |
| 41 | Rate limit handling | any | Retries after 429 | NOT TESTED | |
| 42 | Context truncation | any | Retries with less context | NOT TESTED | |

---

## Memory & Persistence Validation

| # | Capability | Target | Expected Result | Actual | Status |
|---|---|---|---|---|---|
| 43 | State persistence | any | hunt_state.json written | NOT TESTED | |
| 44 | App model persistence | any | app_model.json written | NOT TESTED | |
| 45 | Report generation | any | REPORT.md with findings | NOT TESTED | |
| 46 | Endpoint deduplication | any | Same URL not stored twice | NOT TESTED | |
| 47 | Finding deduplication | any | Same finding not reported twice | NOT TESTED | |

---

## Coverage Metrics (oda.com run)

| Metric | Value | Target | Gap |
|---|---|---|---|
| Pages visited | 7 | 50+ | 86% |
| Endpoints discovered | 7 | 100+ | 93% |
| Endpoints tested | 7 | 50+ | 86% |
| API endpoints from JS | 0 | 30+ | 100% |
| Business objects | 0 | 10+ | 100% |
| Workflows | 0 | 5+ | 100% |
| Trust boundaries | 0 | 5+ | 100% |
| Hypotheses generated | 64 | N/A | — |
| Findings | 0 | 1+ | 100% |
| Iterations wasted (bad JSON) | ~50% | <5% | 90% |
| Iterations wasted (duplicates) | ~20% | <5% | 75% |
