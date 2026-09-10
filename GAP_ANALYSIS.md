# GAP_ANALYSIS.md — Missing Capabilities

## Ranking System

- **CRITICAL** — Blocks finding any reportable vulnerabilities
- **HIGH** — Significantly reduces finding probability
- **MEDIUM** — Reduces coverage or quality
- **LOW** — Nice-to-have, minimal impact

---

## Critical Gaps (P0)

### 1. Deterministic Endpoint Discovery

**Current state:** Relies entirely on LLM to choose which pages to visit. The researcher visits 5-7 hardcoded URLs and relies on browser auto-capture for API endpoints.

**What's missing:**
- Wordlist-based directory/file fuzzing (like ffuf/feroxbuster)
- Recursive crawl with depth limit
- JavaScript bundle analysis for hidden routes
- Subdomain enumeration
- Historical URL discovery (Wayback, GAU)

**Impact:** Without discovering endpoints, there's nothing to test. This is the #1 blocker.

**Expected improvement:** 10x more endpoints discovered → 10x more attack surface

---

### 2. Deterministic Vulnerability Detection

**Current state:** LLM must decide "this looks like SQL injection" or "this response indicates IDOR". No pattern matching, no template matching.

**What's missing:**
- Error-based SQL injection detection (error messages, response patterns)
- Time-based blind SQL injection detection (response timing)
- XSS detection (reflected input in response)
- Known vulnerability template matching (like Nuclei)
- Technology-specific vulnerability patterns

**Impact:** Even if endpoints are discovered, vulnerabilities go undetected without pattern matching.

**Expected improvement:** From 0% detection to 30-50% for known patterns

---

### 3. Authcore Integration

**Current state:** 7,465 lines of production-quality auth testing code exists in `auth/authcore/` but is never imported by the researcher. The researcher uses a basic 204-line `auth.py` instead.

**What's missing:**
- Cross-user IDOR testing (idor_tester.py: 826 lines)
- Role-based access testing (role_tester.py: 597 lines)
- GraphQL auth testing (graphql_tester.py: 840 lines)
- Multi-org isolation testing (multi_org_tester.py: 551 lines)
- Account boundary testing (boundary_tester.py: 622 lines)
- Object inventory tracking (object_inventory.py: 922 lines)
- Session store with SQLite persistence (store.py: 778 lines)

**Impact:** All auth-related vulnerability testing is effectively disabled.

**Expected improvement:** Enable IDOR, privilege escalation, and multi-tenant testing

---

## High Gaps (P1)

### 4. Parameter Discovery

**Current state:** Parameters are only discovered from form fields and captured XHR requests. No parameter fuzzing, no URL parameter extraction from JS, no API schema analysis.

**What's missing:**
- URL parameter mining from JS source
- API schema analysis (OpenAPI/Swagger parsing)
- Parameter fuzzing (common param names)
- Hidden parameter discovery (commented-out params, dev endpoints)

**Impact:** Miss injection points in URL parameters, headers, cookies.

---

### 5. Response Analysis

**Current state:** `diff_responses()` compares status code, length, and basic content patterns. No timing analysis, no encoding detection, no semantic comparison.

**What's missing:**
- Timing-based blind injection detection
- Response encoding analysis (base64, HTML entities)
- JSON structure diff (not just key comparison)
- Error message categorization
- Server header analysis
- WAF detection

**Impact:** Subtle vulnerabilities (blind injection, timing attacks) go undetected.

---

### 6. Parallel Testing

**Current state:** Sequential iteration loop. One request at a time. LLM decides next action.

**What's missing:**
- Concurrent request batches
- Parallel mutation testing
- Async endpoint probing
- Background reconnaissance

**Impact:** 10-50x slower than parallel tools. Limited coverage in time-constrained hunts.

---

### 7. Learning and Adaptation

**Current state:** LLM context includes "already tested" list but no learning from successful patterns. Failed hypotheses are tracked but not used to generate new approaches.

**What's missing:**
- Pattern recognition from successful tests
- Automatic hypothesis refinement
- Cross-endpoint learning (if X worked on endpoint A, try similar on B)
- Technique effectiveness tracking

**Impact:** Repeats failed approaches, misses similar vulnerabilities on other endpoints.

---

## Medium Gaps (P2)

### 8. WebSocket Testing

**Current state:** Zero WebSocket support. Real-time APIs (chat, notifications, live data) are invisible.

**What's missing:**
- WebSocket connection and message capture
- WebSocket message fuzzing
- Auth testing on WebSocket connections

---

### 9. File Upload Testing

**Current state:** Upload widgets are detected by visual_explorer but never tested.

**What's missing:**
- Malicious file upload (polyglot files, web shells)
- Content-type bypass testing
- File size limit testing
- Path traversal in filenames

---

### 10. SSRF Testing

**Current state:** No SSRF detection or testing.

**What's missing:**
- Internal URL detection in parameters
- HTTP/SOCKS redirect testing
- DNS rebinding testing
- Cloud metadata endpoint testing (169.254.169.254)

---

### 11. Cache Poisoning

**Current state:** No cache-related testing.

**What's missing:**
- Cache header analysis
- Unkeyed header detection
- Cache key manipulation
- Web cache deception testing

---

### 12. HTTP Request Smuggling

**Current state:** No HTTP/2 or CL.TE/TE.CL testing.

**What's missing:**
- HTTP/2 downgrading detection
- Transfer-Encoding manipulation
- Content-Length/Transfer-Encoding conflict testing

---

### 13. Race Condition Testing

**Current state:** `replay_batch()` exists but is never called from the researcher. No automatic race detection.

**What's missing:**
- Automatic race condition detection on state-changing endpoints
- Response comparison across concurrent requests
- State change verification

---

## Low Gaps (P3)

### 14. OAuth/OIDC Testing

**Current state:** No OAuth flow testing.

**What's missing:**
- Authorization code interception
- PKCE bypass testing
- Token refresh abuse
- Redirect URI manipulation

---

### 15. Subdomain Takeover

**Current state:** No subdomain enumeration or takeover detection.

**What's missing:**
- Subdomain enumeration (subfinder, amass)
- DNS record analysis
- CNAME/ALIAS record checking
- Service fingerprinting

---

### 16. Business Logic Automation

**Current state:** LLM can reason about business logic but has no automated tools.

**What's missing:**
- Price manipulation testing
- Quantity overflow testing
- Discount code abuse
- Workflow step skipping

---

### 17. Report Quality

**Current state:** Basic Markdown report with finding details.

**What's missing:**
- CVSS scoring
- Proof-of-concept automation
- Severity justification
- Remediation recommendations
- HackerOne/Bugcrowd format templates

---

## Gap Summary

| Priority | Gap | Impact | Effort |
|---|---|---|---|
| CRITICAL | Deterministic endpoint discovery | 10x coverage | High |
| CRITICAL | Deterministic vulnerability detection | 30-50% detection | High |
| CRITICAL | Authcore integration | Auth testing enabled | Medium |
| HIGH | Parameter discovery | More injection points | Medium |
| HIGH | Response analysis | Subtle vulns detected | Medium |
| HIGH | Parallel testing | 10-50x speed | High |
| HIGH | Learning and adaptation | Better hypotheses | High |
| MEDIUM | WebSocket testing | Real-time API coverage | Medium |
| MEDIUM | File upload testing | Upload vuln detection | Low |
| MEDIUM | SSRF testing | SSRF detection | Medium |
| MEDIUM | Cache poisoning | Cache vuln detection | Medium |
| MEDIUM | HTTP smuggling | Smuggling detection | High |
| MEDIUM | Race condition testing | Race vuln detection | Low |
| LOW | OAuth/OIDC testing | Auth flow coverage | High |
| LOW | Subdomain takeover | Infrastructure coverage | Medium |
| LOW | Business logic automation | Logic bug detection | High |
| LOW | Report quality | Submission-ready reports | Low |
