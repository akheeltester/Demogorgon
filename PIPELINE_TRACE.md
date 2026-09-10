# PIPELINE_TRACE.md — End-to-End Hunt Trace

## Command

```bash
python -m demogorgon https://target.com
```

---

## Stage-by-Stage Trace

### Stage 0: Initialization

```
main.py:main()
  ├── Parse args (target, headless, proxy, rate_limit, max_iterations, output)
  ├── LLMClient() — loads .env, creates OpenAI client
  ├── Test LLM connection — "Reply with one word: CONNECTED"
  └── Researcher() — stores config, creates Memory, ApplicationModel
```

**Inputs:** CLI args, .env file
**Outputs:** Researcher instance
**Assumptions:** .env has valid OPENROUTER_API_KEY, OPENROUTER_BASE_URL
**Failure modes:** Invalid API key → SystemExit. No base URL → connection error.
**Lost information:** None

---

### Stage 1: Product Understanding

```
researcher._stage_product_understanding()
  ├── browser.navigate(target_url)
  │   └── Captures: page HTML, all requests/responses, cookies, tokens, localStorage
  ├── browser.screenshot("initial_page")
  ├── browser_intel.full_scan()
  │   ├── _scan_dom() — page title, meta tags, canonical URL
  │   ├── _scan_ui_elements() — buttons, inputs, links, forms, modals
  │   ├── _scan_api_endpoints() — from captured XHR/fetch requests
  │   ├── _scan_js_state() — framework detection, API base URLs
  │   ├── _scan_tokens() — JWT, CSRF, API keys from storage/cookies
  │   └── _scan_storage() — localStorage, sessionStorage, cookies
  ├── js_intel.analyze_page()
  │   ├── _get_all_scripts() — all <script> tags
  │   ├── _analyze_script() — regex: fetch(), axios, API strings, env vars
  │   ├── _analyze_runtime() — framework, router, state management
  │   └── _analyze_network_patterns() — API URLs from performance entries
  ├── visual_explorer.explore()
  │   └── DOM queries: buttons, forms, navigation, tables, uploads, pagination
  ├── browser.get_text() — visible text content
  ├── browser.get_all_links() — all <a href> URLs
  ├── browser.get_all_forms() — all <form> with fields
  ├── Build context string (620+ lines)
  ├── LLM call: PRODUCT_UNDERSTANDING_PROMPT
  │   └── Returns: product_type, user_roles, ownership_model, tech_stack, api_style
  ├── Store in app_model: product_type, roles, tech_stack, api_style
  ├── Add endpoints from links, forms, API endpoints
  └── Import browser cookies into auth manager
```

**Inputs:** target_url
**Outputs:** app_model populated with product_type, roles, tech_stack
**Assumptions:** Target is reachable, renders in browser
**Failure modes:** Site blocks headless browser, requires CAPTCHA, geo-restricted
**Lost information:**
- `browser_intel.full_scan()` returns structured data but it's serialized to JSON for LLM
- `js_intel.analyze_page()` returns structured data but it's serialized to JSON for LLM
- The LLM may ignore or misinterpret the structured data
- **3 separate JS analysis passes** happen (browser auto-capture, browser_intel, js_intel) — massive redundancy

**Duplicate work:**
- `browser_intel._scan_api_endpoints()` duplicates `browser.get_api_endpoints()`
- `js_intel._analyze_script()` regex patterns overlap with `browser.extract_endpoints_from_js()` (which is never called)
- `visual_explorer.explore()` duplicates `browser.get_all_forms()` + DOM queries in browser_intel

---

### Stage 2: Business Object Discovery

```
researcher._stage_business_object_discovery()
  ├── pages_to_visit = [target, /api/v1, /dashboard, /profile, /settings]
  ├── For each page:
  │   ├── browser.navigate(page_url)
  │   ├── browser.get_api_endpoints() — XHR/fetch from this page
  │   └── http.request("GET", ep["url"]) — fetch each API endpoint
  ├── LLM call: BUSINESS_OBJECT_PROMPT
  │   └── Returns: business_objects, relationships, observations
  └── Store in app_model: business_objects
```

**Inputs:** app_model.product_type, discovered endpoints
**Outputs:** app_model.business_objects
**Assumptions:** API endpoints return JSON with business objects
**Failure modes:** APIs require auth (returns 401), APIs return HTML (not JSON), rate limiting
**Lost information:**
- Only visits 5 hardcoded pages — misses most of the site
- Only fetches XHR/fetch endpoints — misses form submissions
- LLM may miss objects in large JSON responses (truncated to 5000 chars)
- **No parameter extraction** from API responses

**Duplicate work:**
- `browser.get_api_endpoints()` is called again here (was already captured in Stage 1)

---

### Stage 3: Workflow Reconstruction

```
researcher._stage_workflow_reconstruction()
  ├── workflows_to_explore = [/register, /login, /dashboard, /profile, /settings]
  ├── For each page:
  │   ├── browser.navigate(url)
  │   ├── browser.get_all_forms()
  │   └── browser.get_text()
  ├── LLM call: WORKFLOW_PROMPT
  │   └── Returns: workflows with steps, attack_points
  └── Store in app_model: workflows
```

**Inputs:** app_model.product_type, user_roles, business_objects
**Outputs:** app_model.workflows
**Assumptions:** Workflow pages are accessible without auth
**Failure modes:** Login-required pages return redirect
**Lost information:**
- Only visits 5 hardcoded pages — misses most workflows
- No click-path exploration (user journey simulation)
- No state machine detection

---

### Stage 4: Trust Boundary Mapping

```
researcher._stage_trust_boundary_mapping()
  ├── LLM call: TRUST_BOUNDARY_PROMPT (NO browser/HTTP requests)
  │   └── Returns: trust_boundaries, observations
  └── Store in app_model: trust_boundaries
```

**Inputs:** app_model (product_type, roles, objects, workflows)
**Outputs:** app_model.trust_boundaries
**Assumptions:** LLM can infer trust boundaries from app model
**Failure modes:** LLM hallucinates boundaries
**Lost information:**
- **Zero requests made** — purely LLM inference
- No actual auth testing to verify boundaries
- No boundary enforcement verification

---

### Stage 5: Attack Surface Classification

```
researcher._stage_attack_surface_classification()
  ├── LLM call: ATTACK_SURFACE_PROMPT (NO browser/HTTP requests)
  │   └── Returns: attack_surface (endpoint, category, risk_level)
  └── Store in app_model: attack_surface
```

**Inputs:** app_model, discovered endpoints
**Outputs:** app_model.attack_surface
**Assumptions:** LLM can classify endpoints
**Failure modes:** LLM misclassifies
**Lost information:**
- **Zero requests made** — purely LLM inference
- No actual probing of endpoints

---

### Stage 6: Attack Opportunity Generation

```
researcher._stage_attack_opportunity_generation()
  ├── LLM call: ATTACK_OPPORTUNITY_PROMPT (NO browser/HTTP requests)
  │   └── Returns: attack_opportunities (specific endpoints, test plans)
  └── Store in app_model: attack_opportunities
```

**Inputs:** app_model summary (50+ lines)
**Outputs:** app_model.attack_opportunities
**Assumptions:** LLM generates specific, actionable opportunities
**Failure modes:** LLM generates generic hypotheses ("maybe IDOR exists")
**Lost information:**
- **Zero requests made** — purely LLM inference
- Opportunities depend on quality of app_model (which depends on Stages 1-3)

---

### Stage 7: Intelligent Testing Loop (x30 iterations)

```
For each iteration:
  ├── _build_hunting_context()
  │   └── Builds 200+ line context string from app_model + memory
  ├── LLM call: HUNTING_PROMPT + context
  │   └── Returns: action (tool, URL, method, body, headers, replay_mode)
  ├── _is_duplicate(action) — check if already tested
  │   └── If duplicate: skip, increment consecutive_duplicates
  ├── _act(action)
  │   ├── tool="replay" → _act_replay()
  │   │   ├── Find matching captured request
  │   │   ├── Dispatch to replay method (baseline/no_auth/no_csrf/method_override/idor/full_analysis/multi_session/negative_ids/null_bytes/array_injection/race)
  │   │   ├── http.request() — send mutated request
  │   │   └── diff_responses() — compare baseline vs mutated
  │   ├── tool="http" → _act_http()
  │   │   ├── auth.apply_to_request() — inject session headers/cookies
  │   │   ├── http.request() — send request
  │   │   └── memory.add_evidence/add_endpoint/mark_tested
  │   ├── tool="browser" → _act_browser()
  │   │   └── navigate/click/fill/screenshot/content/text/evaluate/cookies/local_storage
  │   ├── tool="auth" → _act_auth()
  │   │   └── set_active/create/import_from_browser/status
  │   └── tool="report" → _act_report()
  │       └── memory.add_finding()
  ├── _observe(action, result)
  │   ├── app_model.add_observation()
  │   ├── app_model.add_business_object()
  │   ├── memory.add_hypothesis()
  │   └── memory.add_finding()
  ├── _track_tested(action) — add to _tested_combos
  └── Every 5 iterations: save state
```

**Inputs:** app_model, memory, captured requests
**Outputs:** evidence, findings, observations
**Assumptions:** LLM produces valid JSON actions, endpoints are reachable
**Failure modes:**
- LLM returns malformed JSON → iteration wasted (50-60% of iterations)
- LLM repeats same endpoint → duplicate check skips (but iteration still consumed)
- LLM ignores unvisited endpoints → keeps testing homepage
- HTTP errors → response is {"status_code": 0}
**Lost information:**
- `_build_hunting_context()` is 200+ lines — LLM may not read it all
- Failed tests are tracked but not used to steer LLM away from similar approaches
- No learning from successful patterns

---

## Information Flow Diagram

```
Browser ──→ browser_intel ──→ LLM (Stage 1)
Browser ──→ js_intel ────────→ LLM (Stage 1)
Browser ──→ visual_explorer ─→ LLM (Stage 1)
Browser ──→ get_all_links ───→ memory.endpoints
Browser ──→ get_all_forms ───→ memory.endpoints
Browser ──→ get_api_endpoints → memory.endpoints

HTTP ─────→ API responses ───→ LLM (Stage 2)
LLM ──────→ app_model.business_objects

LLM ──────→ app_model.workflows (Stage 3)
LLM ──────→ app_model.trust_boundaries (Stage 4)
LLM ──────→ app_model.attack_surface (Stage 5)
LLM ──────→ app_model.attack_opportunities (Stage 6)

LLM ──────→ action (Stage 7)
Action ────→ replay/http/browser → evidence
Evidence ──→ memory.findings
```

**Critical gap:** The browser's deterministic extraction methods (`extract_next_data`, `extract_endpoints_from_js`, `extract_api_from_network_entries`, `extract_form_endpoints`, `discover_admin_paths`) are NEVER called. All endpoint discovery goes through the LLM.
