# METRICS.md — Performance Instrumentation Plan

## Current State

Demogorgon has **zero instrumentation**. No metrics are collected during a hunt. The only output is:
- Console prints (not structured)
- `memory.get_summary()` (basic counts)
- `app_model.get_summary()` (text dump)

---

## Required Metrics Collection

### Discovery Metrics

| Metric | How to Collect | Current Value | Target |
|---|---|---|---|
| Pages visited | Count `browser.navigate()` calls | ~7 | 50+ |
| DOMs parsed | Count `browser.get_content()` calls | 0 | 50+ |
| JS bundles analyzed | Count script tags processed | 0 | 20+ |
| Links extracted | Count `get_all_links()` results | ~30 | 200+ |
| Forms extracted | Count `get_all_forms()` results | ~5 | 20+ |
| API endpoints (browser) | Count `get_api_endpoints()` results | 7 | 50+ |
| API endpoints (JS source) | Count `extract_endpoints_from_js()` results | 0 (never called) | 30+ |
| Hidden endpoints | Count from `discover_admin_paths()` | 0 (never called) | 5+ |
| GraphQL endpoints | Count from `graphql_introspect()` | 0 (never called) | 2+ |
| __NEXT_DATA__ routes | Count from `extract_next_data()` | 0 (never called) | 10+ |
| Parameters discovered | Count from form fields + URL params | 0 | 50+ |

### Testing Metrics

| Metric | How to Collect | Current Value | Target |
|---|---|---|---|
| Total HTTP requests | `http.request_count` | ~7 | 200+ |
| Replay mutations executed | Count `_act_replay()` calls | 0 | 50+ |
| Unique payloads sent | Count unique request bodies | ~7 | 100+ |
| Auth contexts tested | `len(auth.sessions)` | 1 | 4+ |
| Duplicate actions skipped | Count `_is_duplicate()` returns True | ~20% | <5% |
| LLM parse failures | Count `_parse_json_response()` returns None | ~50% | <5% |
| LLM calls made | Count `_llm_call()` calls | ~35 | 50+ |
| LLM calls succeeded | Count non-None returns | ~15 | 45+ |

### Finding Metrics

| Metric | How to Collect | Current Value | Target |
|---|---|---|---|
| Hypotheses generated | `len(memory.hypotheses)` | 64 | 30+ |
| Hypotheses tested | Count hypotheses with status="testing" | 7 | 25+ |
| Hypotheses confirmed | `len(memory.get_confirmed_hypotheses())` | 0 | 3+ |
| Hypotheses rejected | `len(memory.get_rejected_hypotheses())` | 0 | 20+ |
| Evidence items collected | `len(memory.evidence)` | 7 | 100+ |
| Findings reported | `len(memory.findings)` | 0 | 1+ |
| False positives | Manual review | Unknown | 0 |

### Performance Metrics

| Metric | How to Collect | Current Value | Target |
|---|---|---|---|
| Total runtime | `time.time() - memory.start_time` | ~5min | 15min |
| Time per iteration | Track per-iteration elapsed | ~10s | 5s |
| LLM response time | Track `llm.complete()` elapsed | ~8s | 5s |
| HTTP request time | Track `http.request()` elapsed | ~1s | 0.5s |
| Browser navigation time | Track `browser.navigate()` elapsed | ~3s | 2s |
| Context build time | Track `_build_hunting_context()` elapsed | ~0.1s | <0.1s |

---

## Instrumentation Implementation

### Where to Add Metrics

```python
# In researcher.py __init__:
self.metrics = {
    "pages_visited": 0,
    "js_bundles_analyzed": 0,
    "api_endpoints_browser": 0,
    "api_endpoints_js": 0,
    "hidden_endpoints": 0,
    "graphql_endpoints": 0,
    "parameters_discovered": 0,
    "http_requests": 0,
    "replay_mutations": 0,
    "duplicate_skips": 0,
    "llm_calls": 0,
    "llm_successes": 0,
    "llm_parse_failures": 0,
    "hypotheses_generated": 0,
    "hypotheses_tested": 0,
    "evidence_items": 0,
    "findings": 0,
    "runtime_seconds": 0,
}

# After each action:
self.metrics["http_requests"] += 1
# etc.

# At end of hunt:
self._save_metrics()
```

### Metrics Output Format

```json
{
  "target": "https://target.com",
  "runtime_seconds": 900,
  "discovery": {
    "pages_visited": 45,
    "api_endpoints_browser": 32,
    "api_endpoints_js": 18,
    "hidden_endpoints": 3,
    "parameters_discovered": 67
  },
  "testing": {
    "http_requests": 187,
    "replay_mutations": 45,
    "duplicate_skips": 8,
    "llm_calls": 42,
    "llm_successes": 38,
    "llm_parse_failures": 4
  },
  "findings": {
    "hypotheses_generated": 28,
    "hypotheses_tested": 22,
    "hypotheses_confirmed": 2,
    "evidence_items": 89,
    "findings": 1
  },
  "coverage": {
    "endpoints_discovered": 53,
    "endpoints_tested": 41,
    "coverage_percent": 77
  }
}
```
