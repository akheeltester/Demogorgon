# LEGACY_FORENSIC_REPORT.md — Archaeological Codebase Audit

## Executive Summary

The legacy directory contains **708 Python files**. After forensic analysis:

- **22 files are production-quality** (must recover)
- **15 files are useful but need adaptation** (recover with changes)
- **~670 files are dead code, stubs, prompt wrappers, or experimental engines** (delete)

**Total recoverable code: ~12,000 lines out of ~45,000 lines (27%)**

---

## Category: KEEP (Production Quality, Immediately Reusable)

| # | File | Lines | What It Does | Why Keep |
|---|---|---|---|---|
| 1 | `interceptor.py` | 143 | HTTP client with scope guard, rate limiter, auth injection, Burp proxy | Best-designed file in legacy. contextvars pattern, real rate limiting |
| 2 | `crawler.py` | 166 | BFS web crawler with form extraction, SPA detection, auth injection | Real crawling, real HTML parsing, real form extraction |
| 3 | `checkpoint.py` | 292 | Atomic JSON checkpoint with signal handlers, auto-save, recovery plans | Crash recovery for long scans. Real file I/O, real signal handling |
| 4 | `reporter.py` | 212 | HTML (Jinja2 + Chart.js) and Markdown report generation | Real templates, real file output, severity charts |
| 5 | `notifier.py` | 128 | Discord webhook, Telegram bot, terminal alerts on findings | Real HTTP POST to real services |
| 6 | `tool_execution_bus.py` | 160 | Subprocess execution backbone with scope checking, dedup, timeouts | Only file that actually runs external tools. Real asyncio.subprocess |
| 7 | `nuclei_bridge.py` | 71 | Nuclei scanner bridge with JSONL parsing | Real subprocess call, correct parser |
| 8 | `amass_bridge.py` | 52 | Amass subdomain enumeration bridge | Real subprocess call, correct parser |
| 9 | `katana_bridge.py` | 50 | Katana web crawler bridge | Real subprocess call, correct parser |
| 10 | `recon.py` | 419 | Subdomain discovery (crt.sh, HackerTarget, DNS brute), live host probing, info gathering | Real HTTP requests, real DNS resolution, real HTML parsing |
| 11 | `authcore/session.py` | 940 | AuthSession, CookieJar, JWTToken, CSRFToken, UserRole — full auth primitives | Production-quality data model |
| 12 | `authcore/auth_client.py` | 269 | Auth-aware HTTP client with cookie/header/JWT/API key injection | Real HTTP requests, real auth injection |
| 13 | `authcore/store.py` | 778 | SQLite-backed session store with role/org/domain queries | Real SQLite, real persistence |
| 14 | `authcore/object_inventory.py` | 922 | Object tracking for IDOR detection with SQLite persistence | Real SQLite, real ownership tracking |
| 15 | `authcore/idor_tester.py` | 826 | Cross-user IDOR testing with response fingerprinting | Real HTTP requests, real cross-user testing |
| 16 | `authcore/role_tester.py` | 597 | RBAC matrix testing, role escalation, mass assignment | Real HTTP requests, real role testing |
| 17 | `authcore/boundary_tester.py` | 622 | Horizontal IDOR, vertical privesc, session fixation | Real HTTP requests, real boundary testing |
| 18 | `authcore/multi_org_tester.py` | 551 | Cross-tenant IDOR, org_id tampering, invitation abuse | Real HTTP requests, real tenant testing |
| 19 | `authcore/graphql_tester.py` | 840 | GraphQL introspection abuse, mutation auth, field-level auth | Real HTTP requests, real GraphQL testing |
| 20 | `knowledge.py` | 275 | SQLite knowledge base with learned patterns, parameter intelligence, feedback loops | Real SQLite, real learning from results |
| 21 | `cognitive_memory.py` | 553 | 4-layer memory (episodic/semantic/working/personality), framework inference | Real persistent memory, real framework detection |
| 22 | `adaptive_methodology.py` | 255 | Rule-based methodology adjustment for SPA, GraphQL, anti-bot, JWT | Real rules, real adjustments |

---

## Category: RECOVER (Useful, Needs Adaptation)

| # | File | Lines | What It Does | What Needs Changing |
|---|---|---|---|---|
| 1 | `hypothesis_planner.py` | 403 | Deterministic hypothesis generation from goal patterns | Simplify goal patterns, remove hardcoded confidence math |
| 2 | `attack_graph.py` | 307 | Graph-based exploit chain discovery via DFS | Remove networkx dependency, use simpler graph |
| 3 | `cognitive_engine.py` | 467 | Orchestrator with tech signal extraction, gap analysis | Extract tech signal extraction, discard orchestration |
| 4 | `cognitive_refactor.py` | 463 | Circular reasoning detection, shallow loop detection | Extract anti-pattern detectors, discard observation mapping |
| 5 | `ml_core.py` | 275 | MinHash dedup, IsolationForest anomaly, Thompson bandit | Extract MinHash dedup only, discard ML components |
| 6 | `cookie_import_engine.py` | 443 | Parse cookies from Netscape/JSON/HAR/Postman formats | Clean up, remove unused export formats |
| 7 | `jwt_analysis_engine.py` | 166 | JWT algorithm confusion, KID injection, claim extraction | Standalone, needs minimal changes |
| 8 | `jwt_import_engine.py` | 278 | Import JWTs from headers/cookies/storage/text | Standalone, needs minimal changes |
| 9 | `session_abuse_engine.py` | 179 | Cookie attribute weakness detection, session fixation | Standalone analysis engine |
| 10 | `browser_session_manager.py` | 252 | Playwright session management with storage persistence | Merge with V2's browser.py |
| 11 | `auth_behavior_diff_engine.py` | 133 | Compare behavior across auth states | Standalone, clean interface |
| 12 | `discovery_effectiveness_engine.py` | 354 | Coverage tracking across 6 dimensions | Extract coverage tracking concept |
| 13 | `business_logic_reasoner.py` | ~200 | Infer workflows, detect missing steps, price manipulation | Extract price/quantity manipulation |
| 14 | `workflow_state_desynchronizer.py` | ~150 | Step skip, stale state, CSRF desync test payloads | Extract test payload generation |

---

## Category: REWRITE (Correct Idea, Poor Implementation)

| # | File | Lines | What It Does | Why Rewrite |
|---|---|---|---|---|
| 1 | `ffuf_bridge.py` | 68 | Directory fuzzing bridge | Parser is wrong for ffuf output. Need JSON output parsing |
| 2 | `sqlmap_bridge.py` | 62 | SQL injection testing bridge | Parser is too naive. Need output directory parsing |
| 3 | `proxy_core.py` | 139 | mitmproxy addon | Good concept, stub UI, needs V2 integration |
| 4 | `burp_bridge.py` | 214 | Burp Suite integration | Finding push doesn't actually POST. Need real API calls |

---

## Category: DELETE (Dead Code, Never Recover)

| Category | Files | Lines | Why Delete |
|---|---|---|---|
| **Phase validation scripts** | ~90 files (phase14-phase91) | ~15,000 | One-time test scripts, not production code |
| **DataDome research scripts** | 14 datadome*.py files | ~2,000 | Standalone bounty scripts, not integrated |
| **LLM prompt wrappers** | multi_agent.py, advanced_attacks.py, ~20 others | ~3,000 | Just prompt → LLM → JSON parse |
| **Orchestrator stubs** | privilege_escalation_engine.py, session_orchestrator.py, ~15 others | ~2,500 | Delegate to sub-engines that may not exist |
| **Dead reasoning engines** | exploit_obsession_engine.py, exploit_frustration_handler.py, exploit_intuition_engine.py, ~30 others | ~8,000 | Unvalidated cognitive theories |
| **Dead ML components** | RL/PPO agent, ChromaDB RAG, most of ml_core.py | ~500 | Experimental, no real-world validation |
| **Interactive console** | interactive.py | 116 | Never actually started in main.py |
| **Dead session engines** | session_orchestrator.py, session_db.py, session_persistence_engine.py | ~300 | Superseded by authcore/store.py |
| **Benchmark targets** | dvwa_benchmark.py, juice_shop_benchmark.py, etc. | ~500 | Test harnesses, not production |
| **Dead adapters** | brain/adapters/*.py | ~200 | Depend on deleted Brain architecture |

---

## Dependencies Required for Recovery

| Dependency | Used By | Status |
|---|---|---|
| httpx | interceptor, authcore, recon | ✅ Already in V2 |
| playwright | browser.py, browser_session_manager | ✅ Already in V2 |
| beautifulsoup4 | crawler, recon | ⚠️ Need to install |
| networkx | attack_graph | ⚠️ Need to install |
| jinja2 | reporter | ⚠️ Need to install |
| rich | multiple | ✅ Already in V2 |
| sqlite3 | knowledge, authcore | ✅ Python stdlib |
| curl_cffi | datadome_solver | ⚠️ Optional, for anti-bot |

---

## External Tools Available

| Tool | Installed | Location |
|---|---|---|
| nuclei | ✅ | `/usr/bin/nuclei` |
| ffuf | ✅ | `/usr/bin/ffuf` |
| sqlmap | ✅ | `/usr/bin/sqlmap` |
| amass | ✅ | `/usr/bin/amass` |
| katana | ✅ | `/home/akheel/go/bin/katana` |
| httpx | ✅ | `/usr/bin/httpx` |
| subfinder | ✅ | `/usr/bin/subfinder` |

**All 7 external tools are installed and available.**
