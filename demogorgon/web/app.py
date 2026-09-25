"""FastAPI Application — local web control center for DEMOGORGON.

Provides:
- Provider configuration API
- Engagement management API
- Live research monitoring via WebSocket
- Findings and evidence viewing
- Session controls (start/pause/resume/stop)

Architecture:
    Web UI → FastAPI routes → existing services (ProviderConfigManager, AgentSession, etc.)
    EventBus → WebSocketBridge → browser clients
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from pathlib import Path
from typing import Any

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.responses import HTMLResponse

from .models import (
    ProviderCreate, ProviderTestRequest, EngagementCreate,
    InstructionRequest,
)
from .ws_bridge import get_web_bridge
from ..agent.events import EventType

logger = logging.getLogger(__name__)

app = FastAPI(
    title="DEMOGORGON Control Center",
    description="Local web UI for autonomous security research",
    version="3.0.0",
)


# ── Provider API ────────────────────────────────────────────────


@app.get("/api/providers")
async def list_providers():
    """List all configured providers (without API keys)."""
    from ..config.provider_config import ProviderConfigManager
    mgr = ProviderConfigManager()
    profiles = mgr.list_providers()
    return {
        "providers": [
            {
                "provider": p.provider,
                "model": p.selected_model,
                "fast_model": p.fast_model,
                "reasoning_model": p.reasoning_model,
                "enabled": p.enabled,
                "has_key": p.api_key == "****",
                "masked_key": p.masked_key if p.api_key else None,
            }
            for p in profiles
        ]
    }


@app.post("/api/providers")
async def save_provider(req: ProviderCreate):
    """Create or update a provider configuration."""
    from ..config.provider_config import ProviderConfigManager, ProviderProfile
    mgr = ProviderConfigManager()
    profile = ProviderProfile(
        provider=req.provider,
        api_key=req.api_key,
        base_url=req.base_url,
        selected_model=req.selected_model,
        fast_model=req.fast_model,
        reasoning_model=req.reasoning_model,
        report_model=req.report_model,
    )
    mgr.save_profile(profile)
    mgr.set_active_provider(req.provider)
    mgr.load_into_environment(req.provider)
    return {"status": "ok", "provider": req.provider}


@app.post("/api/providers/test")
async def test_provider(req: ProviderTestRequest):
    """Test a provider connection."""
    from ..config.model_discovery import test_provider_connection
    result = await test_provider_connection(req.provider, req.api_key, req.base_url)
    if result.get("error"):
        from ..config.provider_config import redact_secrets
        result["error"] = redact_secrets(result["error"])
    return result


@app.get("/api/providers/active")
async def get_active_provider():
    """Get the currently active provider."""
    from ..config.provider_config import ProviderConfigManager
    mgr = ProviderConfigManager()
    active = mgr.get_active_profile()
    if not active:
        return {"provider": None}
    return {
        "provider": active.provider,
        "model": active.selected_model,
        "fast_model": active.fast_model,
        "reasoning_model": active.reasoning_model,
        "has_key": active.has_key,
        "masked_key": active.masked_key,
    }


# ── Model Discovery API ─────────────────────────────────────────


@app.get("/api/models")
async def list_models(provider: str = ""):
    """Discover available models for a provider."""
    from ..config.provider_config import ProviderConfigManager
    from ..config.model_discovery import discover_models

    mgr = ProviderConfigManager()

    if not provider:
        active = mgr.get_active_profile()
        provider = active.provider if active else ""

    if not provider:
        return {"models": [], "error": "No provider specified"}

    profile = mgr.get_profile(provider)
    api_key = profile.api_key if profile else ""
    base_url = profile.base_url if profile else ""

    models = await discover_models(provider, api_key, base_url)
    return {
        "provider": provider,
        "models": [
            {
                "id": m["id"],
                "name": m.get("name", m["id"]),
                "context_length": m.get("context_length", 0),
                "pricing": m.get("pricing"),
            }
            for m in models
        ],
    }


# ── Engagement API ──────────────────────────────────────────────


@app.post("/api/engagements")
async def create_engagement(req: EngagementCreate):
    """Create a new engagement."""
    from ..config.provider_config import ProviderConfigManager
    from ..agent.session import AgentSession, SessionConfig

    mgr = ProviderConfigManager()
    active = mgr.get_active_profile()

    if not active:
        raise HTTPException(status_code=400, detail="No provider configured")

    # Load provider into environment
    mgr.load_into_environment(active.provider)

    config = SessionConfig(
        target=req.target,
        program_text=req.program_text,
        provider=active.provider,
        model=active.selected_model,
        api_key=active.api_key,
        base_url=active.base_url,
        max_cycles=req.max_cycles,
        max_cost_usd=req.max_cost_usd,
        max_requests=req.max_requests,
        approval_level=req.approval_level,
    )

    session = AgentSession(config=config)

    # Store session reference globally
    _set_current_session(session)

    return {
        "status": "created",
        "session_id": session.session_id,
        "target": req.target,
        "provider": active.provider,
        "model": active.selected_model,
    }


@app.get("/api/engagements")
async def list_engagements():
    """List all engagements/sessions (active + saved)."""
    # Active sessions
    sessions = []
    for s in _get_all_sessions():
        sessions.append({
            "target": s.target,
            "session_id": s.session_id,
            "status": s.status.value,
            "findings": len(s.findings),
            "evidence": s.evidence_count,
            "strategy": s.strategy.state.strategy.value if hasattr(s.strategy, 'state') else "unknown",
            "active": True,
        })

    # Saved sessions from disk
    from ..agent.session import AgentSession
    saved = AgentSession.list_saved_sessions()
    for s in saved:
        # Don't duplicate if already active
        if not any(sess.target == s["target"] for sess in _get_all_sessions()):
            sessions.append({**s, "active": False})

    return {"sessions": sessions}


@app.get("/api/engagements/{engagement_id}")
async def get_engagement(engagement_id: str):
    """Get engagement details."""
    session = _get_session_by_id(engagement_id)
    if not session:
        raise HTTPException(status_code=404, detail="Engagement not found")
    return {
        "target": session.target,
        "status": session.status.value,
        "findings": len(session.findings),
        "evidence": session.evidence_count,
        "budget": session.budget.get_usage_display(),
        "strategy": session.strategy.state.strategy.value if hasattr(session.strategy, 'state') else "unknown",
    }


@app.post("/api/engagements/{engagement_id}/start")
async def start_engagement(engagement_id: str):
    """Start an engagement."""
    session = _get_session_by_id(engagement_id)
    if not session:
        raise HTTPException(status_code=404, detail="Engagement not found")

    # Start in background
    asyncio.create_task(_run_session(session))
    return {"status": "started"}


@app.post("/api/engagements/{engagement_id}/pause")
async def pause_engagement(engagement_id: str):
    """Pause an engagement."""
    session = _get_session_by_id(engagement_id)
    if not session:
        raise HTTPException(status_code=404, detail="Engagement not found")
    session.is_paused = True
    await session.events.emit(EventType.STATUS_CHANGE, {"status": "paused"}, source="web")
    return {"status": "paused", "session_id": engagement_id}


@app.post("/api/engagements/{engagement_id}/resume")
async def resume_engagement(engagement_id: str):
    """Resume an engagement."""
    session = _get_session_by_id(engagement_id)
    if not session:
        raise HTTPException(status_code=404, detail="Engagement not found")
    session.is_paused = False
    await session.events.emit(EventType.STATUS_CHANGE, {"status": "resumed"}, source="web")
    return {"status": "resumed", "session_id": engagement_id}


@app.post("/api/engagements/{engagement_id}/stop")
async def stop_engagement(engagement_id: str):
    """Stop an engagement."""
    session = _get_session_by_id(engagement_id)
    if not session:
        raise HTTPException(status_code=404, detail="Engagement not found")
    await session.stop()
    return {"status": "stopped"}


@app.post("/api/engagements/resume/{target:path}")
async def resume_saved_session(target: str):
    """Resume a saved session from disk."""
    from ..agent.session import AgentSession
    saved = AgentSession.list_saved_sessions()
    for s in saved:
        if s["target"] == target:
            session = AgentSession.load_state(s["workspace"])
            _set_current_session(session)
            asyncio.create_task(_run_session(session))
            return {"status": "resumed", "target": target}
    raise HTTPException(status_code=404, detail="Saved session not found")


@app.post("/api/engagements/{engagement_id}/instructions")
async def send_instruction(engagement_id: str, req: InstructionRequest):
    """Send a natural language instruction to the agent."""
    session = _get_session_by_id(engagement_id)
    if not session:
        raise HTTPException(status_code=404, detail="Engagement not found")

    # Parse instruction through NaturalLanguageParser
    try:
        from ..agent.natural_language import NaturalLanguageParser
        parser = NaturalLanguageParser()
        result = parser.parse(req.instruction)
        return {"status": "parsed", "intent": result.intent, "params": result.params}
    except Exception as e:
        return {"status": "error", "error": str(e)}


# ── Findings API ────────────────────────────────────────────────


@app.get("/api/engagements/{engagement_id}/findings")
async def get_findings(engagement_id: str):
    """Get findings for an engagement."""
    session = _get_session_by_id(engagement_id)
    if not session:
        raise HTTPException(status_code=404, detail="Engagement not found")
    return {"findings": session.findings}


@app.get("/api/engagements/{engagement_id}/export")
async def export_findings(engagement_id: str):
    """Export findings as JSON for download."""
    session = _get_session_by_id(engagement_id)
    if not session:
        raise HTTPException(status_code=404, detail="Engagement not found")
    return {
        "target": session.target,
        "session_id": session.session_id,
        "findings": session.findings,
        "evidence_count": session.evidence_count,
        "summary": {
            "total_findings": len(session.findings),
            "total_evidence": session.evidence_count,
        },
    }


@app.get("/api/engagements/{engagement_id}/evidence")
async def get_evidence(engagement_id: str):
    """Get evidence for an engagement."""
    session = _get_session_by_id(engagement_id)
    if not session:
        raise HTTPException(status_code=404, detail="Engagement not found")
    return {"evidence_count": session.evidence_count}


@app.get("/api/engagements/{engagement_id}/trace")
async def get_trace(engagement_id: str):
    """Get research trace for an engagement."""
    session = _get_session_by_id(engagement_id)
    if not session:
        raise HTTPException(status_code=404, detail="Engagement not found")

    entries = session.trace.get_recent(50)
    return {
        "trace": [
            {
                "type": e.type.value,
                "content": e.content,
                "timestamp": e.timestamp,
                "iteration": e.iteration,
            }
            for e in entries
        ]
    }


# ── Scope Management API ──────────────────────────────────────


@app.get("/api/engagements/{engagement_id}/scope")
async def get_scope(engagement_id: str):
    """Get scope assets for an engagement."""
    session = _get_session_by_id(engagement_id)
    if not session:
        raise HTTPException(status_code=404, detail="Engagement not found")
    return {
        "in_scope": session.scope_assets,
        "out_of_scope": session.out_of_scope,
        "restrictions": session.restrictions,
    }


@app.post("/api/engagements/{engagement_id}/scope")
async def add_scope(engagement_id: str, req: dict):
    """Add a scope asset to an engagement."""
    session = _get_session_by_id(engagement_id)
    if not session:
        raise HTTPException(status_code=404, detail="Engagement not found")

    pattern = req.get("pattern", "").strip()
    asset_type = req.get("asset_type", "url")
    description = req.get("description", "")

    if not pattern:
        raise HTTPException(status_code=400, detail="Pattern is required")

    asset = {"pattern": pattern, "asset_type": asset_type, "description": description}
    session.scope_assets.append(asset)

    await session.events.emit(
        EventType.LOG,
        {"message": f"Scope added: {pattern} ({asset_type})"},
        source="web",
    )

    return {"status": "added", "asset": asset, "total": len(session.scope_assets)}


@app.delete("/api/engagements/{engagement_id}/scope/{pattern:path}")
async def remove_scope(engagement_id: str, pattern: str):
    """Remove a scope asset from an engagement."""
    session = _get_session_by_id(engagement_id)
    if not session:
        raise HTTPException(status_code=404, detail="Engagement not found")

    before = len(session.scope_assets)
    session.scope_assets = [a for a in session.scope_assets if a.get("pattern") != pattern]
    removed = before - len(session.scope_assets)

    if removed:
        await session.events.emit(
            EventType.LOG,
            {"message": f"Scope removed: {pattern}"},
            source="web",
        )

    return {"status": "removed" if removed else "not_found", "total": len(session.scope_assets)}


# ── Findings Detail API ───────────────────────────────────────


@app.get("/api/engagements/{engagement_id}/findings/{finding_idx:int}")
async def get_finding_detail(engagement_id: str, finding_idx: int):
    """Get a specific finding by index."""
    session = _get_session_by_id(engagement_id)
    if not session:
        raise HTTPException(status_code=404, detail="Engagement not found")
    if finding_idx < 0 or finding_idx >= len(session.findings):
        raise HTTPException(status_code=404, detail="Finding not found")
    return {"finding": session.findings[finding_idx], "index": finding_idx}


# ── Evidence Detail API ───────────────────────────────────────


@app.get("/api/engagements/{engagement_id}/evidence/{evidence_idx:int}")
async def get_evidence_detail(engagement_id: str, evidence_idx: int):
    """Get a specific evidence pack by index."""
    session = _get_session_by_id(engagement_id)
    if not session:
        raise HTTPException(status_code=404, detail="Engagement not found")
    # Evidence is stored on disk in workspace
    if not session.workspace_dir:
        raise HTTPException(status_code=404, detail="No workspace")
    evidence_dir = os.path.join(session.workspace_dir, "evidence")
    if not os.path.exists(evidence_dir):
        return {"evidence": None}
    files = sorted(os.listdir(evidence_dir))
    if evidence_idx < 0 or evidence_idx >= len(files):
        raise HTTPException(status_code=404, detail="Evidence not found")
    filepath = os.path.join(evidence_dir, files[evidence_idx])
    try:
        import json
        content = json.loads(Path(filepath).read_text())
    except Exception:
        content = {"file": files[evidence_idx]}
    return {"evidence": content, "filename": files[evidence_idx]}


# ── Session Summary API ───────────────────────────────────────


@app.get("/api/engagements/{engagement_id}/summary")
async def get_session_summary(engagement_id: str):
    """Get a full session summary with stats."""
    session = _get_session_by_id(engagement_id)
    if not session:
        raise HTTPException(status_code=404, detail="Engagement not found")

    duration = time.time() - session.start_time if session.start_time else 0
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in session.findings:
        sev = f.get("severity", "info").lower()
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

    return {
        "target": session.target,
        "session_id": session.session_id,
        "status": session.status.value,
        "strategy": session.strategy.state.strategy.value if hasattr(session.strategy, "state") else "unknown",
        "duration_seconds": duration,
        "total_cycles": session.strategy.state.total_cycles if hasattr(session.strategy, "state") else 0,
        "findings_total": len(session.findings),
        "findings_by_severity": sev_counts,
        "evidence_count": session.evidence_count,
        "chains": len(session.chains),
        "scope_count": len(session.scope_assets),
        "budget": session.budget.get_usage_display(),
        "tokens": session.token_tracker.live_display,
    }


# ── Tools & MCP API ────────────────────────────────────────────


@app.get("/api/tools")
async def list_tools():
    """List available security tools (ToolManager adapters + capability registry)."""
    from ..agent.capabilities import CapabilityRegistry
    from ..tools.manager import create_default_tool_manager

    registry = CapabilityRegistry()
    caps = registry.get_available_capabilities()

    manager = create_default_tool_manager()
    tools = []
    for name, adapter in manager._adapters.items():
        try:
            available = await adapter.discover()
        except Exception:
            available = False
        tools.append({"name": name, "available": available, "category": getattr(adapter.category, "value", str(adapter.category))})

    return {"capabilities": caps, "tools": tools}


@app.get("/api/mcp")
async def list_mcp():
    """List MCP servers and their status."""
    return {"servers": []}


# ── Session Status API ──────────────────────────────────────────


@app.get("/api/status")
async def get_status():
    """Get overall system status."""
    from ..config.provider_config import ProviderConfigManager
    mgr = ProviderConfigManager()
    active = mgr.get_active_profile()

    return {
        "provider": active.provider if active else None,
        "model": active.selected_model if active else None,
        "fast_model": active.fast_model if active else None,
        "reasoning_model": active.reasoning_model if active else None,
        "has_key": active.has_key if active else False,
        "sessions": len(_get_all_sessions()),
        "bridge_clients": get_web_bridge().client_count,
    }


# ── WebSocket ───────────────────────────────────────────────────


@app.websocket("/ws/events")
async def websocket_events(websocket: WebSocket):
    """WebSocket endpoint for live event streaming."""
    bridge = get_web_bridge()
    await bridge.connect(websocket)
    try:
        while True:
            # Keep connection alive, receive any client messages
            data = await websocket.receive_text()
            # Client can send commands via WebSocket too
            # For now, just acknowledge
            await websocket.send_json({"type": "ack", "data": data})
    except WebSocketDisconnect:
        await bridge.disconnect(websocket)
    except Exception:
        await bridge.disconnect(websocket)


# ── Static Files (Frontend) ────────────────────────────────────


@app.get("/", response_class=HTMLResponse)
async def root():
    """Redirect to /setup if no provider, else /hunt."""
    from ..config.provider_config import ProviderConfigManager
    mgr = ProviderConfigManager()
    active = mgr.get_active_profile()
    if active and active.has_key:
        return HTMLResponse(content=_hunt_html(), status_code=200)
    return HTMLResponse(content=_setup_html(), status_code=200)


@app.get("/setup", response_class=HTMLResponse)
async def setup_page():
    """Provider/model configuration page."""
    return HTMLResponse(content=_setup_html(), status_code=200)


@app.get("/new-hunt", response_class=HTMLResponse)
async def new_hunt_page():
    """New engagement creation page."""
    return HTMLResponse(content=_new_hunt_html(), status_code=200)


@app.get("/hunt", response_class=HTMLResponse)
async def hunt_page():
    """Live research dashboard (current session)."""
    return HTMLResponse(content=_hunt_html(), status_code=200)


@app.get("/hunt/{session_id}", response_class=HTMLResponse)
async def hunt_session_page(session_id: str):
    """Live research dashboard for a specific session."""
    return HTMLResponse(content=_hunt_html(session_id), status_code=200)


@app.get("/findings", response_class=HTMLResponse)
async def findings_page():
    """Findings list page."""
    return HTMLResponse(content=_findings_html(), status_code=200)


@app.get("/hunts", response_class=HTMLResponse)
async def hunts_page():
    """Hunts dashboard — list all hunts with status and progress."""
    return HTMLResponse(content=_hunts_html(), status_code=200)


# ── Internal State ──────────────────────────────────────────────

_current_session = None
_sessions: dict[str, Any] = {}


def set_terminal_session(session) -> None:
    """Set the terminal's AgentSession so web UI shares it.

    Called by AgentMain after session creation.
    """
    global _current_session
    _current_session = session
    _sessions[session.session_id] = session
    _sessions[f"target:{session.target}"] = session

    # Wire EventBus to WebSocket bridge
    try:
        bridge = get_web_bridge()
        session.events.on_all(bridge.handle_event)
    except Exception as e:
        logger.warning(f"Could not wire EventBus to WebSocket bridge: {e}")


def _set_current_session(session):
    global _current_session
    _current_session = session
    _sessions[session.session_id] = session
    # Also store by target for backward compat
    _sessions[f"target:{session.target}"] = session

    # Wire EventBus to WebSocket bridge for real-time updates
    try:
        bridge = get_web_bridge()
        session.events.on_all(bridge.handle_event)
    except Exception as e:
        logger.warning(f"Could not wire EventBus to WebSocket bridge: {e}")


def _get_all_sessions() -> list:
    # Include terminal session if set
    sessions = list(_sessions.values())
    if _current_session and _current_session not in sessions:
        sessions.insert(0, _current_session)
    return sessions


def _get_session_by_id(session_id: str):
    # Try direct session_id lookup (UUID)
    if session_id in _sessions:
        return _sessions[session_id]
    # Try target lookup
    target_key = f"target:{session_id}"
    if target_key in _sessions:
        return _sessions[target_key]
    # Try matching by target on current session
    if _current_session and (_current_session.target == session_id or _current_session.session_id == session_id):
        return _current_session
    # Fallback: search all sessions by target
    for key, sess in _sessions.items():
        if hasattr(sess, 'target') and sess.target == session_id:
            return sess
    return None


async def _run_session(session):
    """Run a session in the background."""
    try:
        await session.initialize()
        await session.run()
    except Exception as e:
        logger.error(f"Session failed: {e}")


def _get_dashboard_html() -> str:
    """Return the dashboard HTML (legacy)."""
    return _hunt_html()


# ── Page HTML Generators ───────────────────────────────────────

_SHARED_CSS = """
:root {
  --bg: #07070c;
  --bg-elevated: #0e0e16;
  --bg-panel: #12121c;
  --bg-glass: rgba(18, 18, 28, 0.78);
  --bg-input: #0a0a12;
  --border: #1e1e30;
  --border-glow: rgba(0, 212, 255, 0.35);
  --text: #e8eaf0;
  --text-muted: #8b90a0;
  --text-dim: #5a5f70;
  --accent: #00d4ff;
  --accent-2: #a855f7;
  --accent-grad: linear-gradient(135deg, #00d4ff, #22d3ee);
  --success: #34d399;
  --warning: #fbbf24;
  --danger: #f87171;
  --critical: #ef4444;
  --high: #f97316;
  --medium: #eab308;
  --low: #60a5fa;
  --info: #94a3b8;
  --radius-sm: 6px;
  --radius: 10px;
  --radius-lg: 16px;
  --shadow: 0 4px 24px rgba(0,0,0,0.45);
  --glow: 0 0 20px rgba(0,212,255,0.25);
  --font-sans: "Inter", "Segoe UI", system-ui, -apple-system, sans-serif;
  --font-mono: "JetBrains Mono", "Fira Code", "SF Mono", ui-monospace, monospace;
}
* { margin: 0; padding: 0; box-sizing: border-box; }
html { scroll-behavior: smooth; }
body { font-family: var(--font-sans); background: var(--bg); color: var(--text); min-height: 100vh; line-height: 1.5; }
body::before { content: ""; position: fixed; inset: 0; background: radial-gradient(ellipse 80% 50% at 50% -20%, rgba(0,212,255,0.07), transparent), radial-gradient(ellipse 60% 40% at 100% 100%, rgba(168,85,247,0.05), transparent); pointer-events: none; z-index: 0; }
.mono, code, pre, .input, textarea, .stat .value, .event, .finding-item { font-family: var(--font-mono); }
a { color: var(--accent); text-decoration: none; transition: color 0.15s; }
a:hover { color: #33e0ff; text-decoration: none; }
.header { position: sticky; top: 0; z-index: 100; background: var(--bg-glass); backdrop-filter: blur(14px); -webkit-backdrop-filter: blur(14px); border-bottom: 1px solid var(--border); padding: 14px 28px; display: flex; align-items: center; justify-content: space-between; gap: 20px; }
.brand { display: flex; align-items: center; gap: 10px; }
.brand-mark { width: 28px; height: 28px; border-radius: 7px; background: var(--accent-grad); display: flex; align-items: center; justify-content: center; font-weight: 800; font-size: 13px; color: #05050a; box-shadow: var(--glow); flex-shrink: 0; }
.header h1 { font-size: 15px; font-weight: 700; letter-spacing: 2.5px; color: var(--text); font-family: var(--font-mono); }
.header h1 span { color: var(--accent); }
.header nav { display: flex; gap: 4px; font-size: 13px; font-weight: 500; }
.header nav a { color: var(--text-muted); padding: 7px 14px; border-radius: var(--radius-sm); transition: all 0.15s; position: relative; }
.header nav a:hover { color: var(--text); background: rgba(255,255,255,0.04); text-decoration: none; }
.header nav a.active { color: var(--accent); background: rgba(0,212,255,0.08); box-shadow: inset 0 -2px 0 var(--accent); }
.header .status { font-size: 11px; font-weight: 600; letter-spacing: 1px; font-family: var(--font-mono); display: flex; align-items: center; gap: 6px; color: var(--text-dim); }
.header .status .dot { width: 7px; height: 7px; border-radius: 50%; background: var(--text-dim); box-shadow: 0 0 6px currentColor; }
.header .status.connected { color: var(--success); }
.header .status.connected .dot { background: var(--success); animation: pulse 2s infinite; }
.header .status.offline { color: var(--danger); }
.header .status.offline .dot { background: var(--danger); }
.header .status.reconnecting { color: var(--warning); }
.header .status.reconnecting .dot { background: var(--warning); animation: pulse 1s infinite; }
@keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: 0.4; } }
.container { max-width: 1240px; margin: 0 auto; padding: 28px; position: relative; z-index: 1; }
.page-title { font-size: 22px; font-weight: 700; margin-bottom: 4px; }
.page-sub { color: var(--text-muted); font-size: 13px; margin-bottom: 24px; }
.panel { background: var(--bg-panel); border: 1px solid var(--border); border-radius: var(--radius-lg); padding: 20px; margin-bottom: 18px; box-shadow: var(--shadow); position: relative; overflow: hidden; }
.panel::before { content: ""; position: absolute; top: 0; left: 0; right: 0; height: 1px; background: linear-gradient(90deg, transparent, rgba(0,212,255,0.3), transparent); }
.panel h3 { color: var(--accent); font-size: 11px; margin-bottom: 16px; text-transform: uppercase; letter-spacing: 1.5px; font-weight: 700; display: flex; align-items: center; gap: 8px; }
.panel h3 .count { color: var(--text-dim); font-weight: 400; letter-spacing: 0; }
.stat { display: flex; justify-content: space-between; align-items: center; padding: 9px 0; border-bottom: 1px solid rgba(30,30,48,0.7); font-size: 13px; gap: 12px; }
.stat:last-child { border-bottom: none; }
.stat .label { color: var(--text-muted); font-size: 12px; }
.stat .value { color: var(--text); font-weight: 600; font-size: 12px; text-align: right; word-break: break-all; }
.btn { display: inline-flex; align-items: center; justify-content: center; gap: 7px; background: var(--bg-elevated); color: var(--text); border: 1px solid var(--border); padding: 10px 20px; border-radius: var(--radius); cursor: pointer; font-family: var(--font-sans); font-size: 13px; font-weight: 600; transition: all 0.18s; }
.btn:hover { background: #161622; border-color: #2e2e45; transform: translateY(-1px); }
.btn:active { transform: translateY(0); }
.btn:disabled { opacity: 0.5; cursor: not-allowed; transform: none; }
.btn:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
.btn.primary { background: var(--accent-grad); color: #05050a; border: none; box-shadow: 0 2px 12px rgba(0,212,255,0.3); }
.btn.primary:hover { box-shadow: 0 4px 20px rgba(0,212,255,0.45); transform: translateY(-1px); filter: brightness(1.08); }
.btn.danger { background: rgba(239,68,68,0.12); color: var(--danger); border-color: rgba(239,68,68,0.35); }
.btn.danger:hover { background: rgba(239,68,68,0.2); border-color: var(--danger); }
.btn.success { background: rgba(52,211,153,0.12); color: var(--success); border-color: rgba(52,211,153,0.35); }
.btn.success:hover { background: rgba(52,211,153,0.2); border-color: var(--success); }
.btn.sm { padding: 6px 12px; font-size: 12px; border-radius: var(--radius-sm); }
.btn.block { width: 100%; }
.input { background: var(--bg-input); color: var(--text); border: 1px solid var(--border); padding: 11px 14px; border-radius: var(--radius); font-size: 13px; width: 100%; transition: border-color 0.15s, box-shadow 0.15s; }
.input:focus { outline: none; border-color: var(--accent); box-shadow: 0 0 0 3px rgba(0,212,255,0.12); }
.input::placeholder { color: var(--text-dim); }
textarea.input { min-height: 130px; resize: vertical; line-height: 1.55; }
select.input { appearance: none; background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='10' height='6' fill='%238b90a0'%3E%3Cpath d='M0 0l5 6 5-6z'/%3E%3C/svg%3E"); background-repeat: no-repeat; background-position: right 14px center; padding-right: 34px; cursor: pointer; }
label { display: block; color: var(--text-muted); font-size: 11px; margin-bottom: 7px; text-transform: uppercase; letter-spacing: 0.8px; font-weight: 600; }
.form-group { margin-bottom: 18px; }
.form-group .hint { font-size: 11px; color: var(--text-dim); margin-top: 5px; }
.row { display: flex; gap: 16px; }
.row > * { flex: 1; }
.empty { color: var(--text-dim); font-size: 13px; padding: 28px 16px; text-align: center; line-height: 1.6; }
.empty .icon { font-size: 28px; display: block; margin-bottom: 8px; opacity: 0.5; }
.badge { display: inline-flex; align-items: center; gap: 4px; padding: 3px 9px; border-radius: 99px; font-size: 10px; font-weight: 700; letter-spacing: 0.6px; text-transform: uppercase; font-family: var(--font-mono); }
.badge.green { background: rgba(52,211,153,0.12); color: var(--success); border: 1px solid rgba(52,211,153,0.3); }
.badge.red { background: rgba(239,68,68,0.12); color: var(--danger); border: 1px solid rgba(239,68,68,0.3); }
.badge.yellow { background: rgba(251,191,36,0.12); color: var(--warning); border: 1px solid rgba(251,191,36,0.3); }
.badge.blue { background: rgba(96,165,250,0.12); color: var(--low); border: 1px solid rgba(96,165,250,0.3); }
.badge.cyan { background: rgba(0,212,255,0.1); color: var(--accent); border: 1px solid rgba(0,212,255,0.3); }
.badge.purple { background: rgba(168,85,247,0.12); color: var(--accent-2); border: 1px solid rgba(168,85,247,0.3); }
.badge.gray { background: rgba(148,163,184,0.1); color: var(--info); border: 1px solid rgba(148,163,184,0.25); }
.sev-critical { color: var(--critical); }
.sev-high { color: var(--high); }
.sev-medium { color: var(--medium); }
.sev-low { color: var(--low); }
.sev-info, .sev-unknown { color: var(--info); }
.grid { display: grid; grid-template-columns: 1fr 1fr; gap: 18px; }
.meter { height: 6px; background: var(--bg-input); border-radius: 99px; overflow: hidden; margin-top: 6px; }
.meter-fill { height: 100%; background: var(--accent-grad); border-radius: 99px; transition: width 0.5s ease; }
.meter-fill.warn { background: linear-gradient(90deg, #fbbf24, #f97316); }
.meter-fill.danger { background: linear-gradient(90deg, #ef4444, #dc2626); }
.meter-fill.ok { background: linear-gradient(90deg, #34d399, #10b981); }
.meter-row { display: flex; justify-content: space-between; font-size: 11px; margin-bottom: 4px; }
.meter-row .lbl { color: var(--text-muted); }
.meter-row .val { color: var(--text); font-weight: 600; font-family: var(--font-mono); }
.toast-container { position: fixed; bottom: 24px; right: 24px; z-index: 9999; display: flex; flex-direction: column; gap: 10px; }
.toast { padding: 13px 20px; border-radius: var(--radius); font-size: 13px; font-family: var(--font-sans); color: white; opacity: 0; transform: translateX(80px); animation: toastIn 0.3s ease forwards; max-width: 400px; word-break: break-word; box-shadow: var(--shadow); font-weight: 500; display: flex; align-items: center; gap: 8px; }
.toast.error { background: linear-gradient(135deg, #7f1d1d, #991b1b); border: 1px solid rgba(239,68,68,0.5); }
.toast.success { background: linear-gradient(135deg, #064e3b, #166534); border: 1px solid rgba(52,211,153,0.5); }
.toast.info { background: linear-gradient(135deg, #0c4a6e, #1e40af); border: 1px solid rgba(96,165,250,0.5); }
@keyframes toastIn { to { opacity: 1; transform: translateX(0); } }
@keyframes toastOut { to { opacity: 0; transform: translateX(80px); } }
.spinner { display: inline-block; width: 16px; height: 16px; border: 2px solid rgba(0,212,255,0.15); border-top-color: var(--accent); border-radius: 50%; animation: spin 0.7s linear infinite; }
.spinner.lg { width: 28px; height: 28px; border-width: 3px; }
@keyframes spin { to { transform: rotate(360deg); } }
.loading-overlay { display: flex; align-items: center; justify-content: center; gap: 10px; padding: 32px; color: var(--text-muted); font-size: 13px; }
.skeleton { background: linear-gradient(90deg, var(--bg-elevated) 25%, #16162a 50%, var(--bg-elevated) 75%); background-size: 200% 100%; animation: shimmer 1.5s infinite; border-radius: var(--radius-sm); height: 14px; margin-bottom: 10px; }
@keyframes shimmer { 0% { background-position: 200% 0; } 100% { background-position: -200% 0; } }
.empty-state { text-align: center; padding: 48px 24px; color: var(--text-muted); }
.empty-state .icon { font-size: 40px; display: block; margin-bottom: 14px; opacity: 0.4; }
.empty-state h4 { color: var(--text); font-size: 15px; margin-bottom: 8px; font-weight: 600; }
.empty-state p { font-size: 13px; max-width: 380px; margin: 0 auto 18px; line-height: 1.6; }
.modal-overlay { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.75); backdrop-filter: blur(6px); z-index: 1000; justify-content: center; align-items: center; padding: 24px; }
.modal-overlay.show { display: flex; animation: fadeIn 0.2s ease; }
@keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
.modal-content { background: var(--bg-panel); border: 1px solid var(--border); border-radius: var(--radius-lg); padding: 28px; max-width: 720px; width: 100%; max-height: 85vh; overflow-y: auto; box-shadow: 0 24px 64px rgba(0,0,0,0.6); position: relative; }
.modal-content h3 { color: var(--accent); margin-bottom: 16px; font-size: 16px; }
.modal-header { display: flex; justify-content: space-between; align-items: flex-start; gap: 16px; margin-bottom: 20px; }
.modal-close { background: var(--bg-elevated); border: 1px solid var(--border); color: var(--text-muted); width: 32px; height: 32px; border-radius: var(--radius-sm); cursor: pointer; font-size: 16px; display: flex; align-items: center; justify-content: center; flex-shrink: 0; transition: all 0.15s; }
.modal-close:hover { color: var(--text); border-color: #2e2e45; background: #161622; }
.field { margin-bottom: 14px; }
.field .label { color: var(--text-dim); font-size: 10px; text-transform: uppercase; letter-spacing: 1px; font-weight: 700; margin-bottom: 5px; }
.field .val { color: var(--text); font-size: 13px; line-height: 1.6; }
.field pre, pre.code { background: var(--bg-input); padding: 14px; border-radius: var(--radius); font-size: 12px; overflow-x: auto; color: #c8d0e0; border: 1px solid var(--border); line-height: 1.5; font-family: var(--font-mono); white-space: pre-wrap; word-break: break-word; }
.kpi-strip { display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 14px; margin-bottom: 20px; }
.kpi { background: var(--bg-panel); border: 1px solid var(--border); border-radius: var(--radius); padding: 16px; text-align: center; }
.kpi .big { font-size: 26px; font-weight: 800; color: var(--accent); font-family: var(--font-mono); line-height: 1.1; }
.kpi .lbl { font-size: 10px; color: var(--text-dim); text-transform: uppercase; letter-spacing: 1px; margin-top: 5px; font-weight: 600; }
.kpi.green .big { color: var(--success); }
.kpi.yellow .big { color: var(--warning); }
.kpi.blue .big { color: var(--low); }
.kpi.purple .big { color: var(--accent-2); }
.kpi.red .big { color: var(--critical); }
.filter-bar { display: flex; gap: 8px; margin-bottom: 18px; flex-wrap: wrap; align-items: center; }
.filter-btn { background: var(--bg-elevated); color: var(--text-muted); border: 1px solid var(--border); padding: 7px 16px; border-radius: 99px; cursor: pointer; font-family: var(--font-sans); font-size: 12px; font-weight: 600; transition: all 0.15s; }
.filter-btn:hover { color: var(--text); border-color: #2e2e45; }
.filter-btn.active { color: #05050a; background: var(--accent-grad); border-color: transparent; box-shadow: 0 2px 10px rgba(0,212,255,0.3); }
.provider-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(140px, 1fr)); gap: 10px; margin-bottom: 18px; }
.provider-tile { background: var(--bg-elevated); border: 1px solid var(--border); border-radius: var(--radius); padding: 14px 12px; text-align: center; cursor: pointer; transition: all 0.18s; font-size: 12px; font-weight: 600; color: var(--text-muted); }
.provider-tile:hover { border-color: #2e2e45; transform: translateY(-2px); }
.provider-tile.active { border-color: var(--accent); background: rgba(0,212,255,0.06); color: var(--accent); box-shadow: 0 0 16px rgba(0,212,255,0.15); }
.provider-tile .picon { width: 36px; height: 36px; border-radius: 8px; background: var(--bg-panel); display: flex; align-items: center; justify-content: center; margin: 0 auto 8px; font-weight: 800; font-size: 14px; color: var(--accent); border: 1px solid var(--border); }
.provider-tile.active .picon { border-color: rgba(0,212,255,0.4); }
.search-box { position: relative; flex: 1; min-width: 200px; }
.search-box .input { padding-left: 38px; }
.search-box::before { content: "⌕"; position: absolute; left: 14px; top: 50%; transform: translateY(-50%); color: var(--text-dim); font-size: 16px; pointer-events: none; z-index: 1; }
.tip-list { list-style: none; font-size: 13px; color: var(--text-muted); line-height: 1.5; }
.tip-list li { padding: 7px 0 7px 26px; position: relative; border-bottom: 1px solid rgba(30,30,48,0.5); }
.tip-list li:last-child { border-bottom: none; }
.tip-list li::before { content: "▸"; position: absolute; left: 6px; color: var(--accent); }
.check-list { list-style: none; font-size: 13px; }
.check-list li { padding: 8px 0; color: var(--text-muted); display: flex; gap: 10px; align-items: flex-start; }
.check-list li::before { content: "✓"; color: var(--success); font-weight: 700; flex-shrink: 0; }
@media (max-width: 900px) { .grid { grid-template-columns: 1fr; } .row { flex-direction: column; } .header { flex-wrap: wrap; } .header nav { order: 3; width: 100%; overflow-x: auto; } }
@media (max-width: 600px) { .container { padding: 16px; } .kpi-strip { grid-template-columns: repeat(2, 1fr); } }
"""

_SHARED_JS = """
function escapeHtml(s) {
    if (s === null || s === undefined) return '';
    const d = document.createElement('div');
    d.appendChild(document.createTextNode(String(s)));
    return d.innerHTML;
}
function showToast(msg, type) {
    type = type || 'info';
    let c = document.querySelector('.toast-container');
    if (!c) { c = document.createElement('div'); c.className = 'toast-container'; document.body.appendChild(c); }
    const t = document.createElement('div');
    t.className = 'toast ' + type;
    t.textContent = msg;
    c.appendChild(t);
    setTimeout(() => { t.style.animation = 'toastOut 0.3s ease forwards'; setTimeout(() => t.remove(), 300); }, 4000);
}
function showLoading(el, text) {
    if (!el) return;
    el.innerHTML = '<div class="loading-overlay"><div class="spinner"></div> ' + (text || 'Loading...') + '</div>';
}
function setWsStatus(state) {
    const el = document.getElementById('ws-status');
    if (!el) return;
    el.className = 'status ' + state;
    const labels = { connected: 'CONNECTED', offline: 'OFFLINE', reconnecting: 'RECONNECTING', connecting: 'CONNECTING' };
    el.innerHTML = '<span class="dot"></span> ' + (labels[state] || state.toUpperCase());
}
function connectWs(onMessage, onOpen, onClose) {
    let retries = 0;
    function open() {
        const proto = location.protocol === 'https:' ? 'wss' : 'ws';
        const ws = new WebSocket(proto + '://' + location.host + '/ws/events');
        ws.onopen = () => { retries = 0; setWsStatus('connected'); if (onOpen) onOpen(ws); };
        ws.onmessage = (e) => { try { if (onMessage) onMessage(JSON.parse(e.data)); } catch (err) {} };
        ws.onclose = () => {
            retries++;
            setWsStatus(retries > 1 ? 'reconnecting' : 'connecting');
            if (onClose) onClose();
            const delay = Math.min(1000 * Math.pow(1.6, retries), 15000);
            setTimeout(open, delay);
        };
        ws.onerror = () => { try { ws.close(); } catch (e) {} };
    }
    open();
}
function confirmAction(msg) { return window.confirm(msg); }
function sevClass(sev) { return 'sev-' + String(sev || 'unknown').toLowerCase(); }
function sevBadge(sev) {
    const s = String(sev || 'unknown').toLowerCase();
    const colors = { critical: 'red', high: 'yellow', medium: 'yellow', low: 'blue', info: 'gray', unknown: 'gray' };
    return '<span class="badge ' + (colors[s] || 'gray') + '">' + escapeHtml(s.toUpperCase()) + '</span>';
}
function fmtTime(ts) {
    try { return new Date(ts > 1e12 ? ts : ts * 1000).toLocaleTimeString(); } catch (e) { return ''; }
}
function pct(used, max) { if (!max) return 0; return Math.min(100, Math.round((used / max) * 100)); }
function meter(label, used, max, suffix) {
    const p = pct(used, max);
    const cls = p >= 90 ? 'danger' : p >= 70 ? 'warn' : '';
    const display = suffix === '$' ? '$' + (used || 0).toFixed(2) : (used || 0) + (max ? '/' + max : '');
    return '<div class="meter-row"><span class="lbl">' + label + '</span><span class="val">' + display + '</span></div>' +
           '<div class="meter"><div class="meter-fill ' + cls + '" style="width:' + p + '%"></div></div>';
}
"""


def _header(active: str) -> str:
    links = [
        ("setup", "Setup", "/setup"),
        ("hunts", "Hunts", "/hunts"),
        ("new-hunt", "New Hunt", "/new-hunt"),
        ("hunt", "Dashboard", "/hunt"),
        ("findings", "Findings", "/findings"),
    ]
    nav = "".join(
        f'<a href="{href}" class="{"active" if key == active else ""}">{label}</a>'
        for key, label, href in links
    )
    return f"""<header class="header">
    <div class="brand">
        <div class="brand-mark">D</div>
        <h1>DEMO<span>GORGON</span></h1>
    </div>
    <nav>{nav}</nav>
    <div class="status connecting" id="ws-status"><span class="dot"></span> CONNECTING</div>
</header>"""


def _setup_html() -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DEMOGORGON — Setup</title>
    <style>{_SHARED_CSS}</style>
</head>
<body>
    {_header("setup")}
    <div class="container">
        <div class="page-title">Configure your AI</div>
        <div class="page-sub">Connect a provider, pick dual models, and verify tools before hunting.</div>
        <div class="grid">
            <div>
                <div class="panel">
                    <h3>Provider</h3>
                    <div class="provider-grid" id="provider-tiles">
                        <div class="provider-tile active" data-p="openrouter" onclick="selectProvider('openrouter')"><div class="picon">OR</div>OpenRouter</div>
                        <div class="provider-tile" data-p="openai" onclick="selectProvider('openai')"><div class="picon">AI</div>OpenAI</div>
                        <div class="provider-tile" data-p="anthropic" onclick="selectProvider('anthropic')"><div class="picon">AN</div>Anthropic</div>
                        <div class="provider-tile" data-p="gemini" onclick="selectProvider('gemini')"><div class="picon">GM</div>Gemini</div>
                        <div class="provider-tile" data-p="deepseek" onclick="selectProvider('deepseek')"><div class="picon">DS</div>DeepSeek</div>
                        <div class="provider-tile" data-p="ollama" onclick="selectProvider('ollama')"><div class="picon">OL</div>Ollama</div>
                    </div>
                    <input type="hidden" id="provider-select" value="openrouter">
                    <div class="form-group">
                        <label>API Key</label>
                        <input type="password" id="api-key" class="input" placeholder="sk-...">
                    </div>
                    <div class="form-group">
                        <label>Base URL (optional)</label>
                        <input type="text" id="base-url" class="input" placeholder="https://openrouter.ai/api/v1">
                    </div>
                    <div class="row">
                        <button class="btn" onclick="testConnection()" id="btn-test">Test Connection</button>
                        <button class="btn primary" onclick="saveProvider()" id="btn-save">Save Provider</button>
                    </div>
                    <div id="test-result" style="margin-top:14px;font-size:13px"></div>
                </div>
                <div class="panel">
                    <h3>Dual Models</h3>
                    <div class="form-group">
                        <label>Fast Model — Laya decisions</label>
                        <select id="fast-model-select" class="input">
                            <option value="">Click "Discover Models" first</option>
                        </select>
                        <input type="text" id="custom-fast-model" class="input" placeholder="Or type custom model name" style="margin-top:8px">
                    </div>
                    <div class="form-group">
                        <label>Reasoning Model — deep analysis</label>
                        <select id="reasoning-model-select" class="input">
                            <option value="">Click "Discover Models" first</option>
                        </select>
                        <input type="text" id="custom-reasoning-model" class="input" placeholder="Or type custom model name" style="margin-top:8px">
                    </div>
                    <button class="btn block" onclick="discoverModels()" id="btn-discover">
                        <span class="spinner" style="display:none" id="discover-spin"></span>
                        Discover Models
                    </button>
                </div>
            </div>
            <div>
                <div class="panel">
                    <h3>Current Status</h3>
                    <div id="current-status"><div class="loading-overlay"><div class="spinner"></div> Loading...</div></div>
                </div>
                <div class="panel">
                    <h3>Configured Providers</h3>
                    <div id="provider-list"><div class="loading-overlay"><div class="spinner"></div> Loading...</div></div>
                </div>
                <div class="panel">
                    <h3>Security Tools</h3>
                    <div id="tools-list"><div class="loading-overlay"><div class="spinner"></div> Discovering tools...</div></div>
                </div>
                <div class="panel" style="text-align:center">
                    <h3 style="justify-content:center">Quick Start</h3>
                    <p style="font-size:13px;color:var(--text-muted);margin-bottom:14px">After configuring a provider, launch your first engagement.</p>
                    <a href="/new-hunt" class="btn primary" style="display:inline-flex">Start a Hunt →</a>
                </div>
            </div>
        </div>
    </div>
    <script>
        {_SHARED_JS}
        const URLS = {{
            openrouter: 'https://openrouter.ai/api/v1',
            openai: 'https://api.openai.com/v1',
            anthropic: 'https://api.anthropic.com',
            gemini: 'https://generativelanguage.googleapis.com/v1beta',
            deepseek: 'https://api.deepseek.com/v1',
            ollama: 'http://localhost:11434/v1',
        }};

        function selectProvider(p) {{
            document.getElementById('provider-select').value = p;
            document.querySelectorAll('.provider-tile').forEach(t => t.classList.toggle('active', t.dataset.p === p));
            document.getElementById('base-url').value = URLS[p] || '';
        }}

        connectWs(null);

        async function loadStatus() {{
            try {{
                const r = await fetch('/api/status');
                const d = await r.json();
                const el = document.getElementById('current-status');
                if (!d.provider) {{
                    el.innerHTML = '<div class="empty"><span class="icon">⚙</span>No provider configured yet</div>';
                    return;
                }}
                el.innerHTML = `
                    <div class="stat"><span class="label">Provider</span><span class="value">${{escapeHtml(d.provider)}}</span></div>
                    <div class="stat"><span class="label">Model</span><span class="value">${{escapeHtml(d.model || '—')}}</span></div>
                    <div class="stat"><span class="label">Fast (Laya)</span><span class="value">${{escapeHtml(d.fast_model || d.model || '—')}}</span></div>
                    <div class="stat"><span class="label">Reasoning</span><span class="value">${{escapeHtml(d.reasoning_model || d.model || '—')}}</span></div>
                    <div class="stat"><span class="label">Key</span><span class="value">${{d.has_key ? '<span class="badge green">configured</span>' : '<span class="badge red">missing</span>'}}</span></div>
                    <div class="stat"><span class="label">Sessions</span><span class="value">${{d.sessions || 0}}</span></div>
                `;
            }} catch(e) {{ showToast('Failed to load status', 'error'); }}
        }}

        async function loadProviders() {{
            try {{
                const r = await fetch('/api/providers');
                const d = await r.json();
                const el = document.getElementById('provider-list');
                if (!d.providers.length) {{
                    el.innerHTML = '<div class="empty">None configured yet</div>';
                    return;
                }}
                el.innerHTML = d.providers.map(p => `
                    <div class="stat">
                        <span class="label">${{escapeHtml(p.provider)}}</span>
                        <span class="value"><span class="badge cyan">${{escapeHtml(p.model || '?')}}</span>${{p.has_key ? ' <span class="badge green">key</span>' : ''}}</span>
                    </div>
                `).join('');
            }} catch(e) {{ document.getElementById('provider-list').innerHTML = '<div class="empty">Failed to load</div>'; }}
        }}

        async function testConnection() {{
            const btn = document.getElementById('btn-test');
            const provider = document.getElementById('provider-select').value;
            const key = document.getElementById('api-key').value;
            const url = document.getElementById('base-url').value;
            btn.disabled = true;
            btn.innerHTML = '<span class="spinner"></span> Testing...';
            document.getElementById('test-result').innerHTML = '';
            try {{
                const r = await fetch('/api/providers/test', {{
                    method: 'POST',
                    headers: {{'Content-Type': 'application/json'}},
                    body: JSON.stringify({{provider, api_key: key, base_url: url}})
                }});
                const d = await r.json();
                if (d.success) {{
                    document.getElementById('test-result').innerHTML = '<span class="badge green">✓ Connection successful</span>';
                    showToast('Connection successful', 'success');
                }} else {{
                    document.getElementById('test-result').innerHTML = `<span class="badge red">✗ ${{escapeHtml(d.error || 'Failed')}}</span>`;
                    showToast(d.error || 'Connection failed', 'error');
                }}
            }} catch(e) {{
                document.getElementById('test-result').innerHTML = `<span class="badge red">✗ ${{escapeHtml(e.message)}}</span>`;
            }} finally {{
                btn.disabled = false;
                btn.textContent = 'Test Connection';
            }}
        }}

        async function saveProvider() {{
            const provider = document.getElementById('provider-select').value;
            const key = document.getElementById('api-key').value;
            const url = document.getElementById('base-url').value;
            const fastModel = (document.getElementById('custom-fast-model')?.value) ||
                (document.getElementById('fast-model-select')?.value) || '';
            const reasoningModel = (document.getElementById('custom-reasoning-model')?.value) ||
                (document.getElementById('reasoning-model-select')?.value) || fastModel;
            if (!key) {{ showToast('API key required', 'error'); return; }}
            const btn = document.getElementById('btn-save');
            btn.disabled = true;
            btn.innerHTML = '<span class="spinner"></span> Saving...';
            try {{
                const r = await fetch('/api/providers', {{
                    method: 'POST',
                    headers: {{'Content-Type': 'application/json'}},
                    body: JSON.stringify({{
                        provider,
                        api_key: key,
                        base_url: url,
                        selected_model: fastModel,
                        fast_model: fastModel,
                        reasoning_model: reasoningModel
                    }})
                }});
                const d = await r.json();
                if (d.status === 'ok') {{
                    showToast('Provider saved!', 'success');
                    loadStatus();
                    loadProviders();
                }} else {{
                    showToast('Failed to save', 'error');
                }}
            }} catch(e) {{
                showToast('Save failed: ' + e.message, 'error');
            }} finally {{
                btn.disabled = false;
                btn.textContent = 'Save Provider';
            }}
        }}

        async function discoverModels() {{
            const provider = document.getElementById('provider-select').value;
            const key = document.getElementById('api-key').value;
            const url = document.getElementById('base-url').value;
            const spin = document.getElementById('discover-spin');
            const btn = document.getElementById('btn-discover');
            spin.style.display = 'inline-block';
            btn.disabled = true;
            try {{
                if (key) {{
                    await fetch('/api/providers/test', {{
                        method: 'POST',
                        headers: {{'Content-Type': 'application/json'}},
                        body: JSON.stringify({{provider, api_key: key, base_url: url}})
                    }});
                }}
                const r = await fetch(`/api/models?provider=${{provider}}`);
                const d = await r.json();
                const fastSel = document.getElementById('fast-model-select');
                const reasonSel = document.getElementById('reasoning-model-select');
                fastSel.innerHTML = '';
                reasonSel.innerHTML = '';
                if (!d.models || !d.models.length) {{
                    fastSel.innerHTML = '<option value="">No models found</option>';
                    reasonSel.innerHTML = '<option value="">No models found</option>';
                    showToast('No models found', 'error');
                    return;
                }}
                d.models.slice(0, 50).forEach(m => {{
                    const o1 = document.createElement('option');
                    o1.value = m.id; o1.textContent = m.id;
                    fastSel.appendChild(o1);
                    const o2 = document.createElement('option');
                    o2.value = m.id; o2.textContent = m.id;
                    reasonSel.appendChild(o2);
                }});
                fastSel.value = d.models[0].id;
                const reasoningGuess = d.models.find(m => /o1|o3|sonnet|opus|gpt-4[^-]|nemotron|deepseek-chat|llama3/i.test(m.id));
                reasonSel.value = (reasoningGuess || d.models[d.models.length - 1] || d.models[0]).id;
                showToast(d.models.length + ' models discovered', 'success');
            }} catch(e) {{
                showToast('Discovery failed: ' + e.message, 'error');
            }} finally {{
                spin.style.display = 'none';
                btn.disabled = false;
            }}
        }}

        async function loadSetupTools() {{
            try {{
                const r = await fetch('/api/tools');
                const d = await r.json();
                const el = document.getElementById('tools-list');
                const tools = d.tools || [];
                if (!tools.length) {{
                    el.innerHTML = '<div class="empty">No tools discovered</div>';
                    return;
                }}
                el.innerHTML = tools.map(t => `
                    <div class="stat">
                        <span class="label">${{escapeHtml(t.name)}}</span>
                        <span class="value">${{t.available ? '<span class="badge green">available</span>' : '<span class="badge gray">missing</span>'}}</span>
                    </div>
                `).join('');
            }} catch (e) {{
                document.getElementById('tools-list').innerHTML = '<div class="empty">Failed to load tools</div>';
            }}
        }}

        loadStatus();
        loadProviders();
        loadSetupTools();
    </script>
</body>
</html>"""


def _new_hunt_html() -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DEMOGORGON — New Hunt</title>
    <style>{_SHARED_CSS}</style>
</head>
<body>
    {_header("new-hunt")}
    <div class="container">
        <div class="page-title">New Hunt</div>
        <div class="page-sub">Define target, budget, and authorization. The agent adapts strategy autonomously.</div>
        <div class="grid">
            <div>
                <div class="panel">
                    <h3>Target</h3>
                    <div class="form-group">
                        <label>Target URL or Domain</label>
                        <input type="text" id="target" class="input" placeholder="https://example.com" autofocus>
                    </div>
                </div>
                <div class="panel">
                    <h3>Program Policy <span class="count">optional</span></h3>
                    <div class="form-group">
                        <label>Paste bug bounty program text (HackerOne, Bugcrowd, etc.)</label>
                        <textarea id="program-text" class="input" placeholder="Paste program guidelines here...

Scope will be auto-parsed."></textarea>
                        <div class="hint">Scope, restrictions, and allowed vuln classes are extracted automatically.</div>
                    </div>
                </div>
                <div class="panel">
                    <h3>Budget</h3>
                    <div class="row">
                        <div class="form-group">
                            <label>Max Cycles</label>
                            <input type="number" id="max-cycles" class="input" value="50" min="1">
                        </div>
                        <div class="form-group">
                            <label>Max Cost (USD)</label>
                            <input type="number" id="max-cost" class="input" value="2.00" step="0.50" min="0">
                        </div>
                        <div class="form-group">
                            <label>Max Requests</label>
                            <input type="number" id="max-requests" class="input" value="200" min="1">
                        </div>
                    </div>
                    <div id="budget-preview" style="margin-top:4px"></div>
                </div>
                <div class="panel">
                    <h3>Authorization</h3>
                    <div class="form-group">
                        <label>Confirm you are authorized to test this target</label>
                        <select id="approval-level" class="input">
                            <option value="none">No approval required (I have authorization)</option>
                            <option value="for_exploits">Ask before exploitation</option>
                            <option value="required">Ask before every action</option>
                        </select>
                    </div>
                </div>
                <button class="btn primary block" onclick="startHunt()" id="btn-start" style="padding:15px;font-size:15px">
                    Start Hunt →
                </button>
            </div>
            <div>
                <div class="panel">
                    <h3>Active Provider</h3>
                    <div id="provider-info"><div class="loading-overlay"><div class="spinner"></div> Loading...</div></div>
                </div>
                <div class="panel">
                    <h3>Recent Hunts</h3>
                    <div id="recent-hunts"><div class="loading-overlay"><div class="spinner"></div> Loading...</div></div>
                </div>
                <div class="panel">
                    <h3>Tips</h3>
                    <ul class="tip-list">
                        <li>Paste a program policy to auto-parse scope</li>
                        <li>Start with recon strategy — the agent will adapt</li>
                        <li>Use /pause and /resume from the terminal</li>
                        <li>Web dashboard shows the same live events</li>
                        <li>Keep budgets low on first runs to explore</li>
                    </ul>
                </div>
            </div>
        </div>
    </div>
    <script>
        {_SHARED_JS}
        connectWs(null);

        function updateBudgetPreview() {{
            const cycles = parseInt(document.getElementById('max-cycles').value) || 50;
            const cost = parseFloat(document.getElementById('max-cost').value) || 2;
            const reqs = parseInt(document.getElementById('max-requests').value) || 200;
            document.getElementById('budget-preview').innerHTML =
                meter('Cycles', cycles, 200, '') +
                '<div style="height:8px"></div>' +
                meter('Cost', cost, 10, '$') +
                '<div style="height:8px"></div>' +
                meter('Requests', reqs, 500, '');
        }}
        ['max-cycles','max-cost','max-requests'].forEach(id =>
            document.getElementById(id).addEventListener('input', updateBudgetPreview));
        updateBudgetPreview();

        async function loadProvider() {{
            const r = await fetch('/api/providers/active');
            const d = await r.json();
            if (d.provider) {{
                document.getElementById('provider-info').innerHTML = `
                    <div class="stat"><span class="label">Provider</span><span class="value">${{escapeHtml(d.provider)}}</span></div>
                    <div class="stat"><span class="label">Model</span><span class="value">${{escapeHtml(d.model || '—')}}</span></div>
                    <div class="stat"><span class="label">Fast</span><span class="value">${{escapeHtml(d.fast_model || '—')}}</span></div>
                    <div class="stat"><span class="label">Reasoning</span><span class="value">${{escapeHtml(d.reasoning_model || '—')}}</span></div>
                    <div class="stat"><span class="label">Key</span><span class="value">${{escapeHtml(d.masked_key || '—')}}</span></div>
                `;
            }} else {{
                document.getElementById('provider-info').innerHTML = '<div class="empty"><span class="icon">⚠</span>No provider — <a href="/setup">configure first</a></div>';
            }}
        }}

        async function loadRecent() {{
            try {{
                const r = await fetch('/api/engagements');
                const d = await r.json();
                const el = document.getElementById('recent-hunts');
                if (!d.sessions.length) {{
                    el.innerHTML = '<div class="empty">No hunts yet</div>';
                    return;
                }}
                el.innerHTML = d.sessions.slice(0, 5).map(s => `
                    <div class="stat">
                        <span class="label" style="font-family:var(--font-mono);font-size:12px">${{escapeHtml((s.target || '').replace(/^https?:\\/\\//, '').substring(0, 40))}}</span>
                        <span class="value"><span class="badge ${{s.active ? 'green' : 'blue'}}">${{escapeHtml(s.status || '?')}}</span></span>
                    </div>
                `).join('');
            }} catch(e) {{ document.getElementById('recent-hunts').innerHTML = '<div class="empty">Failed to load</div>'; }}
        }}

        async function startHunt() {{
            const target = document.getElementById('target').value.trim();
            if (!target) {{ showToast('Target required', 'error'); return; }}
            const btn = document.getElementById('btn-start');
            btn.disabled = true;
            btn.innerHTML = '<span class="spinner"></span> Launching...';
            try {{
                const body = {{
                    target,
                    program_text: document.getElementById('program-text').value,
                    max_cycles: parseInt(document.getElementById('max-cycles').value) || 50,
                    max_cost_usd: parseFloat(document.getElementById('max-cost').value) || 2.0,
                    max_requests: parseInt(document.getElementById('max-requests').value) || 200,
                    approval_level: document.getElementById('approval-level').value,
                }};
                const r = await fetch('/api/engagements', {{
                    method: 'POST',
                    headers: {{'Content-Type': 'application/json'}},
                    body: JSON.stringify(body)
                }});
                const d = await r.json();
                if (d.session_id) {{
                    showToast('Hunt created — starting...', 'success');
                    await fetch(`/api/engagements/${{d.session_id}}/start`, {{method: 'POST'}});
                    window.location.href = `/hunt/${{d.session_id}}`;
                }} else {{
                    showToast('Failed: ' + (d.detail || 'Unknown error'), 'error');
                    btn.disabled = false;
                    btn.textContent = 'Start Hunt →';
                }}
            }} catch(e) {{
                showToast('Failed: ' + e.message, 'error');
                btn.disabled = false;
                btn.textContent = 'Start Hunt →';
            }}
        }}

        loadProvider();
        loadRecent();
    </script>
</body>
</html>"""


def _hunt_html(session_id: str = "") -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DEMOGORGON — Research Dashboard</title>
    <style>{_SHARED_CSS}
        .dash {{ display: grid; grid-template-columns: 280px 1fr 320px; gap: 18px; padding: 20px; height: calc(100vh - 58px); max-width: 1600px; margin: 0 auto; position: relative; z-index: 1; }}
        .dash-col {{ overflow-y: auto; display: flex; flex-direction: column; gap: 16px; padding-bottom: 12px; }}
        .dash-col::-webkit-scrollbar {{ width: 6px; }}
        .dash-col::-webkit-scrollbar-thumb {{ background: var(--border); border-radius: 3px; }}
        .event-stream {{ max-height: calc(100vh - 220px); overflow-y: auto; font-size: 12px; }}
        .event {{ padding: 7px 11px; border-left: 3px solid var(--border); margin-bottom: 4px; font-size: 12px; border-radius: 0 var(--radius-sm) var(--radius-sm) 0; transition: background 0.15s; }}
        .event:hover {{ background: rgba(255,255,255,0.02); }}
        .event.finding {{ border-color: var(--success); background: rgba(52,211,153,0.06); }}
        .event.action {{ border-color: var(--accent); background: rgba(0,212,255,0.05); }}
        .event.error {{ border-color: var(--danger); background: rgba(239,68,68,0.07); }}
        .event.tool {{ border-color: var(--accent-2); background: rgba(168,85,247,0.06); }}
        .event.log {{ border-color: var(--border); background: rgba(18,18,28,0.5); }}
        .event .time {{ color: var(--text-dim); font-family: var(--font-mono); font-size: 10px; }}
        .event .type {{ color: var(--accent); font-weight: 700; font-size: 10px; letter-spacing: 0.5px; }}
        .findings-list .finding-item {{ padding: 10px 12px; border-left: 3px solid var(--success); margin-bottom: 6px; background: rgba(52,211,153,0.05); font-size: 12px; cursor: pointer; transition: all 0.15s; border-radius: 0 var(--radius-sm) var(--radius-sm) 0; }}
        .findings-list .finding-item:hover {{ background: rgba(52,211,153,0.1); transform: translateX(2px); }}
        .findings-list .finding-item .sev {{ font-weight: 700; font-size: 10px; letter-spacing: 0.5px; margin-right: 6px; }}
        .scope-list {{ font-size: 12px; }}
        .scope-list .scope-item {{ display: flex; justify-content: space-between; align-items: center; padding: 6px 0; border-bottom: 1px solid rgba(30,30,48,0.7); gap: 8px; }}
        .scope-list .scope-item:last-child {{ border-bottom: none; }}
        .scope-list .scope-item .pattern {{ color: var(--success); word-break: break-all; font-family: var(--font-mono); font-size: 11px; }}
        .scope-list .scope-item .type {{ color: var(--text-dim); font-size: 10px; }}
        .scope-list .scope-item .remove {{ color: var(--danger); cursor: pointer; font-size: 14px; opacity: 0.6; transition: opacity 0.15s; }}
        .scope-list .scope-item .remove:hover {{ opacity: 1; }}
        .scope-add {{ display: flex; gap: 6px; margin-top: 10px; }}
        .scope-add input {{ flex: 1; padding: 7px 10px; font-size: 11px; }}
        .scope-add select {{ width: 90px; padding: 7px 10px; font-size: 11px; }}
        .instruction-box {{ display: flex; gap: 6px; margin-top: 8px; }}
        .instruction-box input {{ flex: 1; }}
        .status-pill {{ display: inline-flex; align-items: center; gap: 6px; padding: 4px 12px; border-radius: 99px; font-size: 11px; font-weight: 700; font-family: var(--font-mono); letter-spacing: 0.5px; }}
        .status-pill.running {{ background: rgba(52,211,153,0.12); color: var(--success); border: 1px solid rgba(52,211,153,0.3); }}
        .status-pill.paused {{ background: rgba(251,191,36,0.12); color: var(--warning); border: 1px solid rgba(251,191,36,0.3); }}
        .status-pill.stopped, .status-pill.completed {{ background: rgba(148,163,184,0.1); color: var(--info); border: 1px solid rgba(148,163,184,0.25); }}
        .status-pill.error {{ background: rgba(239,68,68,0.12); color: var(--danger); border: 1px solid rgba(239,68,68,0.3); }}
        .trace-line {{ padding: 4px 0; border-bottom: 1px solid rgba(30,30,48,0.5); font-size: 11px; display: flex; gap: 8px; }}
        .trace-line:last-child {{ border-bottom: none; }}
        .trace-line .t {{ color: var(--text-dim); font-family: var(--font-mono); font-size: 10px; flex-shrink: 0; }}
        .trace-line .ty {{ color: var(--accent); font-weight: 600; font-size: 10px; flex-shrink: 0; min-width: 36px; }}
        .trace-line .c {{ color: var(--text-muted); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
        @media (max-width: 1100px) {{ .dash {{ grid-template-columns: 1fr; height: auto; }} .event-stream {{ max-height: 300px; }} }}
    </style>
</head>
<body>
    {_header("hunt")}
    <div class="dash">
        <div class="dash-col">
            <div class="panel">
                <h3>Session</h3>
                <div class="stat"><span class="label">Target</span><span class="value" id="target" style="font-size:11px;word-break:break-all">—</span></div>
                <div class="stat"><span class="label">Provider</span><span class="value" id="provider">—</span></div>
                <div class="stat"><span class="label">Model</span><span class="value" id="model">—</span></div>
                <div class="stat"><span class="label">Status</span><span class="value" id="status">—</span></div>
                <div class="stat"><span class="label">Strategy</span><span class="value" id="strategy">—</span></div>
            </div>
            <div class="panel">
                <h3>Budget</h3>
                <div style="margin-bottom:14px">
                    <div class="meter-row"><span class="lbl">Cycles</span><span class="val" id="cycles-text">0</span></div>
                    <div class="meter"><div class="meter-fill" id="cycles-meter" style="width:0%"></div></div>
                </div>
                <div style="margin-bottom:14px">
                    <div class="meter-row"><span class="lbl">Cost</span><span class="val" id="cost-text">$0.00</span></div>
                    <div class="meter"><div class="meter-fill" id="cost-meter" style="width:0%"></div></div>
                </div>
                <div style="margin-bottom:14px">
                    <div class="meter-row"><span class="lbl">Requests</span><span class="val" id="requests-text">0</span></div>
                    <div class="meter"><div class="meter-fill" id="requests-meter" style="width:0%"></div></div>
                </div>
                <div class="stat"><span class="label">Tokens</span><span class="value" id="tokens">0</span></div>
                <div class="stat"><span class="label">Findings</span><span class="value" id="findings-count" style="color:var(--success)">0</span></div>
                <div class="stat"><span class="label">Evidence</span><span class="value" id="evidence-count" style="color:var(--accent-2)">0</span></div>
            </div>
            <div class="panel">
                <h3>Controls</h3>
                <button class="btn success block" onclick="resumeSession()" style="margin-bottom:8px">▶ Resume</button>
                <button class="btn block" onclick="pauseSession()" style="margin-bottom:8px">⏸ Pause</button>
                <button class="btn danger block" onclick="stopSession()" style="margin-bottom:8px">■ Stop</button>
                <button class="btn block" onclick="exportFindings()">↓ Export Findings</button>
            </div>
            <div class="panel">
                <h3>Scope <span class="count" id="scope-count">(0)</span></h3>
                <div id="scope-list" class="scope-list"><div class="empty">No scope loaded</div></div>
                <div class="scope-add">
                    <input type="text" id="scope-pattern" class="input" placeholder="pattern">
                    <select id="scope-type" class="input">
                        <option value="url">URL</option>
                        <option value="domain">Domain</option>
                        <option value="wildcard">Wildcard</option>
                        <option value="cidr">CIDR</option>
                    </select>
                    <button class="btn sm" onclick="addScope()">+</button>
                </div>
            </div>
            <div class="panel">
                <h3>Send Instruction</h3>
                <div class="instruction-box">
                    <input type="text" id="instruction-input" class="input" placeholder="e.g. focus on XSS on /api">
                    <button class="btn sm" onclick="sendInstruction()">→</button>
                </div>
            </div>
        </div>
        <div class="dash-col">
            <div class="panel" style="flex:1;display:flex;flex-direction:column;min-height:400px">
                <h3>Live Event Stream <span class="count" id="event-count"></span></h3>
                <div class="event-stream" id="events" style="flex:1;overflow-y:auto">
                    <div class="empty"><span class="icon">◉</span>Waiting for events...</div>
                </div>
            </div>
        </div>
        <div class="dash-col">
            <div class="panel">
                <h3>Findings <span class="count" id="findings-badge"></span></h3>
                <div id="findings-list" class="findings-list"><div class="empty"><span class="icon">◎</span>No findings yet</div></div>
            </div>
            <div class="panel">
                <h3>Recent Activity</h3>
                <div id="trace-list"><div class="empty">No trace entries</div></div>
            </div>
            <div class="panel">
                <h3>Tools</h3>
                <div id="tools-list"><div class="loading-overlay"><div class="spinner"></div> Loading...</div></div>
            </div>
        </div>
    </div>

    <div class="modal-overlay" id="finding-modal" onclick="if(event.target===this)this.classList.remove('show')">
        <div class="modal-content">
            <div class="modal-header">
                <h3 id="modal-title" style="margin:0">Finding Detail</h3>
                <button class="modal-close" onclick="document.getElementById('finding-modal').classList.remove('show')">✕</button>
            </div>
            <div id="modal-body"></div>
        </div>
    </div>

    <script>
        {_SHARED_JS}
        const sessionId = '{session_id}';
        let eventCount = 0;
        const eventsDiv = document.getElementById('events');

        connectWs((event) => {{
            addEvent(event);
            updateFromEvent(event);
        }}, null, () => {{
            loadSession(); loadFindings(); loadTrace();
        }});

        function addEvent(event) {{
            if (eventCount === 0) eventsDiv.innerHTML = '';
            eventCount++;
            const div = document.createElement('div');
            div.className = 'event';
            const time = fmtTime(event.timestamp);
            const type = event.type || 'unknown';
            const data = event.data || {{}};
            let msg = '';
            if (type.includes('finding')) {{ div.className += ' finding'; msg = data.title || data.description || JSON.stringify(data).substring(0,120); }}
            else if (type.includes('tool')) {{ div.className += ' tool'; msg = (data.tool||'') + ' ' + (data.target||data.command||'').substring(0,80); }}
            else if (type.includes('error')) {{ div.className += ' error'; msg = data.error || data.message || JSON.stringify(data).substring(0,120); }}
            else if (type.includes('action') || type.includes('decision')) {{ div.className += ' action'; msg = data.action || data.content || JSON.stringify(data).substring(0,120); }}
            else {{ div.className += ' log'; msg = data.message || data.content || JSON.stringify(data).substring(0,120); }}
            div.innerHTML = `<span class="time">${{time}}</span> <span class="type">${{escapeHtml(type)}}</span> ${{escapeHtml(msg.substring(0,160))}}`;
            eventsDiv.appendChild(div);
            eventsDiv.scrollTop = eventsDiv.scrollHeight;
            document.getElementById('event-count').textContent = '(' + eventCount + ')';
            while (eventsDiv.children.length > 200) eventsDiv.removeChild(eventsDiv.firstChild);
        }}

        function updateFromEvent(event) {{
            const type = event.type || '';
            const data = event.data || {{}};
            if (type === 'status_change') {{
                const st = data.status || '—';
                const el = document.getElementById('status');
                el.innerHTML = `<span class="status-pill ${{escapeHtml(st)}}">${{escapeHtml(st.toUpperCase())}}</span>`;
            }}
            if (type === 'strategy_change') document.getElementById('strategy').textContent = data.to || '—';
            if (type === 'progress_update') {{
                const cyc = data.cycle || 0;
                document.getElementById('cycles').textContent = cyc;
                document.getElementById('cycles-text').textContent = cyc;
                document.getElementById('cycles-meter').style.width = pct(cyc, 50) + '%';
                document.getElementById('findings-count').textContent = data.findings || '0';
                if (data.budget) {{
                    const cost = data.budget.cost_usd || 0;
                    document.getElementById('cost').textContent = '$' + cost.toFixed(2);
                    document.getElementById('cost-text').textContent = '$' + cost.toFixed(2);
                    document.getElementById('cost-meter').style.width = pct(cost, 2) + '%';
                    document.getElementById('requests').textContent = data.budget.requests || 0;
                    document.getElementById('requests-text').textContent = data.budget.requests || 0;
                    document.getElementById('requests-meter').style.width = pct(data.budget.requests, 200) + '%';
                }}
                if (data.tokens) document.getElementById('tokens').textContent = data.tokens.total || 0;
            }}
            if (type === 'finding') loadFindings();
        }}

        async function loadSession() {{
            const id = sessionId || '';
            if (!id) {{
                const r = await fetch('/api/engagements');
                const d = await r.json();
                if (d.sessions.length) {{
                    const s = d.sessions.find(x => x.active) || d.sessions[0];
                    updateSessionUI(s);
                }}
                return;
            }}
            try {{
                const r = await fetch(`/api/engagements/${{encodeURIComponent(id)}}`);
                if (r.ok) {{
                    const d = await r.json();
                    updateSessionUI(d);
                }}
            }} catch(e) {{ showToast('Failed to load session: ' + e.message, 'error'); }}
        }}

        function updateSessionUI(s) {{
            document.getElementById('target').textContent = s.target || '—';
            document.getElementById('provider').textContent = s.provider || '—';
            document.getElementById('model').textContent = s.model || '—';
            const st = s.status || '—';
            document.getElementById('status').innerHTML = `<span class="status-pill ${{escapeHtml(st)}}">${{escapeHtml(String(st).toUpperCase())}}</span>`;
            document.getElementById('strategy').textContent = s.strategy || '—';
            document.getElementById('findings-count').textContent = s.findings || '0';
            document.getElementById('evidence-count').textContent = s.evidence || '0';
        }}

        async function loadSummary() {{
            const id = sessionId || document.getElementById('target').textContent;
            if (!id || id === '—') return;
            try {{
                const r = await fetch(`/api/engagements/${{encodeURIComponent(id)}}/summary`);
                if (!r.ok) return;
                const d = await r.json();
                if (d.budget) {{
                    const cost = d.budget.cost_usd || 0;
                    const reqs = d.budget.requests || 0;
                    document.getElementById('cost').textContent = '$' + cost.toFixed(2);
                    document.getElementById('cost-text').textContent = '$' + cost.toFixed(2);
                    document.getElementById('cost-meter').style.width = pct(cost, 2) + '%';
                    document.getElementById('requests').textContent = reqs;
                    document.getElementById('requests-text').textContent = reqs;
                    document.getElementById('requests-meter').style.width = pct(reqs, 200) + '%';
                }}
                if (d.tokens) document.getElementById('tokens').textContent = d.tokens.total || 0;
                const cyc = d.total_cycles || 0;
                document.getElementById('cycles').textContent = cyc;
                document.getElementById('cycles-text').textContent = cyc;
                document.getElementById('cycles-meter').style.width = pct(cyc, 50) + '%';
                if (d.findings_by_severity) {{
                    // keep simple count display
                }}
            }} catch(e) {{ /* silent */ }}
        }}

        async function loadScope() {{
            const id = sessionId || document.getElementById('target').textContent;
            if (!id || id === '—') return;
            try {{
                const r = await fetch(`/api/engagements/${{encodeURIComponent(id)}}/scope`);
                if (!r.ok) return;
                const d = await r.json();
                const el = document.getElementById('scope-list');
                const count = (d.in_scope || []).length;
                document.getElementById('scope-count').textContent = `(${{count}})`;
                if (!count) {{
                    el.innerHTML = '<div class="empty">No scope loaded</div>';
                    return;
                }}
                el.innerHTML = d.in_scope.map(a => `
                    <div class="scope-item">
                        <div>
                            <div class="pattern">${{escapeHtml(a.pattern)}}</div>
                            <div class="type">${{escapeHtml(a.asset_type || 'url')}}</div>
                        </div>
                        <span class="remove" onclick="removeScope(${{JSON.stringify(escapeHtml(a.pattern))}})" title="Remove">✕</span>
                    </div>
                `).join('');
            }} catch(e) {{ /* silent */ }}
        }}

        async function addScope() {{
            const id = sessionId || document.getElementById('target').textContent;
            if (!id || id === '—') return;
            const pattern = document.getElementById('scope-pattern').value.trim();
            if (!pattern) return;
            const asset_type = document.getElementById('scope-type').value;
            try {{
                await fetch(`/api/engagements/${{encodeURIComponent(id)}}/scope`, {{
                    method: 'POST',
                    headers: {{'Content-Type': 'application/json'}},
                    body: JSON.stringify({{pattern, asset_type}})
                }});
                document.getElementById('scope-pattern').value = '';
                showToast('Scope added', 'success');
                loadScope();
            }} catch(e) {{ showToast('Failed to add scope', 'error'); }}
        }}

        async function removeScope(pattern) {{
            const id = sessionId || document.getElementById('target').textContent;
            if (!id || id === '—') return;
            await fetch(`/api/engagements/${{encodeURIComponent(id)}}/scope/${{encodeURIComponent(pattern)}}`, {{method: 'DELETE'}});
            loadScope();
        }}

        async function sendInstruction() {{
            const id = sessionId || document.getElementById('target').textContent;
            if (!id || id === '—') return;
            const input = document.getElementById('instruction-input');
            const instruction = input.value.trim();
            if (!instruction) return;
            try {{
                await fetch(`/api/engagements/${{encodeURIComponent(id)}}/instructions`, {{
                    method: 'POST',
                    headers: {{'Content-Type': 'application/json'}},
                    body: JSON.stringify({{instruction}})
                }});
                input.value = '';
                showToast('Instruction sent', 'success');
            }} catch(e) {{ showToast('Failed to send instruction', 'error'); }}
        }}

        async function loadFindings() {{
            const id = sessionId || document.getElementById('target').textContent;
            if (!id || id === '—') return;
            try {{
                const r = await fetch(`/api/engagements/${{encodeURIComponent(id)}}/findings`);
                const d = await r.json();
                const el = document.getElementById('findings-list');
                const findings = (d.findings || []).slice().sort((a, b) => {{
                    const order = {{critical:0, high:1, medium:2, low:3, info:4}};
                    return (order[(a.severity||'').toLowerCase()] ?? 5) - (order[(b.severity||'').toLowerCase()] ?? 5);
                }});
                document.getElementById('findings-badge').textContent = findings.length ? `(${{findings.length}})` : '';
                if (!findings.length) {{
                    el.innerHTML = '<div class="empty"><span class="icon">◎</span>No findings yet</div>';
                    return;
                }}
                el.innerHTML = findings.map((f, i) => {{
                    const sev = (f.severity || '?').toLowerCase();
                    return `<div class="finding-item" onclick="showFindingDetail(${{i}})"><span class="sev ${{sevClass(sev)}}">${{escapeHtml(sev.toUpperCase())}}</span> ${{escapeHtml(f.title || f.description || 'Untitled')}}</div>`;
                }}).join('');
            }} catch(e) {{ showToast('Request failed: ' + e.message, 'error'); }}
        }}

        async function showFindingDetail(idx) {{
            const id = sessionId || document.getElementById('target').textContent;
            if (!id || id === '—') return;
            try {{
                const r = await fetch(`/api/engagements/${{encodeURIComponent(id)}}/findings/${{idx}}`);
                const d = await r.json();
                const f = d.finding;
                const modal = document.getElementById('finding-modal');
                document.getElementById('modal-title').innerHTML = `${{sevBadge(f.severity)}} ${{escapeHtml(f.title || 'Finding')}}`;
                let html = '';
                html += `<div class="field"><div class="label">Severity</div><div class="val">${{sevBadge(f.severity)}}</div></div>`;
                if (f.vuln_class) html += `<div class="field"><div class="label">Vulnerability Class</div><div class="val">${{escapeHtml(f.vuln_class)}}</div></div>`;
                if (f.endpoint) html += `<div class="field"><div class="label">Endpoint</div><div class="val mono" style="color:var(--accent)">${{escapeHtml(f.endpoint)}}</div></div>`;
                if (f.description) html += `<div class="field"><div class="label">Description</div><div class="val">${{escapeHtml(f.description)}}</div></div>`;
                if (f.impact) html += `<div class="field"><div class="label">Impact</div><div class="val">${{escapeHtml(f.impact)}}</div></div>`;
                if (f.steps && f.steps.length) html += `<div class="field"><div class="label">Reproduction Steps</div><div class="val">${{f.steps.map((s,i) => `${{i+1}}. ${{escapeHtml(s)}}`).join('<br>')}}</div></div>`;
                if (f.evidence) html += `<div class="field"><div class="label">Evidence</div><pre class="code">${{escapeHtml(typeof f.evidence === 'string' ? f.evidence : JSON.stringify(f.evidence, null, 2))}}</pre></div>`;
                document.getElementById('modal-body').innerHTML = html;
                modal.classList.add('show');
            }} catch(e) {{ showToast('Request failed: ' + e.message, 'error'); }}
        }}

        async function loadTrace() {{
            const id = sessionId || document.getElementById('target').textContent;
            if (!id || id === '—') return;
            try {{
                const r = await fetch(`/api/engagements/${{encodeURIComponent(id)}}/trace`);
                const d = await r.json();
                const el = document.getElementById('trace-list');
                if (!d.trace || !d.trace.length) {{
                    el.innerHTML = '<div class="empty">No trace entries</div>';
                    return;
                }}
                el.innerHTML = d.trace.slice(0, 15).map(e => `
                    <div class="trace-line">
                        <span class="t">${{fmtTime(e.timestamp)}}</span>
                        <span class="ty">${{escapeHtml(e.type)}}</span>
                        <span class="c">${{escapeHtml(e.content.substring(0, 70))}}</span>
                    </div>
                `).join('');
            }} catch(e) {{ /* silent */ }}
        }}

        async function loadTools() {{
            try {{
                const r = await fetch('/api/tools');
                const d = await r.json();
                const el = document.getElementById('tools-list');
                if (d.tools && d.tools.length) {{
                    el.innerHTML = d.tools.map(t => `
                        <div class="stat">
                            <span class="label">${{escapeHtml(t.name)}}</span>
                            <span class="value">${{t.available ? '<span class="badge green">on</span>' : '<span class="badge gray">off</span>'}}</span>
                        </div>
                    `).join('');
                    return;
                }}
                if (!d.capabilities || !d.capabilities.length) {{
                    el.innerHTML = '<div class="empty">No tools registered</div>';
                    return;
                }}
                el.innerHTML = d.capabilities.map(c => `<div class="stat"><span class="label">${{escapeHtml(c)}}</span></div>`).join('');
            }} catch(e) {{ el.innerHTML = '<div class="empty">Failed to load</div>'; }}
        }}

        async function pauseSession() {{
            const id = sessionId || document.getElementById('target').textContent;
            if (!id || id === '—') return;
            if (!confirmAction('Pause this hunt?')) return;
            await fetch(`/api/engagements/${{encodeURIComponent(id)}}/pause`, {{method: 'POST'}});
            document.getElementById('status').innerHTML = '<span class="status-pill paused">PAUSED</span>';
            showToast('Hunt paused', 'info');
        }}

        async function resumeSession() {{
            const id = sessionId || document.getElementById('target').textContent;
            if (!id || id === '—') return;
            await fetch(`/api/engagements/${{encodeURIComponent(id)}}/resume`, {{method: 'POST'}});
            document.getElementById('status').innerHTML = '<span class="status-pill running">RUNNING</span>';
            showToast('Hunt resumed', 'success');
        }}

        async function stopSession() {{
            const id = sessionId || document.getElementById('target').textContent;
            if (!id || id === '—') return;
            if (!confirmAction('Stop this session?')) return;
            await fetch(`/api/engagements/${{encodeURIComponent(id)}}/stop`, {{method: 'POST'}});
            document.getElementById('status').innerHTML = '<span class="status-pill stopped">STOPPED</span>';
            showToast('Session stopped', 'info');
        }}

        async function exportFindings() {{
            const id = sessionId || document.getElementById('target').textContent;
            if (!id || id === '—') return;
            try {{
                const r = await fetch(`/api/engagements/${{encodeURIComponent(id)}}/export`);
                const data = await r.json();
                const blob = new Blob([JSON.stringify(data, null, 2)], {{type: 'application/json'}});
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `findings-${{id}}.json`;
                a.click();
                URL.revokeObjectURL(url);
                showToast('Findings exported!', 'success');
            }} catch(e) {{ showToast('Export failed: ' + e.message, 'error'); }}
        }}

        document.getElementById('scope-pattern').addEventListener('keydown', e => {{ if(e.key==='Enter') addScope(); }});
        document.getElementById('instruction-input').addEventListener('keydown', e => {{ if(e.key==='Enter') sendInstruction(); }});
        document.addEventListener('keydown', e => {{ if(e.key==='Escape') document.getElementById('finding-modal').classList.remove('show'); }});

        loadSession();
        loadSummary();
        loadScope();
        loadFindings();
        loadTrace();
        loadTools();
        setInterval(() => {{ loadFindings(); loadTrace(); loadSummary(); loadScope(); }}, 5000);
    </script>
</body>
</html>"""


def _hunts_html() -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DEMOGORGON — Hunts</title>
    <style>{_SHARED_CSS}
        .hunt-card {{ background: var(--bg-panel); border: 1px solid var(--border); border-radius: var(--radius-lg); padding: 18px 20px; margin-bottom: 14px; cursor: pointer; transition: all 0.18s; box-shadow: var(--shadow); position: relative; overflow: hidden; }}
        .hunt-card::before {{ content: ""; position: absolute; top: 0; left: 0; bottom: 0; width: 3px; background: var(--border); transition: background 0.18s; }}
        .hunt-card:hover {{ border-color: rgba(0,212,255,0.35); transform: translateY(-2px); box-shadow: 0 8px 32px rgba(0,0,0,0.5), var(--glow); }}
        .hunt-card:hover::before {{ background: var(--accent); }}
        .hunt-card .hunt-header {{ display: flex; justify-content: space-between; align-items: center; gap: 12px; margin-bottom: 8px; }}
        .hunt-card .hunt-target {{ color: var(--text); font-size: 15px; font-weight: 700; font-family: var(--font-mono); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
        .hunt-card .hunt-meta {{ display: flex; gap: 16px; font-size: 12px; color: var(--text-muted); flex-wrap: wrap; }}
        .hunt-card .hunt-stats {{ display: flex; gap: 10px; margin-top: 12px; }}
        .hunt-card .stat-pill {{ background: var(--bg-elevated); border: 1px solid var(--border); border-radius: 99px; padding: 5px 14px; font-size: 11px; color: var(--text-muted); display: flex; align-items: center; gap: 6px; }}
        .stat-pill .num {{ color: var(--accent); font-weight: 700; font-family: var(--font-mono); font-size: 13px; }}
        .stat-pill.findings .num {{ color: var(--success); }}
        .stat-pill.evidence .num {{ color: var(--accent-2); }}
        .live-dot {{ width: 7px; height: 7px; border-radius: 50%; display: inline-block; }}
        .live-dot.on {{ background: var(--success); box-shadow: 0 0 8px var(--success); animation: pulse 2s infinite; }}
        .live-dot.off {{ background: var(--text-dim); }}
    </style>
</head>
<body>
    {_header("hunts")}
    <div class="container">
        <div class="page-title">Hunts</div>
        <div class="page-sub">All engagements — active, paused, and completed.</div>
        <div class="kpi-strip" id="summary-bar">
            <div class="kpi"><div class="big" id="total-hunts">0</div><div class="lbl">Total Hunts</div></div>
            <div class="kpi green"><div class="big" id="active-hunts">0</div><div class="lbl">Active</div></div>
            <div class="kpi yellow"><div class="big" id="paused-hunts">0</div><div class="lbl">Paused</div></div>
            <div class="kpi blue"><div class="big" id="completed-hunts">0</div><div class="lbl">Completed</div></div>
            <div class="kpi purple"><div class="big" id="total-findings">0</div><div class="lbl">Total Findings</div></div>
        </div>
        <div class="filter-bar">
            <button class="filter-btn active" onclick="filterHunts('all', this)">All</button>
            <button class="filter-btn" onclick="filterHunts('running', this)">Running</button>
            <button class="filter-btn" onclick="filterHunts('paused', this)">Paused</button>
            <button class="filter-btn" onclick="filterHunts('completed', this)">Completed</button>
            <button class="filter-btn" onclick="filterHunts('stopped', this)">Stopped</button>
            <div style="flex:1"></div>
            <a href="/new-hunt" class="btn primary sm">+ New Hunt</a>
        </div>
        <div id="hunts-list">
            <div class="panel"><div class="loading-overlay"><div class="spinner lg"></div> Loading hunts...</div></div>
        </div>
    </div>
    <script>
        {_SHARED_JS}
        connectWs(() => {{ loadHunts(); }});
        let allHunts = [];
        let currentFilter = 'all';

        async function loadHunts() {{
            try {{
                const r = await fetch('/api/engagements');
                const d = await r.json();
                allHunts = d.sessions || [];
                updateSummary();
                filterHunts(currentFilter);
            }} catch(e) {{
                document.getElementById('hunts-list').innerHTML = '<div class="empty"><span class="icon">✕</span>Failed to load hunts</div>';
            }}
        }}

        function updateSummary() {{
            document.getElementById('total-hunts').textContent = allHunts.length;
            document.getElementById('active-hunts').textContent = allHunts.filter(s => s.status === 'running').length;
            document.getElementById('paused-hunts').textContent = allHunts.filter(s => s.status === 'paused').length;
            document.getElementById('completed-hunts').textContent = allHunts.filter(s => s.status === 'completed' || s.status === 'stopped').length;
            document.getElementById('total-findings').textContent = allHunts.reduce((a, s) => a + (s.findings || 0), 0);
        }}

        function filterHunts(filter, el) {{
            currentFilter = filter;
            document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
            if (el) el.classList.add('active');
            else document.querySelector('.filter-btn').classList.add('active');
            const filtered = filter === 'all' ? allHunts : allHunts.filter(s => s.status === filter);
            renderHunts(filtered);
        }}

        function renderHunts(hunts) {{
            const el = document.getElementById('hunts-list');
            if (!hunts.length) {{
                el.innerHTML = '<div class="empty-state panel"><span class="icon">◎</span><h4>No hunts found</h4><p>Start your first engagement to begin autonomous research.</p><a href="/new-hunt" class="btn primary">Start a Hunt →</a></div>';
                return;
            }}
            const sevColors = {{running:'green', paused:'yellow', completed:'blue', stopped:'gray', error:'red', initializing:'gray', ready:'gray'}};
            el.innerHTML = hunts.map(s => {{
                const status = s.status || 'unknown';
                const badgeClass = sevColors[status] || 'gray';
                const target = s.target || 'Unknown';
                const displayTarget = target.replace(/^https?:\\/\\//, '').substring(0, 60);
                const strategy = s.strategy || '—';
                const findings = s.findings || 0;
                const evidence = s.evidence || 0;
                const live = s.active ? 'on' : 'off';
                return `
                    <div class="hunt-card" onclick="window.location.href='/hunt/${{s.session_id || encodeURIComponent(target)}}'">
                        <div class="hunt-header">
                            <span class="hunt-target"><span class="live-dot ${{live}}"></span> ${{escapeHtml(displayTarget)}}</span>
                            <span class="badge ${{badgeClass}}">${{escapeHtml(status)}}</span>
                        </div>
                        <div class="hunt-meta">
                            <span>Strategy: <strong style="color:var(--text)">${{escapeHtml(strategy)}}</strong></span>
                            ${{s.session_id ? '<span class="mono" style="font-size:11px;color:var(--text-dim)">' + escapeHtml(s.session_id.substring(0,8)) + '</span>' : ''}}
                            <span>${{s.active ? '<span style="color:var(--success)">● LIVE</span>' : '<span>○ SAVED</span>'}}</span>
                        </div>
                        <div class="hunt-stats">
                            <div class="stat-pill findings"><span class="num">${{findings}}</span> findings</div>
                            <div class="stat-pill evidence"><span class="num">${{evidence}}</span> evidence</div>
                        </div>
                    </div>
                }}).join('');
        }}

        loadHunts();
        setInterval(loadHunts, 5000);
    </script>
</body>
</html>"""


def _findings_html() -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DEMOGORGON — Findings</title>
    <style>{_SHARED_CSS}
        .finding-card {{ background: var(--bg-panel); border: 1px solid var(--border); border-radius: var(--radius-lg); padding: 18px 20px; margin-bottom: 14px; cursor: pointer; transition: all 0.18s; box-shadow: var(--shadow); position: relative; overflow: hidden; }}
        .finding-card::before {{ content: ""; position: absolute; top: 0; left: 0; bottom: 0; width: 3px; background: var(--info); }}
        .finding-card.sev-critical::before {{ background: var(--critical); }}
        .finding-card.sev-high::before {{ background: var(--high); }}
        .finding-card.sev-medium::before {{ background: var(--medium); }}
        .finding-card.sev-low::before {{ background: var(--low); }}
        .finding-card:hover {{ border-color: rgba(0,212,255,0.3); transform: translateY(-2px); box-shadow: 0 8px 32px rgba(0,0,0,0.5); }}
        .finding-card h4 {{ margin-bottom: 8px; font-size: 14px; display: flex; align-items: center; gap: 10px; flex-wrap: wrap; color: var(--text); }}
        .finding-card .meta {{ font-size: 12px; color: var(--text-muted); margin-bottom: 8px; display: flex; gap: 14px; flex-wrap: wrap; }}
        .finding-card .meta span {{ display: flex; align-items: center; gap: 5px; }}
        .finding-card .desc {{ font-size: 13px; color: var(--text-muted); line-height: 1.55; display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden; }}
        .sev-count {{ display: inline-flex; align-items: center; gap: 5px; padding: 5px 12px; border-radius: 99px; font-size: 12px; font-weight: 700; font-family: var(--font-mono); }}
        .sev-count.critical {{ background: rgba(239,68,68,0.12); color: var(--critical); border: 1px solid rgba(239,68,68,0.3); }}
        .sev-count.high {{ background: rgba(249,115,22,0.12); color: var(--high); border: 1px solid rgba(249,115,22,0.3); }}
        .sev-count.medium {{ background: rgba(234,179,8,0.12); color: var(--medium); border: 1px solid rgba(234,179,8,0.3); }}
        .sev-count.low {{ background: rgba(96,165,250,0.12); color: var(--low); border: 1px solid rgba(96,165,250,0.3); }}
        .sev-count.info {{ background: rgba(148,163,184,0.1); color: var(--info); border: 1px solid rgba(148,163,184,0.25); }}
        .sev-bar {{ display: flex; gap: 8px; margin-bottom: 18px; flex-wrap: wrap; }}
    </style>
</head>
<body>
    {_header("findings")}
    <div class="container">
        <div class="page-title">Findings</div>
        <div class="page-sub">All findings across every engagement.</div>
        <div class="sev-bar" id="sev-bar" style="display:none">
            <span class="sev-count critical" id="count-critical">0 critical</span>
            <span class="sev-count high" id="count-high">0 high</span>
            <span class="sev-count medium" id="count-medium">0 medium</span>
            <span class="sev-count low" id="count-low">0 low</span>
            <span class="sev-count info" id="count-info">0 info</span>
        </div>
        <div class="filter-bar">
            <div class="search-box">
                <input type="text" id="search" class="input" placeholder="Search findings..." oninput="renderFiltered()">
            </div>
            <button class="filter-btn active" onclick="setSevFilter('all', this)">All</button>
            <button class="filter-btn" onclick="setSevFilter('critical', this)">Critical</button>
            <button class="filter-btn" onclick="setSevFilter('high', this)">High</button>
            <button class="filter-btn" onclick="setSevFilter('medium', this)">Medium</button>
            <button class="filter-btn" onclick="setSevFilter('low', this)">Low</button>
            <div style="flex:1"></div>
            <select id="sort" class="input" style="width:auto;min-width:140px" onchange="renderFiltered()">
                <option value="severity">Sort: Severity</option>
                <option value="title">Sort: Title</option>
                <option value="target">Sort: Target</option>
            </select>
        </div>
        <div id="findings-list">
            <div class="panel"><div class="loading-overlay"><div class="spinner lg"></div> Loading findings...</div></div>
        </div>
    </div>

    <div class="modal-overlay" id="finding-modal" onclick="if(event.target===this)this.classList.remove('show')">
        <div class="modal-content">
            <div class="modal-header">
                <h3 id="modal-title" style="margin:0">Finding Detail</h3>
                <button class="modal-close" onclick="document.getElementById('finding-modal').classList.remove('show')">✕</button>
            </div>
            <div id="modal-body"></div>
            <div style="margin-top:16px;display:flex;gap:10px;justify-content:flex-end">
                <button class="btn sm" onclick="copyFindingMarkdown()">Copy as Markdown</button>
                <button class="btn primary sm" onclick="document.getElementById('finding-modal').classList.remove('show')">Close</button>
            </div>
        </div>
    </div>

    <script>
        {_SHARED_JS}
        connectWs(() => {{ loadFindings(); }});
        let allFindings = [];
        let sevFilter = 'all';
        let currentDetail = null;

        async function loadFindings() {{
            try {{
                const r = await fetch('/api/engagements');
                const d = await r.json();
                allFindings = [];
                for (const s of d.sessions) {{
                    try {{
                        const fr = await fetch(`/api/engagements/${{encodeURIComponent(s.session_id || s.target)}}/findings`);
                        const fd = await fr.json();
                        if (fd.findings) {{
                            fd.findings.forEach((f, i) => allFindings.push({{...f, target: s.target, session_id: s.session_id, index: i}}));
                        }}
                    }} catch(e) {{ /* skip session */ }}
                }}
                updateSevBar();
                renderFiltered();
            }} catch(e) {{
                document.getElementById('findings-list').innerHTML = '<div class="empty"><span class="icon">✕</span>Failed to load findings</div>';
            }}
        }}

        function updateSevBar() {{
            const counts = {{critical:0, high:0, medium:0, low:0, info:0}};
            allFindings.forEach(f => {{
                const s = (f.severity || 'info').toLowerCase();
                if (counts[s] !== undefined) counts[s]++;
            }});
            document.getElementById('count-critical').textContent = counts.critical + ' critical';
            document.getElementById('count-high').textContent = counts.high + ' high';
            document.getElementById('count-medium').textContent = counts.medium + ' medium';
            document.getElementById('count-low').textContent = counts.low + ' low';
            document.getElementById('count-info').textContent = counts.info + ' info';
            document.getElementById('sev-bar').style.display = allFindings.length ? 'flex' : 'none';
        }}

        function setSevFilter(sev, el) {{
            sevFilter = sev;
            document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
            if (el) el.classList.add('active');
            renderFiltered();
        }}

        function renderFiltered() {{
            const q = (document.getElementById('search').value || '').toLowerCase();
            const sort = document.getElementById('sort').value;
            let list = allFindings.filter(f => {{
                if (sevFilter !== 'all' && (f.severity || '').toLowerCase() !== sevFilter) return false;
                if (q) {{
                    const hay = [f.title, f.description, f.endpoint, f.target, f.vuln_class].join(' ').toLowerCase();
                    if (!hay.includes(q)) return false;
                }}
                return true;
            }});
            const order = {{critical:0, high:1, medium:2, low:3, info:4, unknown:5}};
            list.sort((a, b) => {{
                if (sort === 'severity') return (order[(a.severity||'').toLowerCase()] ?? 5) - (order[(b.severity||'').toLowerCase()] ?? 5);
                if (sort === 'title') return (a.title || '').localeCompare(b.title || '');
                if (sort === 'target') return (a.target || '').localeCompare(b.target || '');
                return 0;
            }});
            const el = document.getElementById('findings-list');
            if (!list.length) {{
                const msg = allFindings.length ? 'No findings match your filters' : 'No findings across any session';
                el.innerHTML = `<div class="empty-state panel"><span class="icon">◎</span><h4>${{msg}}</h4><p>${{allFindings.length ? 'Try adjusting search or severity filters.' : 'Findings will appear here as the agent discovers them.'}}</p></div>`;
                return;
            }}
            el.innerHTML = list.map((f, idx) => `
                <div class="finding-card sev-${{escapeHtml((f.severity||'info').toLowerCase())}}" onclick="showDetail(${{idx}})">
                    <h4>${{sevBadge(f.severity)}} ${{escapeHtml(f.title || 'Untitled')}}</h4>
                    <div class="meta">
                        <span>◎ ${{escapeHtml(f.target || '—')}}</span>
                        ${{f.endpoint ? '<span class="mono">' + escapeHtml(f.endpoint) + '</span>' : ''}}
                        ${{f.vuln_class ? '<span class="badge cyan">' + escapeHtml(f.vuln_class) + '</span>' : ''}}
                    </div>
                    <div class="desc">${{escapeHtml(f.description || '')}}</div>
                </div>
            `).join('');
            window._filtered = list;
        }}

        function showDetail(idx) {{
            const f = (window._filtered || allFindings)[idx];
            if (!f) return;
            currentDetail = f;
            const modal = document.getElementById('finding-modal');
            document.getElementById('modal-title').innerHTML = `${{sevBadge(f.severity)}} ${{escapeHtml(f.title || 'Finding')}}`;
            let html = '';
            html += `<div class="field"><div class="label">Severity</div><div class="val">${{sevBadge(f.severity)}}</div></div>`;
            if (f.target) html += `<div class="field"><div class="label">Target</div><div class="val mono">${{escapeHtml(f.target)}}</div></div>`;
            if (f.endpoint) html += `<div class="field"><div class="label">Endpoint</div><div class="val mono" style="color:var(--accent)">${{escapeHtml(f.endpoint)}}</div></div>`;
            if (f.vuln_class) html += `<div class="field"><div class="label">Class</div><div class="val">${{escapeHtml(f.vuln_class)}}</div></div>`;
            if (f.description) html += `<div class="field"><div class="label">Description</div><div class="val">${{escapeHtml(f.description)}}</div></div>`;
            if (f.impact) html += `<div class="field"><div class="label">Impact</div><div class="val">${{escapeHtml(f.impact)}}</div></div>`;
            if (f.remediation) html += `<div class="field"><div class="label">Remediation</div><div class="val">${{escapeHtml(f.remediation)}}</div></div>`;
            const steps = f.steps || f.steps_to_reproduce || f.reproduction_steps;
            if (steps && steps.length) html += `<div class="field"><div class="label">Reproduction Steps</div><div class="val">${{steps.map((s,i) => `${{i+1}}. ${{escapeHtml(s)}}`).join('<br>')}}</div></div>`;
            if (f.evidence) html += `<div class="field"><div class="label">Evidence</div><pre class="code">${{escapeHtml(typeof f.evidence === 'string' ? f.evidence : JSON.stringify(f.evidence, null, 2))}}</pre></div>`;
            document.getElementById('modal-body').innerHTML = html;
            modal.classList.add('show');
        }}

        function copyFindingMarkdown() {{
            const f = currentDetail;
            if (!f) return;
            const md = [
                `## ${{f.title || 'Finding'}}`,
                `**Severity:** ${{f.severity || 'unknown'}}`,
                f.target ? `**Target:** ${{f.target}}` : '',
                f.endpoint ? `**Endpoint:** ${{f.endpoint}}` : '',
                f.vuln_class ? `**Class:** ${{f.vuln_class}}` : '',
                '',
                f.description || '',
                f.impact ? `\\n**Impact:** ${{f.impact}}` : '',
            ].filter(Boolean).join('\\n');
            navigator.clipboard.writeText(md).then(() => showToast('Copied as Markdown', 'success'));
        }}

        document.addEventListener('keydown', e => {{ if(e.key==='Escape') document.getElementById('finding-modal').classList.remove('show'); }});
        loadFindings();
        setInterval(loadFindings, 8000);
    </script>
</body>
</html>"""
