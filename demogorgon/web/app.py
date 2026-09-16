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
    title="DEMOGOORGON Control Center",
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
    """List available security tools."""
    from ..agent.capabilities import CapabilityRegistry
    registry = CapabilityRegistry()
    caps = registry.get_available_capabilities()
    return {"capabilities": caps}


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
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: 'SF Mono', 'Fira Code', 'Cascadia Code', monospace; background: #0a0a0f; color: #e0e0e0; min-height: 100vh; }
a { color: #00d4ff; text-decoration: none; }
a:hover { text-decoration: underline; }
.header { background: #12121a; border-bottom: 1px solid #1a1a2e; padding: 16px 24px; display: flex; align-items: center; justify-content: space-between; }
.header h1 { font-size: 18px; color: #00d4ff; }
.header nav { display: flex; gap: 16px; font-size: 13px; }
.header nav a { color: #888; }
.header nav a.active { color: #00d4ff; }
.header .status { font-size: 13px; }
.container { max-width: 1200px; margin: 0 auto; padding: 24px; }
.panel { background: #12121a; border: 1px solid #1a1a2e; border-radius: 8px; padding: 16px; margin-bottom: 16px; }
.panel h3 { color: #00d4ff; font-size: 14px; margin-bottom: 12px; text-transform: uppercase; letter-spacing: 1px; }
.stat { display: flex; justify-content: space-between; padding: 8px 0; border-bottom: 1px solid #1a1a2e; font-size: 13px; }
.stat:last-child { border-bottom: none; }
.stat .label { color: #888; }
.stat .value { color: #e0e0e0; font-weight: bold; }
.btn { background: #1a1a2e; color: #e0e0e0; border: 1px solid #2a2a3e; padding: 10px 20px; border-radius: 4px; cursor: pointer; font-family: inherit; font-size: 13px; transition: background 0.2s; }
.btn:hover { background: #2a2a3e; }
.btn.primary { background: #00d4ff; color: #0a0a0f; border-color: #00d4ff; font-weight: bold; }
.btn.primary:hover { background: #00b8d4; }
.btn.danger { background: #ef4444; color: white; border-color: #ef4444; }
.btn.success { background: #4ade80; color: #0a0a0f; border-color: #4ade80; }
.input { background: #0a0a0f; color: #e0e0e0; border: 1px solid #1a1a2e; padding: 10px 14px; border-radius: 4px; font-family: inherit; font-size: 13px; width: 100%; }
.input:focus { outline: none; border-color: #00d4ff; }
textarea.input { min-height: 120px; resize: vertical; }
label { display: block; color: #888; font-size: 12px; margin-bottom: 6px; text-transform: uppercase; letter-spacing: 0.5px; }
.form-group { margin-bottom: 16px; }
.row { display: flex; gap: 16px; }
.row > * { flex: 1; }
.empty { color: #555; font-style: italic; font-size: 13px; padding: 20px; text-align: center; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; }
.badge.green { background: #0a1a0a; color: #4ade80; border: 1px solid #166534; }
.badge.red { background: #1a0a0a; color: #ef4444; border: 1px solid #991b1b; }
.badge.yellow { background: #1a1a0a; color: #eab308; border: 1px solid #854d0e; }
.badge.blue { background: #0a0a1a; color: #60a5fa; border: 1px solid #1e40af; }
.grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
@media (max-width: 768px) { .grid { grid-template-columns: 1fr; } .row { flex-direction: column; } }
.toast-container { position: fixed; bottom: 20px; right: 20px; z-index: 9999; display: flex; flex-direction: column; gap: 8px; }
.toast { padding: 12px 20px; border-radius: 6px; font-size: 13px; font-family: inherit; color: white; opacity: 0; transform: translateX(100px); animation: toastIn 0.3s ease forwards; max-width: 400px; word-break: break-word; }
.toast.error { background: #991b1b; border: 1px solid #ef4444; }
.toast.success { background: #166534; border: 1px solid #4ade80; }
.toast.info { background: #1e40af; border: 1px solid #60a5fa; }
@keyframes toastIn { to { opacity: 1; transform: translateX(0); } }
.spinner { display: inline-block; width: 16px; height: 16px; border: 2px solid #333; border-top-color: #00d4ff; border-radius: 50%; animation: spin 0.6s linear infinite; }
@keyframes spin { to { transform: rotate(360deg); } }
.loading-overlay { display: flex; align-items: center; justify-content: center; gap: 8px; padding: 20px; color: #888; font-size: 13px; }
"""


def _setup_html() -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DEMOGOORGON — Setup</title>
    <style>{_SHARED_CSS}</style>
</head>
<body>
    <div class="header">
        <h1>DEMOGOORGON</h1>
        <nav>
            <a href="/setup" class="active">Setup</a>
            <a href="/hunts">Hunts</a>
            <a href="/new-hunt">New Hunt</a>
            <a href="/hunt">Dashboard</a>
            <a href="/findings">Findings</a>
        </nav>
        <div class="status" id="ws-status">● CONNECTING</div>
    </div>
    <div class="container">
        <div class="grid">
            <div>
                <div class="panel">
                    <h3>Provider Configuration</h3>
                    <div class="form-group">
                        <label>Provider</label>
                        <select id="provider-select" class="input" onchange="onProviderChange()">
                            <option value="openrouter">OpenRouter</option>
                            <option value="openai">OpenAI</option>
                            <option value="anthropic">Anthropic</option>
                            <option value="gemini">Google Gemini</option>
                            <option value="deepseek">DeepSeek</option>
                            <option value="ollama">Ollama (Local)</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label>API Key</label>
                        <input type="password" id="api-key" class="input" placeholder="sk-...">
                    </div>
                    <div class="form-group">
                        <label>Base URL (optional)</label>
                        <input type="text" id="base-url" class="input" placeholder="https://openrouter.ai/api/v1">
                    </div>
                    <div style="display:flex;gap:8px">
                        <button class="btn" onclick="testConnection()">Test Connection</button>
                        <button class="btn primary" onclick="saveProvider()">Save Provider</button>
                    </div>
                    <div id="test-result" style="margin-top:12px;font-size:13px"></div>
                </div>
                <div class="panel">
                    <h3>Model Selection</h3>
                    <div class="form-group">
                        <label>Model</label>
                        <select id="model-select" class="input">
                            <option value="">Click "Discover Models" first</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label>Or type custom model name</label>
                        <input type="text" id="custom-model" class="input" placeholder="provider/model-name">
                    </div>
                    <button class="btn" onclick="discoverModels()">Discover Models</button>
                </div>
            </div>
            <div>
                <div class="panel">
                    <h3>Current Status</h3>
                    <div id="current-status">
                        <div class="empty">Loading...</div>
                    </div>
                </div>
                <div class="panel">
                    <h3>Configured Providers</h3>
                    <div id="provider-list">
                        <div class="empty">Loading...</div>
                    </div>
                </div>
                <div class="panel">
                    <h3>Quick Start</h3>
                    <p style="font-size:13px;color:#888;margin-bottom:12px">After configuring a provider:</p>
                    <a href="/new-hunt" class="btn primary" style="display:inline-block;text-align:center">Start a Hunt →</a>
                </div>
            </div>
        </div>
    </div>
    <script>
        const ws = new WebSocket(`ws://${{location.host}}/ws/events`);
        ws.onopen = () => {{
            document.getElementById('ws-status').textContent = '● CONNECTED';
            document.getElementById('ws-status').style.color = '#4ade80';
        }};
        ws.onclose = () => {{
            document.getElementById('ws-status').textContent = '● OFFLINE';
            document.getElementById('ws-status').style.color = '#ef4444';
        }};

        async function loadStatus() {{
            const r = await fetch('/api/status');
            const d = await r.json();
            let html = '';
            if (d.provider) {{
                html += `<div class="stat"><span class="label">Provider</span><span class="value">${{d.provider}}</span></div>`;
                html += `<div class="stat"><span class="label">Model</span><span class="value">${{d.model || '—'}}</span></div>`;
                html += `<div class="stat"><span class="label">Key</span><span class="value">${{d.has_key ? '✓ configured' : '✗ missing'}}</span></div>`;
            }} else {{
                html = '<div class="empty">No provider configured</div>';
            }}
            document.getElementById('current-status').innerHTML = html;
        }}

        async function loadProviders() {{
            const r = await fetch('/api/providers');
            const d = await r.json();
            if (!d.providers.length) {{
                document.getElementById('provider-list').innerHTML = '<div class="empty">None configured</div>';
                return;
            }}
            let html = '';
            d.providers.forEach(p => {{
                html += `<div class="stat"><span class="label">${{p.provider}}</span><span class="value"><span class="badge green">${{p.model || '?'}}</span></span></div>`;
            }});
            document.getElementById('provider-list').innerHTML = html;
        }}

        async function testConnection() {{
            const provider = document.getElementById('provider-select').value;
            const key = document.getElementById('api-key').value;
            const url = document.getElementById('base-url').value;
            document.getElementById('test-result').innerHTML = '<span style="color:#888">Testing...</span>';
            const r = await fetch('/api/providers/test', {{
                method: 'POST',
                headers: {{'Content-Type': 'application/json'}},
                body: JSON.stringify({{provider, api_key: key, base_url: url}})
            }});
            const d = await r.json();
            if (d.success) {{
                document.getElementById('test-result').innerHTML = '<span style="color:#4ade80">✓ Connection successful</span>';
            }} else {{
                document.getElementById('test-result').innerHTML = `<span style="color:#ef4444">✗ ${{d.error || 'Failed'}}</span>`;
            }}
        }}

        async function saveProvider() {{
            const provider = document.getElementById('provider-select').value;
            const key = document.getElementById('api-key').value;
            const url = document.getElementById('base-url').value;
            const model = document.getElementById('custom-model').value || document.getElementById('model-select').value;
            if (!key) {{ alert('API key required'); return; }}
            const r = await fetch('/api/providers', {{
                method: 'POST',
                headers: {{'Content-Type': 'application/json'}},
                body: JSON.stringify({{provider, api_key: key, base_url: url, selected_model: model}})
            }});
            const d = await r.json();
            if (d.status === 'ok') {{
                alert('Provider saved!');
                loadStatus();
                loadProviders();
            }} else {{
                alert('Failed to save');
            }}
        }}

        async function discoverModels() {{
            const provider = document.getElementById('provider-select').value;
            const key = document.getElementById('api-key').value;
            const url = document.getElementById('base-url').value;
            // Test connection without saving config
            if (key) {{
                await fetch('/api/providers/test', {{
                    method: 'POST',
                    headers: {{'Content-Type': 'application/json'}},
                    body: JSON.stringify({{provider, api_key: key, base_url: url}})
                }});
            }}
            const r = await fetch(`/api/models?provider=${{provider}}`);
            const d = await r.json();
            const sel = document.getElementById('model-select');
            sel.innerHTML = '';
            if (!d.models || !d.models.length) {{
                sel.innerHTML = '<option value="">No models found</option>';
                return;
            }}
            d.models.slice(0, 50).forEach(m => {{
                const opt = document.createElement('option');
                opt.value = m.id;
                opt.textContent = m.id;
                sel.appendChild(opt);
            }});
        }}

        function onProviderChange() {{
            const p = document.getElementById('provider-select').value;
            const urlMap = {{
                openrouter: 'https://openrouter.ai/api/v1',
                openai: 'https://api.openai.com/v1',
                anthropic: 'https://api.anthropic.com',
                gemini: 'https://generativelanguage.googleapis.com/v1beta',
                deepseek: 'https://api.deepseek.com/v1',
                ollama: 'http://localhost:11434/v1',
            }};
            document.getElementById('base-url').value = urlMap[p] || '';
        }}

        loadStatus();
        loadProviders();
    </script>
</body>
</html>"""


def _new_hunt_html() -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DEMOGOORGON — New Hunt</title>
    <style>{_SHARED_CSS}</style>
</head>
<body>
    <div class="header">
        <h1>DEMOGOORGON</h1>
        <nav>
            <a href="/setup">Setup</a>
            <a href="/hunts">Hunts</a>
            <a href="/new-hunt" class="active">New Hunt</a>
            <a href="/hunt">Dashboard</a>
            <a href="/findings">Findings</a>
        </nav>
        <div class="status" id="ws-status">● CONNECTING</div>
    </div>
    <div class="container">
        <div class="grid">
            <div>
                <div class="panel">
                    <h3>Target</h3>
                    <div class="form-group">
                        <label>Target URL or Domain</label>
                        <input type="text" id="target" class="input" placeholder="https://example.com">
                    </div>
                </div>
                <div class="panel">
                    <h3>Program Policy (optional)</h3>
                    <div class="form-group">
                        <label>Paste bug bounty program text (HackerOne, Bugcrowd, etc.)</label>
                        <textarea id="program-text" class="input" placeholder="Paste program guidelines here...\n\nScope will be auto-parsed."></textarea>
                    </div>
                </div>
                <div class="panel">
                    <h3>Budget</h3>
                    <div class="row">
                        <div class="form-group">
                            <label>Max Cycles</label>
                            <input type="number" id="max-cycles" class="input" value="50">
                        </div>
                        <div class="form-group">
                            <label>Max Cost (USD)</label>
                            <input type="number" id="max-cost" class="input" value="2.00" step="0.50">
                        </div>
                        <div class="form-group">
                            <label>Max Requests</label>
                            <input type="number" id="max-requests" class="input" value="200">
                        </div>
                    </div>
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
                <button class="btn primary" onclick="startHunt()" style="width:100%;padding:14px;font-size:15px">
                    Start Hunt →
                </button>
            </div>
            <div>
                <div class="panel">
                    <h3>Active Provider</h3>
                    <div id="provider-info"><div class="empty">Loading...</div></div>
                </div>
                <div class="panel">
                    <h3>Recent Hunts</h3>
                    <div id="recent-hunts"><div class="empty">Loading...</div></div>
                </div>
                <div class="panel">
                    <h3>Tips</h3>
                    <ul style="font-size:13px;color:#888;line-height:1.8;padding-left:16px">
                        <li>Paste a program policy to auto-parse scope</li>
                        <li>Start with recon strategy, agent will adapt</li>
                        <li>Use /pause and /resume from terminal</li>
                        <li>Web UI shows same live events</li>
                    </ul>
                </div>
            </div>
        </div>
    </div>
    <script>
        const ws = new WebSocket(`ws://${{location.host}}/ws/events`);
        ws.onopen = () => {{
            document.getElementById('ws-status').textContent = '● CONNECTED';
            document.getElementById('ws-status').style.color = '#4ade80';
        }};
        ws.onclose = () => {{
            document.getElementById('ws-status').textContent = '● OFFLINE';
            document.getElementById('ws-status').style.color = '#ef4444';
        }};

        async function loadProvider() {{
            const r = await fetch('/api/providers/active');
            const d = await r.json();
            if (d.provider) {{
                document.getElementById('provider-info').innerHTML = `
                    <div class="stat"><span class="label">Provider</span><span class="value">${{d.provider}}</span></div>
                    <div class="stat"><span class="label">Model</span><span class="value">${{d.model}}</span></div>
                    <div class="stat"><span class="label">Key</span><span class="value">${{d.masked_key || '—'}}</span></div>
                `;
            }} else {{
                document.getElementById('provider-info').innerHTML = '<div class="empty">No provider — <a href="/setup">configure first</a></div>';
            }}
        }}

        async function loadRecent() {{
            const r = await fetch('/api/engagements');
            const d = await r.json();
            if (!d.sessions.length) {{
                document.getElementById('recent-hunts').innerHTML = '<div class="empty">No hunts yet</div>';
                return;
            }}
            let html = '';
            d.sessions.slice(0, 5).forEach(s => {{
                const badge = s.active ? 'green' : 'blue';
                html += `<div class="stat">
                    <span class="label">${{s.target}}</span>
                    <span class="value"><span class="badge ${{badge}}">${{s.status}}</span></span>
                </div>`;
            }});
            document.getElementById('recent-hunts').innerHTML = html;
        }}

        async function startHunt() {{
            const target = document.getElementById('target').value.trim();
            if (!target) {{ alert('Target required'); return; }}

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
                // Start the session
                await fetch(`/api/engagements/${{d.session_id}}/start`, {{method: 'POST'}});
                // Navigate to dashboard using session_id
                window.location.href = `/hunt/${{d.session_id}}`;
            }} else {{
                alert('Failed: ' + (d.detail || 'Unknown error'));
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
    <title>DEMOGOORGON — Research Dashboard</title>
    <style>{_SHARED_CSS}
        .container {{ display: grid; grid-template-columns: 280px 1fr 320px; gap: 16px; padding: 16px; height: calc(100vh - 56px); }}
        .sidebar {{ overflow-y: auto; }}
        .main {{ overflow-y: auto; }}
        .right {{ overflow-y: auto; }}
        .event-stream {{ max-height: calc(100vh - 200px); overflow-y: auto; }}
        .event {{ padding: 6px 10px; border-left: 3px solid #1a1a2e; margin-bottom: 3px; font-size: 12px; }}
        .event.finding {{ border-color: #4ade80; background: #0a1a0a; }}
        .event.action {{ border-color: #00d4ff; background: #0a0a1a; }}
        .event.error {{ border-color: #ef4444; background: #1a0a0a; }}
        .event.tool {{ border-color: #a855f7; background: #0f0a1a; }}
        .event.log {{ border-color: #888; background: #12121a; }}
        .event .time {{ color: #555; }}
        .event .type {{ color: #00d4ff; font-weight: bold; }}
        .findings-list .finding-item {{ padding: 8px 12px; border-left: 3px solid #4ade80; margin-bottom: 4px; background: #0a1a0a; font-size: 12px; cursor: pointer; transition: background 0.2s; }}
        .findings-list .finding-item:hover {{ background: #0f1f0f; }}
        .findings-list .finding-item .sev {{ font-weight: bold; }}
        .findings-list .finding-item .sev.critical {{ color: #ef4444; }}
        .findings-list .finding-item .sev.high {{ color: #f97316; }}
        .findings-list .finding-item .sev.medium {{ color: #eab308; }}
        .findings-list .finding-item .sev.low {{ color: #60a5fa; }}
        .scope-list {{ font-size: 12px; }}
        .scope-list .scope-item {{ display: flex; justify-content: space-between; align-items: center; padding: 4px 0; border-bottom: 1px solid #1a1a2e; }}
        .scope-list .scope-item .pattern {{ color: #4ade80; word-break: break-all; }}
        .scope-list .scope-item .type {{ color: #888; font-size: 11px; }}
        .scope-list .scope-item .remove {{ color: #ef4444; cursor: pointer; font-size: 11px; }}
        .scope-list .scope-item .remove:hover {{ text-decoration: underline; }}
        .scope-add {{ display: flex; gap: 4px; margin-top: 8px; }}
        .scope-add input {{ flex: 1; padding: 6px 8px; font-size: 11px; }}
        .scope-add select {{ width: 80px; padding: 6px 8px; font-size: 11px; }}
        .instruction-box {{ display: flex; gap: 4px; margin-top: 8px; }}
        .instruction-box input {{ flex: 1; }}
        .detail-modal {{ display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.8); z-index: 1000; justify-content: center; align-items: center; }}
        .detail-modal.show {{ display: flex; }}
        .detail-content {{ background: #12121a; border: 1px solid #1a1a2e; border-radius: 8px; padding: 24px; max-width: 700px; width: 90%; max-height: 80vh; overflow-y: auto; }}
        .detail-content h3 {{ color: #00d4ff; margin-bottom: 12px; }}
        .detail-content .field {{ margin-bottom: 8px; }}
        .detail-content .field .label {{ color: #888; font-size: 11px; text-transform: uppercase; }}
        .detail-content .field .val {{ color: #e0e0e0; font-size: 13px; margin-top: 2px; }}
        .detail-content pre {{ background: #0a0a0f; padding: 12px; border-radius: 4px; font-size: 12px; overflow-x: auto; color: #ccc; }}
        @media (max-width: 1024px) {{ .container {{ grid-template-columns: 1fr; }} }}
    </style>
</head>
<body>
    <div class="header">
        <h1>DEMOGOORGON</h1>
        <nav>
            <a href="/setup">Setup</a>
            <a href="/hunts">Hunts</a>
            <a href="/new-hunt">New Hunt</a>
            <a href="/hunt" class="active">Dashboard</a>
            <a href="/findings">Findings</a>
        </nav>
        <div class="status" id="ws-status">● CONNECTING</div>
    </div>
    <div class="container">
        <div class="sidebar">
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
                <div class="stat"><span class="label">Cycles</span><span class="value" id="cycles">0</span></div>
                <div class="stat"><span class="label">Cost</span><span class="value" id="cost">$0.00</span></div>
                <div class="stat"><span class="label">Requests</span><span class="value" id="requests">0</span></div>
                <div class="stat"><span class="label">Tokens</span><span class="value" id="tokens">0</span></div>
                <div class="stat"><span class="label">Findings</span><span class="value" id="findings-count" style="color:#4ade80">0</span></div>
                <div class="stat"><span class="label">Evidence</span><span class="value" id="evidence-count" style="color:#a855f7">0</span></div>
            </div>
            <div class="panel">
                <h3>Controls</h3>
                <button class="btn success" onclick="resumeSession()" style="width:100%;margin-bottom:8px">▶ Resume</button>
                <button class="btn" onclick="pauseSession()" style="width:100%;margin-bottom:8px">⏸ Pause</button>
                <button class="btn danger" onclick="stopSession()" style="width:100%;margin-bottom:8px">■ Stop</button>
                <button class="btn" onclick="exportFindings()" style="width:100%">↓ Export Findings</button>
            </div>
            <div class="panel">
                <h3>Scope <span id="scope-count" style="color:#888;font-size:11px">(0)</span></h3>
                <div id="scope-list" class="scope-list"><div class="empty">No scope loaded</div></div>
                <div class="scope-add">
                    <input type="text" id="scope-pattern" class="input" placeholder="pattern" style="padding:6px 8px;font-size:11px">
                    <select id="scope-type" class="input" style="width:80px;padding:6px 8px;font-size:11px">
                        <option value="url">URL</option>
                        <option value="domain">Domain</option>
                        <option value="wildcard">Wildcard</option>
                        <option value="cidr">CIDR</option>
                    </select>
                    <button class="btn" onclick="addScope()" style="padding:6px 10px;font-size:11px">+</button>
                </div>
            </div>
            <div class="panel">
                <h3>Send Instruction</h3>
                <div class="instruction-box">
                    <input type="text" id="instruction-input" class="input" placeholder="e.g. focus on XSS on /api" style="padding:6px 8px;font-size:11px">
                    <button class="btn" onclick="sendInstruction()" style="padding:6px 10px;font-size:11px">→</button>
                </div>
            </div>
        </div>
        <div class="main">
            <div class="panel" style="flex:1;display:flex;flex-direction:column">
                <h3>Live Event Stream</h3>
                <div class="event-stream" id="events" style="flex:1;overflow-y:auto">
                    <div class="empty">Waiting for events...</div>
                </div>
            </div>
        </div>
        <div class="right">
            <div class="panel">
                <h3>Findings <span id="findings-badge" style="color:#888;font-size:11px"></span></h3>
                <div id="findings-list" class="findings-list"><div class="empty">No findings yet</div></div>
            </div>
            <div class="panel">
                <h3>Recent Activity</h3>
                <div id="trace-list" style="font-size:12px"><div class="empty">No trace entries</div></div>
            </div>
            <div class="panel">
                <h3>Tools</h3>
                <div id="tools-list" style="font-size:12px"><div class="empty">Loading...</div></div>
            </div>
        </div>
    </div>

    <!-- Finding Detail Modal -->
    <div class="detail-modal" id="finding-modal" onclick="if(event.target===this)this.classList.remove('show')">
        <div class="detail-content">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">
                <h3 id="modal-title" style="margin:0">Finding Detail</h3>
                <button class="btn" onclick="document.getElementById('finding-modal').classList.remove('show')" style="padding:4px 12px">✕</button>
            </div>
            <div id="modal-body"></div>
        </div>
    </div>

    <script>
        const sessionId = '{session_id}';

        function escapeHtml(s) {{
            if (!s) return '';
            const d = document.createElement('div');
            d.appendChild(document.createTextNode(s));
            return d.innerHTML;
        }}

        function showToast(msg, type='error') {{
            let c = document.querySelector('.toast-container');
            if (!c) {{ c = document.createElement('div'); c.className = 'toast-container'; document.body.appendChild(c); }}
            const t = document.createElement('div');
            t.className = 'toast ' + type;
            t.textContent = msg;
            c.appendChild(t);
            setTimeout(() => {{ t.style.opacity = '0'; setTimeout(() => t.remove(), 300); }}, 4000);
        }}

        function showLoading(el) {{ el.innerHTML = '<div class="loading-overlay"><div class="spinner"></div> Loading...</div>'; }}

        const ws = new WebSocket(`ws://${{location.host}}/ws/events`);
        const eventsDiv = document.getElementById('events');
        let eventCount = 0;

        ws.onopen = () => {{
            document.getElementById('ws-status').textContent = '● CONNECTED';
            document.getElementById('ws-status').style.color = '#4ade80';
        }};
        ws.onclose = () => {{
            document.getElementById('ws-status').textContent = '● RECONNECTING...';
            document.getElementById('ws-status').style.color = '#eab308';
            setTimeout(() => {{ loadSession(); loadFindings(); loadTrace(); }}, 2000);
        }};
        ws.onmessage = (e) => {{
            const event = JSON.parse(e.data);
            addEvent(event);
            updateFromEvent(event);
        }};

        function addEvent(event) {{
            if (eventCount === 0) eventsDiv.innerHTML = '';
            eventCount++;
            const div = document.createElement('div');
            div.className = 'event';
            const time = new Date(event.timestamp * 1000).toLocaleTimeString();
            const type = event.type || 'unknown';
            const data = event.data || {{}};
            let msg = '';
            if (type.includes('finding')) {{ div.className += ' finding'; msg = data.title || data.description || JSON.stringify(data).substring(0,120); }}
            else if (type.includes('tool')) {{ div.className += ' tool'; msg = (data.tool||'') + ' ' + (data.target||data.command||'').substring(0,80); }}
            else if (type.includes('error')) {{ div.className += ' error'; msg = data.error || data.message || JSON.stringify(data).substring(0,120); }}
            else if (type.includes('action') || type.includes('decision')) {{ div.className += ' action'; msg = data.action || data.content || JSON.stringify(data).substring(0,120); }}
            else {{ div.className += ' log'; msg = data.message || data.content || JSON.stringify(data).substring(0,120); }}
            div.innerHTML = `<span class="time">${{time}}</span> <span class="type">${{type}}</span> ${{msg.substring(0,150)}}`;
            eventsDiv.appendChild(div);
            eventsDiv.scrollTop = eventsDiv.scrollHeight;
        }}

        function updateFromEvent(event) {{
            const type = event.type || '';
            const data = event.data || {{}};
            if (type === 'status_change') document.getElementById('status').textContent = data.status || '—';
            if (type === 'strategy_change') document.getElementById('strategy').textContent = data.to || '—';
            if (type === 'progress_update') {{
                document.getElementById('cycles').textContent = data.cycle || '0';
                document.getElementById('findings-count').textContent = data.findings || '0';
                if (data.budget) {{
                    document.getElementById('cost').textContent = '$' + (data.budget.cost_usd || 0).toFixed(2);
                    document.getElementById('requests').textContent = data.budget.requests || 0;
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
            }} catch(e) {{ showToast('Failed to load session: ' + e.message); }}
        }}

        function updateSessionUI(s) {{
            document.getElementById('target').textContent = s.target || '—';
            document.getElementById('provider').textContent = s.provider || '—';
            document.getElementById('model').textContent = s.model || '—';
            document.getElementById('status').textContent = s.status || '—';
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
                    document.getElementById('cost').textContent = '$' + (d.budget.cost_usd || 0).toFixed(2);
                    document.getElementById('requests').textContent = d.budget.requests || 0;
                }}
                if (d.tokens) document.getElementById('tokens').textContent = d.tokens.total || 0;
                document.getElementById('cycles').textContent = d.total_cycles || 0;
            }} catch(e) {{ showToast('Request failed: ' + e.message); }}
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
                el.innerHTML = d.in_scope.map((a, i) => `
                    <div class="scope-item">
                        <div>
                            <div class="pattern">${{a.pattern}}</div>
                            <div class="type">${{a.asset_type || 'url'}}</div>
                        </div>
                        <span class="remove" onclick="removeScope('${{a.pattern}}')">✕</span>
                    </div>
                `).join('');
            }} catch(e) {{ showToast('Request failed: ' + e.message); }}
        }}

        async function addScope() {{
            const id = sessionId || document.getElementById('target').textContent;
            if (!id || id === '—') return;
            const pattern = document.getElementById('scope-pattern').value.trim();
            if (!pattern) return;
            const asset_type = document.getElementById('scope-type').value;
            await fetch(`/api/engagements/${{encodeURIComponent(id)}}/scope`, {{
                method: 'POST',
                headers: {{'Content-Type': 'application/json'}},
                body: JSON.stringify({{pattern, asset_type}})
            }});
            document.getElementById('scope-pattern').value = '';
            loadScope();
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
            await fetch(`/api/engagements/${{encodeURIComponent(id)}}/instructions`, {{
                method: 'POST',
                headers: {{'Content-Type': 'application/json'}},
                body: JSON.stringify({{instruction}})
            }});
            input.value = '';
        }}

        async function loadFindings() {{
            const id = sessionId || document.getElementById('target').textContent;
            if (!id || id === '—') return;
            try {{
                const r = await fetch(`/api/engagements/${{encodeURIComponent(id)}}/findings`);
                const d = await r.json();
                const el = document.getElementById('findings-list');
                document.getElementById('findings-badge').textContent = d.findings ? `(${{d.findings.length}})` : '';
                if (!d.findings || !d.findings.length) {{
                    el.innerHTML = '<div class="empty">No findings yet</div>';
                    return;
                }}
                el.innerHTML = d.findings.map((f, i) => {{
                    const sev = f.severity || '?';
                    return `<div class="finding-item" onclick="showFindingDetail(${{i}})"><span class="sev ${{sev}}">${{sev.toUpperCase()}}</span> ${{escapeHtml(f.title || f.description || 'Untitled')}}</div>`;
                }}).join('');
            }} catch(e) {{ showToast('Request failed: ' + e.message); }}
        }}

        async function showFindingDetail(idx) {{
            const id = sessionId || document.getElementById('target').textContent;
            if (!id || id === '—') return;
            try {{
                const r = await fetch(`/api/engagements/${{encodeURIComponent(id)}}/findings/${{idx}}`);
                const d = await r.json();
                const f = d.finding;
                const modal = document.getElementById('finding-modal');
                document.getElementById('modal-title').textContent = f.title || 'Finding';
                let html = '';
                html += `<div class="field"><div class="label">Severity</div><div class="val"><span class="badge ${{f.severity === 'critical' ? 'red' : f.severity === 'high' ? 'yellow' : 'blue'}}">${{(f.severity||'?').toUpperCase()}}</span></div></div>`;
                if (f.vuln_class) html += `<div class="field"><div class="label">Vulnerability Class</div><div class="val">${{escapeHtml(f.vuln_class)}}</div></div>`;
                if (f.endpoint) html += `<div class="field"><div class="label">Endpoint</div><div class="val" style="color:#00d4ff">${{escapeHtml(f.endpoint)}}</div></div>`;
                if (f.description) html += `<div class="field"><div class="label">Description</div><div class="val">${{escapeHtml(f.description)}}</div></div>`;
                if (f.impact) html += `<div class="field"><div class="label">Impact</div><div class="val">${{escapeHtml(f.impact)}}</div></div>`;
                if (f.steps && f.steps.length) html += `<div class="field"><div class="label">Reproduction Steps</div><div class="val">${{f.steps.map((s,i) => `${{i+1}}. ${{escapeHtml(s)}}`).join('<br>')}}</div></div>`;
                if (f.evidence) html += `<div class="field"><div class="label">Evidence</div><pre>${{escapeHtml(typeof f.evidence === 'string' ? f.evidence : JSON.stringify(f.evidence, null, 2))}}</pre></div>`;
                if (f.raw) html += `<div class="field"><div class="label">Raw Data</div><pre>${{JSON.stringify(f.raw, null, 2)}}</pre></div>`;
                document.getElementById('modal-body').innerHTML = html;
                modal.classList.add('show');
            }} catch(e) {{ showToast('Request failed: ' + e.message); }}
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
                el.innerHTML = d.trace.slice(0, 15).map(e => {{
                    const ts = new Date(e.timestamp * 1000).toLocaleTimeString();
                    return `<div style="padding:3px 0;border-bottom:1px solid #1a1a2e"><span style="color:#555">${{ts}}</span> <span style="color:#00d4ff">${{e.type}}</span> ${{e.content.substring(0, 60)}}</div>`;
                }}).join('');
            }} catch(e) {{ showToast('Request failed: ' + e.message); }}
        }}

        async function loadTools() {{
            try {{
                const r = await fetch('/api/tools');
                const d = await r.json();
                const el = document.getElementById('tools-list');
                if (!d.capabilities || !d.capabilities.length) {{
                    el.innerHTML = '<div class="empty">No tools registered</div>';
                    return;
                }}
                el.innerHTML = d.capabilities.map(c => `<div style="padding:2px 0;color:#888">• ${{c}}</div>`).join('');
            }} catch(e) {{ showToast('Request failed: ' + e.message); }}
        }}

        async function pauseSession() {{
            const id = sessionId || document.getElementById('target').textContent;
            if (!id || id === '—') return;
            if (!confirm('Pause this hunt?')) return;
            await fetch(`/api/engagements/${{encodeURIComponent(id)}}/pause`, {{method: 'POST'}});
            document.getElementById('status').textContent = 'PAUSED';
        }}

        async function resumeSession() {{
            const id = sessionId || document.getElementById('target').textContent;
            if (!id || id === '—') return;
            if (!confirm('Resume this hunt?')) return;
            await fetch(`/api/engagements/${{encodeURIComponent(id)}}/resume`, {{method: 'POST'}});
            document.getElementById('status').textContent = 'RUNNING';
        }}

        async function stopSession() {{
            const id = sessionId || document.getElementById('target').textContent;
            if (!id || id === '—') return;
            if (!confirm('Stop this session?')) return;
            await fetch(`/api/engagements/${{encodeURIComponent(id)}}/stop`, {{method: 'POST'}});
            document.getElementById('status').textContent = 'STOPPED';
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
            }} catch(e) {{ showToast('Export failed: ' + e.message); }}
        }}

        // Handle Enter key on inputs
        document.getElementById('scope-pattern').addEventListener('keydown', e => {{ if(e.key==='Enter') addScope(); }});
        document.getElementById('instruction-input').addEventListener('keydown', e => {{ if(e.key==='Enter') sendInstruction(); }});

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
    <title>DEMOGOORGON — Hunts</title>
    <style>{_SHARED_CSS}
        .hunt-card {{ background: #12121a; border: 1px solid #1a1a2e; border-radius: 8px; padding: 16px; margin-bottom: 12px; cursor: pointer; transition: border-color 0.2s; }}
        .hunt-card:hover {{ border-color: #00d4ff; }}
        .hunt-card .hunt-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }}
        .hunt-card .hunt-target {{ color: #00d4ff; font-size: 15px; font-weight: bold; }}
        .hunt-card .hunt-meta {{ display: flex; gap: 16px; font-size: 12px; color: #888; margin-top: 8px; }}
        .hunt-card .hunt-stats {{ display: flex; gap: 12px; margin-top: 10px; }}
        .hunt-card .stat-pill {{ background: #0a0a1a; border: 1px solid #1a1a2e; border-radius: 4px; padding: 4px 10px; font-size: 11px; }}
        .stat-pill .num {{ color: #00d4ff; font-weight: bold; }}
        .stat-pill.findings .num {{ color: #4ade80; }}
        .stat-pill.evidence .num {{ color: #a855f7; }}
        .summary-bar {{ display: flex; gap: 24px; margin-bottom: 20px; }}
        .summary-item {{ text-align: center; }}
        .summary-item .big {{ font-size: 28px; font-weight: bold; color: #00d4ff; }}
        .summary-item .lbl {{ font-size: 11px; color: #888; text-transform: uppercase; }}
        .filter-bar {{ display: flex; gap: 8px; margin-bottom: 16px; }}
        .filter-btn {{ background: #0a0a1a; color: #888; border: 1px solid #1a1a2e; padding: 6px 14px; border-radius: 4px; cursor: pointer; font-family: inherit; font-size: 12px; }}
        .filter-btn.active {{ color: #00d4ff; border-color: #00d4ff; background: #0a0a1a; }}
        .filter-btn:hover {{ border-color: #00d4ff; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>DEMOGOORGON</h1>
        <nav>
            <a href="/setup">Setup</a>
            <a href="/hunts" class="active">Hunts</a>
            <a href="/new-hunt">New Hunt</a>
            <a href="/hunt">Dashboard</a>
            <a href="/findings">Findings</a>
        </nav>
        <div class="status" id="ws-status">● CONNECTING</div>
    </div>
    <div class="container">
        <div class="summary-bar" id="summary-bar">
            <div class="summary-item"><div class="big" id="total-hunts">0</div><div class="lbl">Total Hunts</div></div>
            <div class="summary-item"><div class="big" id="active-hunts" style="color:#4ade80">0</div><div class="lbl">Active</div></div>
            <div class="summary-item"><div class="big" id="paused-hunts" style="color:#eab308">0</div><div class="lbl">Paused</div></div>
            <div class="summary-item"><div class="big" id="completed-hunts" style="color:#60a5fa">0</div><div class="lbl">Completed</div></div>
            <div class="summary-item"><div class="big" id="total-findings" style="color:#a855f7">0</div><div class="lbl">Total Findings</div></div>
        </div>
        <div class="filter-bar">
            <button class="filter-btn active" onclick="filterHunts('all', this)">All</button>
            <button class="filter-btn" onclick="filterHunts('running', this)">Running</button>
            <button class="filter-btn" onclick="filterHunts('paused', this)">Paused</button>
            <button class="filter-btn" onclick="filterHunts('completed', this)">Completed</button>
            <button class="filter-btn" onclick="filterHunts('stopped', this)">Stopped</button>
            <div style="flex:1"></div>
            <a href="/new-hunt" class="btn primary" style="font-size:12px;padding:6px 16px">+ New Hunt</a>
        </div>
        <div id="hunts-list">
            <div class="empty">Loading hunts...</div>
        </div>
    </div>
    <script>
        const ws = new WebSocket(`ws://${{location.host}}/ws/events`);
        ws.onopen = () => {{
            document.getElementById('ws-status').textContent = '● CONNECTED';
            document.getElementById('ws-status').style.color = '#4ade80';
        }};
        ws.onclose = () => {{
            document.getElementById('ws-status').textContent = '● OFFLINE';
            document.getElementById('ws-status').style.color = '#ef4444';
        }};
        ws.onmessage = () => {{ loadHunts(); }};

        let allHunts = [];

        async function loadHunts() {{
            try {{
                const r = await fetch('/api/engagements');
                const d = await r.json();
                allHunts = d.sessions || [];
                updateSummary();
                filterHunts(currentFilter);
            }} catch(e) {{
                document.getElementById('hunts-list').innerHTML = '<div class="empty">Failed to load hunts</div>';
            }}
        }}

        function updateSummary() {{
            document.getElementById('total-hunts').textContent = allHunts.length;
            document.getElementById('active-hunts').textContent = allHunts.filter(s => s.status === 'running').length;
            document.getElementById('paused-hunts').textContent = allHunts.filter(s => s.status === 'paused').length;
            document.getElementById('completed-hunts').textContent = allHunts.filter(s => s.status === 'completed' || s.status === 'stopped').length;
            document.getElementById('total-findings').textContent = allHunts.reduce((a, s) => a + (s.findings || 0), 0);
        }}

        let currentFilter = 'all';
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
                el.innerHTML = '<div class="empty">No hunts found. <a href="/new-hunt">Start one →</a></div>';
                return;
            }}
            el.innerHTML = hunts.map(s => {{
                const statusColors = {{running:'#4ade80',paused:'#eab308',completed:'#60a5fa',stopped:'#888',error:'#ef4444',initializing:'#888',ready:'#888'}};
                const color = statusColors[s.status] || '#888';
                const badge = s.active ? 'green' : 'blue';
                const target = s.target || 'Unknown';
                const displayTarget = target.replace(/^https?:\\/\\//, '').substring(0, 50);
                const strategy = s.strategy || '—';
                const findings = s.findings || 0;
                const evidence = s.evidence || 0;
                return `
                    <div class="hunt-card" onclick="window.location.href='/hunt/${{s.session_id || encodeURIComponent(target)}}'">
                        <div class="hunt-header">
                            <span class="hunt-target">${{displayTarget}}</span>
                            <span class="badge ${{badge}}" style="color:${{color}};border-color:${{color}}30;background:${{color}}15">${{s.status}}</span>
                        </div>
                        <div class="hunt-meta">
                            <span>Strategy: ${{strategy}}</span>
                            ${{s.session_id ? '<span>ID: ' + s.session_id + '</span>' : ''}}
                            ${{s.active ? '<span style="color:#4ade80">● LIVE</span>' : '<span style="color:#888">○ SAVED</span>'}}
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
    <title>DEMOGOORGON — Findings</title>
    <style>{_SHARED_CSS}
        .finding-card {{ background: #12121a; border: 1px solid #1a1a2e; border-radius: 8px; padding: 16px; margin-bottom: 12px; }}
        .finding-card h4 {{ margin-bottom: 8px; }}
        .finding-card .meta {{ font-size: 12px; color: #888; margin-bottom: 8px; }}
        .finding-card .desc {{ font-size: 13px; color: #ccc; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>DEMOGOORGON</h1>
        <nav>
            <a href="/setup">Setup</a>
            <a href="/hunts">Hunts</a>
            <a href="/new-hunt">New Hunt</a>
            <a href="/hunt">Dashboard</a>
            <a href="/findings" class="active">Findings</a>
        </nav>
    </div>
    <div class="container">
        <div class="panel">
            <h3>All Findings</h3>
            <div id="findings-list"><div class="empty">Loading...</div></div>
        </div>
    </div>
    <script>
        function escapeHtml(s) {{
            if (!s) return '';
            const d = document.createElement('div');
            d.appendChild(document.createTextNode(s));
            return d.innerHTML;
        }}

        async function loadFindings() {{
            const r = await fetch('/api/engagements');
            const d = await r.json();
            const el = document.getElementById('findings-list');
            let allFindings = [];
            for (const s of d.sessions) {{
                try {{
                    const fr = await fetch(`/api/engagements/${{encodeURIComponent(s.session_id)}}/findings`);
                    const fd = await fr.json();
                    if (fd.findings) {{
                        fd.findings.forEach(f => allFindings.push({{...f, target: s.target}}));
                    }}
                }} catch(e) {{ showToast('Request failed: ' + e.message); }}
            }}
            if (!allFindings.length) {{
                el.innerHTML = '<div class="empty">No findings across any session</div>';
                return;
            }}
            el.innerHTML = allFindings.map(f => {{
                const sev = f.severity || 'unknown';
                const sevColor = {{critical:'#ef4444',high:'#f97316',medium:'#eab308',low:'#60a5fa'}}[sev] || '#888';
                return `<div class="finding-card" style="border-left: 3px solid ${{sevColor}}">
                    <h4><span class="badge" style="background:${{sevColor}}20;color:${{sevColor}};border:1px solid ${{sevColor}}">${{sev.toUpperCase()}}</span> ${{escapeHtml(f.title || 'Untitled')}}</h4>
                    <div class="meta">Target: ${{escapeHtml(f.target)}} ${{f.endpoint ? '| Endpoint: ' + escapeHtml(f.endpoint) : ''}}</div>
                    <div class="desc">${{escapeHtml(f.description || '')}}</div>
                </div>`;
            }}).join('');
        }}
        loadFindings();
    </script>
</body>
</html>"""
