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

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from .models import (
    ProviderCreate, ProviderTestRequest, EngagementCreate,
    InstructionRequest, SessionControl,
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
        "session_id": session.target,  # Using target as ID for now
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


@app.post("/api/engagements/resume")
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
    """Serve the main dashboard page."""
    return _get_dashboard_html()


# ── Internal State ──────────────────────────────────────────────

_current_session = None
_sessions: dict[str, Any] = {}


def set_terminal_session(session) -> None:
    """Set the terminal's AgentSession so web UI shares it.

    Called by AgentMain after session creation.
    """
    global _current_session
    _current_session = session
    _sessions[session.target] = session

    # Wire EventBus to WebSocket bridge
    try:
        bridge = get_web_bridge()
        session.events.on_all(bridge.handle_event)
    except Exception as e:
        logger.warning(f"Could not wire EventBus to WebSocket bridge: {e}")


def _set_current_session(session):
    global _current_session
    _current_session = session
    _sessions[session.target] = session


def _get_all_sessions() -> list:
    # Include terminal session if set
    sessions = list(_sessions.values())
    if _current_session and _current_session not in sessions:
        sessions.insert(0, _current_session)
    return sessions


def _get_session_by_id(session_id: str):
    if _current_session and (_current_session.target == session_id or _current_session.session_id == session_id):
        return _current_session
    return _sessions.get(session_id)


async def _run_session(session):
    """Run a session in the background."""
    try:
        await session.initialize()
        await session.run()
    except Exception as e:
        logger.error(f"Session failed: {e}")


def _get_dashboard_html() -> str:
    """Return the dashboard HTML."""
    return DASHBOARD_HTML


# ── Inline Dashboard HTML ───────────────────────────────────────

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DEMOGOORGON Control Center</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'SF Mono', 'Fira Code', monospace; background: #0a0a0f; color: #e0e0e0; }
        .header { background: #12121a; border-bottom: 1px solid #1a1a2e; padding: 16px 24px; display: flex; align-items: center; justify-content: space-between; }
        .header h1 { font-size: 18px; color: #00d4ff; }
        .header .status { color: #4ade80; font-size: 13px; }
        .container { display: grid; grid-template-columns: 300px 1fr; height: calc(100vh - 60px); }
        .sidebar { background: #0f0f18; border-right: 1px solid #1a1a2e; padding: 16px; overflow-y: auto; }
        .main { padding: 16px; overflow-y: auto; }
        .panel { background: #12121a; border: 1px solid #1a1a2e; border-radius: 8px; padding: 16px; margin-bottom: 16px; }
        .panel h3 { color: #00d4ff; font-size: 14px; margin-bottom: 12px; text-transform: uppercase; letter-spacing: 1px; }
        .stat { display: flex; justify-content: space-between; padding: 6px 0; border-bottom: 1px solid #1a1a2e; font-size: 13px; }
        .stat:last-child { border-bottom: none; }
        .stat .label { color: #888; }
        .stat .value { color: #e0e0e0; font-weight: bold; }
        .event-stream { max-height: 400px; overflow-y: auto; }
        .event { padding: 8px 12px; border-left: 3px solid #1a1a2e; margin-bottom: 4px; font-size: 12px; }
        .event.finding { border-color: #4ade80; background: #0a1a0a; }
        .event.action { border-color: #00d4ff; background: #0a0a1a; }
        .event.error { border-color: #ef4444; background: #1a0a0a; }
        .event .time { color: #666; }
        .event .type { color: #00d4ff; font-weight: bold; }
        .btn { background: #1a1a2e; color: #e0e0e0; border: 1px solid #2a2a3e; padding: 8px 16px; border-radius: 4px; cursor: pointer; font-family: inherit; font-size: 13px; }
        .btn:hover { background: #2a2a3e; }
        .btn.primary { background: #00d4ff; color: #0a0a0f; border-color: #00d4ff; }
        .btn.danger { background: #ef4444; color: white; border-color: #ef4444; }
        .input { background: #0a0a0f; color: #e0e0e0; border: 1px solid #1a1a2e; padding: 8px 12px; border-radius: 4px; font-family: inherit; font-size: 13px; width: 100%; }
        .input:focus { outline: none; border-color: #00d4ff; }
        .hidden { display: none; }
        #provider-status { color: #4ade80; }
        #model-status { color: #00d4ff; }
        .empty { color: #555; font-style: italic; font-size: 13px; padding: 20px; text-align: center; }
    </style>
</head>
<body>
    <div class="header">
        <h1>DEMOGOORGON</h1>
        <div class="status" id="status">● CONNECTING</div>
    </div>
    <div class="container">
        <div class="sidebar">
            <div class="panel">
                <h3>Session</h3>
                <div class="stat"><span class="label">Target</span><span class="value" id="target">—</span></div>
                <div class="stat"><span class="label">Provider</span><span class="value" id="provider-status">—</span></div>
                <div class="stat"><span class="label">Model</span><span class="value" id="model-status">—</span></div>
                <div class="stat"><span class="label">Status</span><span class="value" id="session-status">—</span></div>
            </div>
            <div class="panel">
                <h3>Budget</h3>
                <div class="stat"><span class="label">Cycle</span><span class="value" id="cycle">0</span></div>
                <div class="stat"><span class="label">Findings</span><span class="value" id="findings">0</span></div>
                <div class="stat"><span class="label">Evidence</span><span class="value" id="evidence">0</span></div>
            </div>
            <div class="panel">
                <h3>Controls</h3>
                <button class="btn primary" onclick="createEngagement()" style="width:100%;margin-bottom:8px">New Engagement</button>
                <button class="btn" onclick="pauseSession()" style="width:100%;margin-bottom:8px">Pause</button>
                <button class="btn" onclick="resumeSession()" style="width:100%;margin-bottom:8px">Resume</button>
                <button class="btn danger" onclick="stopSession()" style="width:100%">Stop</button>
            </div>
        </div>
        <div class="main">
            <div class="panel">
                <h3>Live Event Stream</h3>
                <div class="event-stream" id="events">
                    <div class="empty">Waiting for events...</div>
                </div>
            </div>
            <div class="panel">
                <h3>Findings</h3>
                <div id="findings-list">
                    <div class="empty">No findings yet</div>
                </div>
            </div>
        </div>
    </div>

    <script>
        const ws = new WebSocket(`ws://${location.host}/ws/events`);
        const eventsDiv = document.getElementById('events');
        let eventCount = 0;

        ws.onopen = () => {
            document.getElementById('status').textContent = '● CONNECTED';
            document.getElementById('status').style.color = '#4ade80';
        };

        ws.onclose = () => {
            document.getElementById('status').textContent = '● DISCONNECTED';
            document.getElementById('status').style.color = '#ef4444';
            setTimeout(() => location.reload(), 3000);
        };

        ws.onmessage = (e) => {
            const event = JSON.parse(e.data);
            addEvent(event);
        };

        function addEvent(event) {
            if (eventCount === 0) eventsDiv.innerHTML = '';
            eventCount++;

            const div = document.createElement('div');
            div.className = 'event';

            const time = new Date(event.timestamp * 1000).toLocaleTimeString();
            const type = event.type || 'unknown';
            const data = JSON.stringify(event.data || {});

            if (type.includes('finding')) div.className += ' finding';
            else if (type.includes('action') || type.includes('tool')) div.className += ' action';
            else if (type.includes('error')) div.className += ' error';

            div.innerHTML = `<span class="time">${time}</span> <span class="type">${type}</span> ${data.substring(0, 120)}`;
            eventsDiv.appendChild(div);
            eventsDiv.scrollTop = eventsDiv.scrollHeight;
        }

        async function createEngagement() {
            const target = prompt('Target URL:');
            if (!target) return;
            const res = await fetch('/api/engagements', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({target})
            });
            const data = await res.json();
            document.getElementById('target').textContent = target;
            document.getElementById('provider-status').textContent = data.provider || '—';
            document.getElementById('model-status').textContent = data.model || '—';
        }

        async function pauseSession() {
            const target = document.getElementById('target').textContent;
            if (target === '—') return;
            await fetch(`/api/engagements/${target}/pause`, {method: 'POST'});
        }

        async function resumeSession() {
            const target = document.getElementById('target').textContent;
            if (target === '—') return;
            await fetch(`/api/engagements/${target}/resume`, {method: 'POST'});
        }

        async function stopSession() {
            const target = document.getElementById('target').textContent;
            if (target === '—') return;
            if (!confirm('Stop this session?')) return;
            await fetch(`/api/engagements/${target}/stop`, {method: 'POST'});
        }

        // Load initial status
        fetch('/api/status').then(r => r.json()).then(data => {
            if (data.provider) document.getElementById('provider-status').textContent = data.provider;
            if (data.model) document.getElementById('model-status').textContent = data.model;
        });
    </script>
</body>
</html>"""
