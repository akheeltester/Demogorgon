"""Pydantic models for the web API."""

from __future__ import annotations

from pydantic import BaseModel, Field
from typing import Any


class ProviderCreate(BaseModel):
    """Request to create/update a provider."""
    provider: str
    api_key: str = ""
    base_url: str = ""
    selected_model: str = ""
    fast_model: str = ""
    reasoning_model: str = ""
    report_model: str = ""


class ProviderTestRequest(BaseModel):
    """Request to test a provider."""
    provider: str
    api_key: str = ""
    base_url: str = ""


class EngagementCreate(BaseModel):
    """Request to create an engagement."""
    name: str = ""
    target: str
    program_text: str = ""
    max_cycles: int = 100
    max_cost_usd: float = 2.0
    max_requests: int = 5000
    approval_level: str = "none"


class InstructionRequest(BaseModel):
    """User instruction for the agent."""
    instruction: str


class SessionControl(BaseModel):
    """Session control action."""
    action: str  # start, pause, resume, stop
