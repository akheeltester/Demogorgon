"""Tests for the guided hunt flow (target → scope → program document)."""

from __future__ import annotations

import sys

import pytest

from demogorgon.cli.hunt_flow import (
    _create_engagement,
    normalize_target,
    parse_extra_scope,
    read_program_file,
    show_policy,
)
from demogorgon.config.provider_config import _mask_key, redact_secrets
from demogorgon.core.scope.parser import parse_program_policy

# ── normalize_target ────────────────────────────────────────────────────

def test_normalize_adds_https():
    assert normalize_target("example.com") == "https://example.com"


def test_normalize_preserves_scheme_and_path():
    assert normalize_target("http://example.com/path") == "http://example.com/path"


def test_normalize_strips_quotes_and_spaces():
    assert normalize_target('  "example.com"  ') == "https://example.com"


def test_normalize_allows_localhost():
    assert normalize_target("localhost:3000") == "https://localhost:3000"


@pytest.mark.parametrize("raw", ["", "   ", "not a host!!", "https://", '"https://"'])
def test_normalize_rejects_garbage(raw):
    with pytest.raises(ValueError):
        normalize_target(raw)


# ── read_program_file ───────────────────────────────────────────────────

def test_read_program_file_text(tmp_path):
    doc = tmp_path / "policy.md"
    doc.write_text("In scope: *.example.com")
    assert read_program_file(str(doc)) == "In scope: *.example.com"


def test_read_program_file_strips_drag_drop_quotes(tmp_path):
    doc = tmp_path / "policy.txt"
    doc.write_text("scope text")
    assert read_program_file(f'"{doc}"') == "scope text"


def test_read_program_file_missing(tmp_path):
    with pytest.raises(FileNotFoundError):
        read_program_file(str(tmp_path / "nope.txt"))


def test_read_program_file_empty(tmp_path):
    doc = tmp_path / "empty.txt"
    doc.write_text("")
    with pytest.raises(ValueError, match="empty"):
        read_program_file(str(doc))


def test_read_program_file_binary_suffix(tmp_path):
    doc = tmp_path / "policy.png"
    doc.write_bytes(b"\x89PNG")
    with pytest.raises(ValueError, match="Unsupported"):
        read_program_file(str(doc))


def test_read_program_file_too_large(tmp_path, monkeypatch):
    monkeypatch.setattr("demogorgon.cli.hunt_flow.MAX_DOC_BYTES", 10)
    doc = tmp_path / "big.txt"
    doc.write_text("x" * 100)
    with pytest.raises(ValueError, match="too large"):
        read_program_file(str(doc))


def test_read_program_file_pdf_hint_when_pypdf_missing(tmp_path):
    try:
        import pypdf  # noqa: F401
        pytest.skip("pypdf installed — PDF path exercised elsewhere")
    except ImportError:
        pass
    doc = tmp_path / "policy.pdf"
    doc.write_bytes(b"%PDF-1.4 fake")
    with pytest.raises(ValueError, match="pypdf"):
        read_program_file(str(doc))


# ── parse_extra_scope ───────────────────────────────────────────────────

def test_parse_extra_scope_commas_and_blanks():
    assert parse_extra_scope("a.example.com,  b.example.com ,, \n c.example.com") == [
        "a.example.com", "b.example.com", "c.example.com",
    ]


def test_parse_extra_scope_empty():
    assert parse_extra_scope("") == []
    assert parse_extra_scope(" , ,, ") == []


# ── show_policy ─────────────────────────────────────────────────────────

def test_show_policy_renders():
    policy = parse_program_policy("In scope: *.example.com and api.example.com")
    show_policy(policy)  # must not raise


# ── _create_engagement ──────────────────────────────────────────────────

def test_create_engagement_from_policy_with_extras(tmp_path):
    from demogorgon.core.engagement import AuthorizationStatus, EngagementStatus

    text = "In scope: *.example.com"
    engagement = _create_engagement(
        text,
        target="https://shop.example.com",
        extras=["extra.example.org"],
        workspace_root=str(tmp_path),
    )
    assert engagement.target_url == "https://shop.example.com"
    patterns = [a.pattern for a in engagement.policy.in_scope]
    assert "extra.example.org" in patterns
    assert engagement.authorization_status == AuthorizationStatus.CONFIRMED
    assert engagement.status == EngagementStatus.ACTIVE
    assert (tmp_path / engagement.id / "engagement.json").exists()


def test_create_engagement_target_only_fallback_scope(tmp_path):
    engagement = _create_engagement(
        "",
        target="https://only.example.com",
        extras=[],
        workspace_root=str(tmp_path),
    )
    assert engagement.target_url == "https://only.example.com"
    patterns = [a.pattern for a in engagement.policy.in_scope]
    assert "https://only.example.com" in patterns


# ── redact_secrets (never print raw keys) ───────────────────────────────

def test_redact_openrouter_style_key():
    out = redact_secrets("auth failed for sk-or-v1-abcdef1234567890 ok")
    assert "abcdef1234567890" not in out
    assert "***" in out


def test_redact_bearer_token():
    out = redact_secrets("header was Bearer abcdefghijklmnop1234")
    assert "abcdefghijklmnop1234" not in out
    assert "Bearer ***" in out


def test_redact_query_param_key():
    out = redact_secrets("GET https://x/v1/models?key=AIzaSyExample123456&model=gpt")
    assert "AIzaSyExample123456" not in out
    assert "key=***" in out


def test_redact_plain_error_unchanged():
    assert redact_secrets("connection refused") == "connection refused"


def test_redact_none_and_non_string():
    assert redact_secrets(None) == ""
    assert redact_secrets(42) == "42"


def test_redact_does_not_mangle_masked_key():
    masked = _mask_key("sk-or-v1-abcdef1234567890")
    assert redact_secrets(masked) == masked


# ── routing: default entry → guided hunt ────────────────────────────────

async def test_default_argv_routes_to_guided_hunt(monkeypatch):
    import demogorgon.cli as cli

    calls: list = []

    async def fake_guided(target=None):
        calls.append(target)

    monkeypatch.setattr("demogorgon.cli.hunt_flow.guided_hunt", fake_guided)
    monkeypatch.setattr(sys, "argv", ["demogorgon"])
    await cli.main()
    assert calls == [None]


async def test_target_argv_prefills_guided_hunt(monkeypatch):
    import demogorgon.cli as cli

    calls: list = []

    async def fake_guided(target=None):
        calls.append(target)

    monkeypatch.setattr("demogorgon.cli.hunt_flow.guided_hunt", fake_guided)
    monkeypatch.setattr(sys, "argv", ["demogorgon", "https://example.com"])
    await cli.main()
    assert calls == ["https://example.com"]


async def test_menu_argv_opens_menu(monkeypatch):
    import demogorgon.cli as cli

    calls: list = []

    async def fake_menu():
        calls.append("menu")

    monkeypatch.setattr(cli, "cmd_interactive", fake_menu)
    monkeypatch.setattr(sys, "argv", ["demogorgon", "menu"])
    await cli.main()
    assert calls == ["menu"]


async def test_program_flag_routes_to_guided_hunt(monkeypatch):
    import demogorgon.cli as cli

    calls: list = []

    async def fake_guided(target=None):
        calls.append(target)

    monkeypatch.setattr("demogorgon.cli.hunt_flow.guided_hunt", fake_guided)
    monkeypatch.setattr(sys, "argv", ["demogorgon", "--program"])
    await cli.main()
    assert calls == [None]


async def test_cmd_program_delegates_to_guided_hunt(monkeypatch):
    import demogorgon.cli as cli

    calls: list = []

    async def fake_guided(target=None):
        calls.append("guided")

    monkeypatch.setattr("demogorgon.cli.hunt_flow.guided_hunt", fake_guided)
    await cli.cmd_program()
    assert calls == ["guided"]
