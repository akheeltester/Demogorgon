"""Unit tests for beginner onboarding: wizard config plumbing, .env mirror,
env-detection fallback, and setup entry points."""

from __future__ import annotations

import pytest

from demogorgon.config.provider_config import ProviderConfigManager, ProviderProfile
from demogorgon.config.terminal_setup import _MANAGED_ENV_KEYS, _write_dotenv
from demogorgon.llm.manager import (
    LLMManager,
    _load_env,
    _merge_saved_provider_env,
    _provider_configured,
)

# ============================================================
# Provider detection / env loading
# ============================================================

def test_provider_configured_variants():
    assert _provider_configured({"DEMOGORGON_LLM_PROVIDER": "openai"})
    assert _provider_configured({"LLM_PROVIDER": "anthropic"})
    assert _provider_configured({"DEMOGORGON_API_KEY": "sk-x"})
    assert _provider_configured({"LLM_API_KEY": "sk-x"})
    assert _provider_configured({"OPENROUTER_API_KEY": "sk-or-x"})
    assert _provider_configured({"GEMINI_API_KEY": "x"})
    assert not _provider_configured({})
    assert not _provider_configured({"SOME_UNRELATED": "x"})


def test_merge_saved_env_fills_gaps(monkeypatch):
    class FakeMgr:
        def to_env_dict(self):
            return {
                "DEMOGORGON_LLM_PROVIDER": "openrouter",
                "DEMOGORGON_API_KEY": "sk-or-from-wizard",
                "DEMOGORGON_MODEL": "m/model:free",
            }

    import demogorgon.config.provider_config as pc
    monkeypatch.setattr(pc, "ProviderConfigManager", FakeMgr)

    config: dict[str, str] = {}
    _merge_saved_provider_env(config)
    assert config["DEMOGORGON_LLM_PROVIDER"] == "openrouter"
    assert config["DEMOGORGON_API_KEY"] == "sk-or-from-wizard"
    assert config["DEMOGORGON_MODEL"] == "m/model:free"


def test_merge_saved_env_never_overwrites(monkeypatch):
    class FakeMgr:
        def to_env_dict(self):
            return {
                "DEMOGORGON_LLM_PROVIDER": "openrouter",
                "DEMOGORGON_API_KEY": "wizard-key",
            }

    import demogorgon.config.provider_config as pc
    monkeypatch.setattr(pc, "ProviderConfigManager", FakeMgr)

    config = {"DEMOGORGON_LLM_PROVIDER": "openai", "DEMOGORGON_API_KEY": "file-key"}
    _merge_saved_provider_env(config)
    assert config["DEMOGORGON_LLM_PROVIDER"] == "openai"
    assert config["DEMOGORGON_API_KEY"] == "file-key"


def test_merge_saved_env_skips_when_env_configured(monkeypatch):
    calls = {"n": 0}

    class FakeMgr:
        def to_env_dict(self):
            calls["n"] += 1
            return {"DEMOGORGON_API_KEY": "wizard-key"}

    import demogorgon.config.provider_config as pc
    monkeypatch.setattr(pc, "ProviderConfigManager", FakeMgr)

    config = {"OPENAI_API_KEY": "shell-key"}
    _merge_saved_provider_env(config)
    assert calls["n"] == 0
    assert "DEMOGORGON_API_KEY" not in config


def test_merge_saved_env_swallows_storage_errors(monkeypatch):
    import demogorgon.config.provider_config as pc

    class ExplodingMgr:
        def to_env_dict(self):
            raise RuntimeError("no home dir")

    monkeypatch.setattr(pc, "ProviderConfigManager", ExplodingMgr)
    config: dict[str, str] = {}
    assert _merge_saved_provider_env(config) == {}


def test_load_env_returns_dict_and_does_not_crash():
    config = _load_env()
    assert isinstance(config, dict)


# ============================================================
# Ollama (local provider, no API key)
# ============================================================

def test_ollama_configures_without_api_key():
    mgr = LLMManager()
    mgr._env = {}
    mgr.configure_from_params(provider="ollama", api_key="", model="llama3.1:8b")
    assert mgr.available
    assert mgr._active_provider == "ollama"
    assert mgr._active_model == "llama3.1:8b"


def test_non_ollama_still_requires_api_key():
    mgr = LLMManager()
    mgr._env = {}
    mgr.configure_from_params(provider="openai", api_key="", model="gpt-4o-mini")
    assert not mgr.available


# ============================================================
# Wizard config storage
# ============================================================

def test_to_env_dict_includes_active_api_key(tmp_path):
    mgr = ProviderConfigManager(config_dir=tmp_path)
    mgr.save_profile(ProviderProfile(
        provider="openrouter",
        api_key="sk-or-test-123456",
        selected_model="m/test:free",
        base_url="https://openrouter.ai/api/v1",
    ))
    mgr.set_active_provider("openrouter")

    env = mgr.to_env_dict()
    assert env["DEMOGORGON_LLM_PROVIDER"] == "openrouter"
    assert env["DEMOGORGON_API_KEY"] == "sk-or-test-123456"
    assert env["DEMOGORGON_MODEL"] == "m/test:free"
    assert env["DEMOGORGON_BASE_URL"] == "https://openrouter.ai/api/v1"


# ============================================================
# .env mirroring
# ============================================================

def test_write_dotenv_creates_file(tmp_path):
    profile = ProviderProfile(
        provider="openrouter",
        api_key="sk-or-abc123",
        selected_model="m/model:free",
        base_url="https://openrouter.ai/api/v1",
    )
    env_path = tmp_path / ".env"

    assert _write_dotenv(profile, env_path) is True
    content = env_path.read_text()
    assert "DEMOGORGON_LLM_PROVIDER=openrouter" in content
    assert "DEMOGORGON_API_KEY=sk-or-abc123" in content
    assert "DEMOGORGON_MODEL=m/model:free" in content
    assert "DEMOGORGON_BASE_URL=https://openrouter.ai/api/v1" in content


def test_write_dotenv_preserves_unrelated_lines(tmp_path):
    env_path = tmp_path / ".env"
    env_path.write_text(
        "# my notes\n"
        "# DEMOGORGON_LLM_PROVIDER=openai\n"
        "DEMOGORGON_LLM_MAX_RETRIES=5\n"
        "OTHER_SETTING=keep-me\n"
        "DEMOGORGON_API_KEY=old-key\n"
        "DEMOGORGON_MODEL=old-model\n"
    )

    profile = ProviderProfile(
        provider="deepseek", api_key="new-key", selected_model="deepseek-chat"
    )
    assert _write_dotenv(profile, env_path) is True

    content = env_path.read_text()
    assert "OTHER_SETTING=keep-me" in content
    assert "DEMOGORGON_LLM_MAX_RETRIES=5" in content
    assert "# my notes" in content
    assert "DEMOGORGON_LLM_PROVIDER=deepseek" in content
    assert "DEMOGORGON_API_KEY=new-key" in content
    assert "old-key" not in content
    assert "old-model" not in content


def test_write_dotenv_respects_decline_on_existing_config(tmp_path, monkeypatch):
    from demogorgon.config import terminal_setup as ts

    env_path = tmp_path / ".env"
    env_path.write_text("DEMOGORGON_LLM_PROVIDER=openai\nDEMOGORGON_API_KEY=sk-live\n")
    monkeypatch.setattr(ts.Confirm, "ask", lambda *a, **k: False)

    profile = ProviderProfile(provider="openrouter", api_key="sk-or-new")
    assert _write_dotenv(profile, env_path) is False
    assert "sk-live" in env_path.read_text()


def test_write_dotenv_asks_only_for_live_config(tmp_path, monkeypatch):
    from demogorgon.config import terminal_setup as ts

    asked = {"n": 0}

    def fake_ask(*a, **k):
        asked["n"] += 1
        return True

    monkeypatch.setattr(ts.Confirm, "ask", fake_ask)

    # Template-style .env (only comments) → written without prompting
    env_path = tmp_path / ".env"
    env_path.write_text("# DEMOGORGON_LLM_PROVIDER=openai\n")
    profile = ProviderProfile(provider="openrouter", api_key="sk-or-x")
    assert _write_dotenv(profile, env_path) is True
    assert asked["n"] == 0
    assert "DEMOGORGON_LLM_PROVIDER=openrouter" in env_path.read_text()

    # Live config → prompts once
    assert _write_dotenv(profile, env_path) is True
    assert asked["n"] == 1


def test_managed_env_keys_cover_profile_fields():
    for key in (
        "DEMOGORGON_LLM_PROVIDER",
        "DEMOGORGON_API_KEY",
        "DEMOGORGON_MODEL",
        "DEMOGORGON_BASE_URL",
    ):
        assert key in _MANAGED_ENV_KEYS


# ============================================================
# Entry points: cli.setup delegates to the canonical wizard
# ============================================================

def test_cli_setup_delegates_to_terminal_wizard(monkeypatch):
    import demogorgon.cli.setup as cli_setup

    called = {}

    async def fake_wizard():
        called["ran"] = True
        return "profile"

    monkeypatch.setattr(cli_setup, "_run_wizard", fake_wizard)

    import asyncio
    result = asyncio.run(cli_setup.run_setup_wizard())
    assert called.get("ran") is True
    assert result == "profile"


# ============================================================
# Model discovery URL building
# ============================================================

@pytest.mark.asyncio
async def test_discover_ollama_strips_v1_suffix(monkeypatch):
    from demogorgon.config import model_discovery as md

    captured: dict[str, str] = {}

    class FakeResp:
        def raise_for_status(self):
            pass

        def json(self):
            return {"models": [{"name": "llama3.1:8b", "size": 1}]}

    class FakeClient:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def get(self, url, **k):
            captured["url"] = url
            return FakeResp()

    monkeypatch.setattr(md.httpx, "AsyncClient", FakeClient)
    models = await md._discover_ollama("http://localhost:11434/v1")
    assert captured["url"] == "http://localhost:11434/api/tags"
    assert models[0]["id"] == "llama3.1:8b"


@pytest.mark.asyncio
async def test_discover_openai_strips_v1_suffix(monkeypatch):
    from demogorgon.config import model_discovery as md

    captured: dict[str, str] = {}

    class FakeResp:
        def raise_for_status(self):
            pass

        def json(self):
            return {"data": [{"id": "gpt-4o-mini"}]}

    class FakeClient:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def get(self, url, **k):
            captured["url"] = url
            return FakeResp()

    monkeypatch.setattr(md.httpx, "AsyncClient", FakeClient)
    models = await md._discover_openai("sk-test", "https://api.openai.com/v1")
    assert captured["url"] == "https://api.openai.com/v1/models"
    assert models[0]["id"] == "gpt-4o-mini"

# ============================================================
# No shipped keys + post-setup guidance
# ============================================================

def test_env_example_contains_no_real_api_key():
    """Placeholders only — every user must supply their own API key."""
    import re
    from pathlib import Path

    repo_root = Path(__file__).resolve().parents[3]
    text = (repo_root / ".env.example").read_text()
    assert not re.search(r"sk-(?:or-v1-|ant-)?[A-Za-z0-9]{16,}", text), (
        ".env.example must never contain a real API key"
    )


def test_next_steps_points_to_in_tool_guided_hunt():
    """After setup, guidance must ask the target inside the tool (guided hunt),
    never via a pre-filled CLI argument."""
    from demogorgon.config.terminal_setup import _next_steps_panel

    text = str(_next_steps_panel().renderable)
    assert "python -m demogorgon" in text
    assert "target.example" not in text
