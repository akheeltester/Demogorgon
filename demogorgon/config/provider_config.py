"""Provider Configuration Manager — secure credential and provider management.

Stores provider profiles in ~/.demogorgon/config.json with:
- Restrictive file permissions (0600)
- API keys stored in separate keyring file with 0600 permissions
- Masked display of credentials everywhere
- Multiple provider support (primary + fallback)
- Model selection per provider

Usage:
    mgr = ProviderConfigManager()
    mgr.save_profile(ProviderProfile(provider="openrouter", api_key="sk-..."))
    profile = mgr.get_profile("openrouter")
    print(profile.masked_key)  # sk-********************abcd
"""

from __future__ import annotations

import json
import os
import stat
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


CONFIG_DIR = Path.home() / ".demogorgon"
CONFIG_FILE = CONFIG_DIR / "config.json"
KEYS_FILE = CONFIG_DIR / "keys.enc"


def _ensure_config_dir() -> None:
    """Create config directory with restrictive permissions."""
    CONFIG_DIR.mkdir(mode=0o700, exist_ok=True)


def _restrict_file(path: Path) -> None:
    """Set restrictive permissions on a file (owner read/write only)."""
    try:
        path.chmod(stat.S_IRUSR | stat.S_IWUSR)
    except (OSError, PermissionError):
        pass


def _mask_key(key: str) -> str:
    """Mask an API key for display. Never show more than first 4 and last 4 chars."""
    if not key:
        return ""
    if len(key) <= 8:
        return key[:2] + "*" * (len(key) - 2)
    return key[:4] + "*" * (len(key) - 8) + key[-4:]


def _simple_encrypt(data: str, key: str) -> bytes:
    """Simple XOR-based obfuscation for key storage (not cryptographic security,
    but prevents casual plaintext exposure on disk)."""
    key_bytes = key.encode() if isinstance(key, str) else key
    data_bytes = data.encode() if isinstance(data, str) else data
    encrypted = bytes(b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(data_bytes))
    return encrypted


def _simple_decrypt(data: bytes, key: str) -> str:
    """Reverse of _simple_encrypt."""
    key_bytes = key.encode() if isinstance(key, str) else key
    decrypted = bytes(b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(data))
    return decrypted.decode()


# Machine-specific key for obfuscation (derived from hostname + user)
_OBFUSCATION_KEY = f"demogorgon-{os.uname().nodename}-{os.getlogin()}"


@dataclass
class ProviderProfile:
    """A single provider configuration."""
    provider: str  # "openai", "anthropic", "gemini", "openrouter", "deepseek", "ollama"
    api_key: str = ""  # Raw API key (only in memory, never serialized to config.json)
    base_url: str = ""  # Custom base URL (for OpenRouter, Ollama, etc.)
    selected_model: str = ""  # Primary model
    fast_model: str = ""  # Fast/cheap model for simple tasks
    reasoning_model: str = ""  # Reasoning model for complex analysis
    report_model: str = ""  # Model for report generation
    enabled: bool = True
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)

    @property
    def masked_key(self) -> str:
        """Masked API key for display."""
        return _mask_key(self.api_key)

    @property
    def has_key(self) -> bool:
        """Whether an API key is configured."""
        return bool(self.api_key)

    def to_dict(self, include_key: bool = False) -> dict[str, Any]:
        """Serialize to dict. API key excluded by default."""
        d = {
            "provider": self.provider,
            "base_url": self.base_url,
            "selected_model": self.selected_model,
            "fast_model": self.fast_model,
            "reasoning_model": self.reasoning_model,
            "report_model": self.report_model,
            "enabled": self.enabled,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }
        if include_key:
            d["api_key"] = self.api_key
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ProviderProfile:
        """Deserialize from dict."""
        return cls(
            provider=data.get("provider", ""),
            api_key=data.get("api_key", ""),
            base_url=data.get("base_url", ""),
            selected_model=data.get("selected_model", ""),
            fast_model=data.get("fast_model", ""),
            reasoning_model=data.get("reasoning_model", ""),
            report_model=data.get("report_model", ""),
            enabled=data.get("enabled", True),
            created_at=data.get("created_at", 0),
            updated_at=data.get("updated_at", 0),
        )


class ProviderConfigManager:
    """Manages provider configurations with secure credential storage.

    Config structure:
        ~/.demogorgon/config.json  — profiles without API keys
        ~/.demogorgon/keys.enc     — obfuscated API keys

    Usage:
        mgr = ProviderConfigManager()

        # Save a provider
        profile = ProviderProfile(provider="openrouter", api_key="sk-...")
        mgr.save_profile(profile)

        # List providers
        providers = mgr.list_providers()

        # Get a profile (with key loaded)
        profile = mgr.get_profile("openrouter")

        # Test a provider
        result = mgr.test_provider("openrouter")
    """

    def __init__(self, config_dir: Path | None = None):
        self._config_dir = config_dir or CONFIG_DIR
        self._config_file = self._config_dir / "config.json"
        self._keys_file = self._config_dir / "keys.enc"
        _ensure_config_dir()

    def list_providers(self) -> list[ProviderProfile]:
        """List all configured providers (without API keys loaded)."""
        config = self._load_config()
        profiles = []
        for data in config.get("providers", []):
            profile = ProviderProfile.from_dict(data)
            # Check if key exists
            keys = self._load_keys()
            profile.api_key = "****" if profile.provider in keys else ""
            profiles.append(profile)
        return profiles

    def get_profile(self, provider: str) -> ProviderProfile | None:
        """Get a full profile with API key loaded."""
        config = self._load_config()
        for data in config.get("providers", []):
            if data.get("provider") == provider:
                profile = ProviderProfile.from_dict(data)
                # Load API key
                keys = self._load_keys()
                profile.api_key = keys.get(provider, "")
                return profile
        return None

    def get_active_profile(self) -> ProviderProfile | None:
        """Get the currently active (last used) provider profile."""
        config = self._load_config()
        active = config.get("active_provider", "")
        if active:
            return self.get_profile(active)
        # Fall back to first enabled provider
        for data in config.get("providers", []):
            if data.get("enabled", True):
                return self.get_profile(data.get("provider", ""))
        return None

    def save_profile(self, profile: ProviderProfile) -> None:
        """Save a provider profile. API key stored separately."""
        config = self._load_config()
        keys = self._load_keys()

        # Update or add profile
        providers = config.get("providers", [])
        updated = False
        for i, p in enumerate(providers):
            if p.get("provider") == profile.provider:
                profile.updated_at = time.time()
                providers[i] = profile.to_dict(include_key=False)
                updated = True
                break

        if not updated:
            providers.append(profile.to_dict(include_key=False))

        config["providers"] = providers

        # Store API key separately
        if profile.api_key:
            keys[profile.provider] = profile.api_key

        self._save_config(config)
        self._save_keys(keys)

    def delete_profile(self, provider: str) -> bool:
        """Delete a provider profile and its API key."""
        config = self._load_config()
        keys = self._load_keys()

        providers = config.get("providers", [])
        original_len = len(providers)
        providers = [p for p in providers if p.get("provider") != provider]

        if len(providers) == original_len:
            return False

        config["providers"] = providers
        keys.pop(provider, None)

        if config.get("active_provider") == provider:
            config["active_provider"] = ""

        self._save_config(config)
        self._save_keys(keys)
        return True

    def set_active_provider(self, provider: str) -> bool:
        """Set the active provider."""
        config = self._load_config()
        providers = [p.get("provider", "") for p in config.get("providers", [])]
        if provider not in providers:
            return False
        config["active_provider"] = provider
        self._save_config(config)
        return True

    def get_model_for_provider(self, provider: str) -> str:
        """Get the selected model for a provider."""
        profile = self.get_profile(provider)
        return profile.selected_model if profile else ""

    def set_model(self, provider: str, model: str) -> bool:
        """Set the selected model for a provider."""
        profile = self.get_profile(provider)
        if not profile:
            return False
        profile.selected_model = model
        self.save_profile(profile)
        return True

    def test_provider(self, provider: str, api_key: str = "",
                      base_url: str = "") -> dict[str, Any]:
        """Test a provider configuration. Returns status dict."""
        import asyncio

        async def _test():
            try:
                from ..llm.manager import LLMManager
                manager = LLMManager()
                manager.configure_from_params(
                    provider=provider,
                    api_key=api_key,
                    base_url=base_url or None,
                )
                # Health check
                healthy = await manager.health_check()
                if not healthy:
                    return {"success": False, "error": "Provider not reachable"}

                # Smoke test
                smoke = await manager.smoke_test()
                if not smoke:
                    return {"success": False, "error": "Structured output test failed"}

                return {
                    "success": True,
                    "provider": provider,
                    "model": manager._active_model,
                    "latency_ms": healthy,
                }
            except Exception as e:
                return {"success": False, "error": str(e)}

        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # We're inside an async context, create a task
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor() as pool:
                    result = pool.submit(asyncio.run, _test()).result()
                return result
            else:
                return loop.run_until_complete(_test())
        except RuntimeError:
            return asyncio.run(_test())

    def to_env_dict(self, provider: str | None = None) -> dict[str, str]:
        """Export provider config as environment variables (for LLMManager)."""
        providers = [provider] if provider else [
            p.provider for p in self.list_providers()
            if p.enabled and p.api_key not in ("", "****")
        ]

        env = {}
        for prov in providers:
            profile = self.get_profile(prov)
            if not profile or not profile.api_key:
                continue

            prefix = f"DEMOGORGON_{prov.upper()}"
            env[f"{prefix}_API_KEY"] = profile.api_key
            if profile.base_url:
                env[f"{prefix}_BASE_URL"] = profile.base_url
            if profile.selected_model:
                env[f"{prefix}_MODEL"] = profile.selected_model

        # Set active provider
        active = self.get_active_profile()
        if active:
            env["DEMOGORGON_PROVIDER"] = active.provider
            if active.selected_model:
                env["DEMOGORGON_MODEL"] = active.selected_model

        return env

    def load_into_environment(self, provider: str | None = None) -> None:
        """Load provider config into os.environ for LLMManager compatibility."""
        env = self.to_env_dict(provider)
        for key, value in env.items():
            os.environ[key] = value

    # ── Internal persistence ──────────────────────────────────────

    def _load_config(self) -> dict[str, Any]:
        """Load config from disk."""
        if not self._config_file.exists():
            return {"providers": [], "active_provider": ""}
        try:
            return json.loads(self._config_file.read_text())
        except (json.JSONDecodeError, OSError):
            return {"providers": [], "active_provider": ""}

    def _save_config(self, config: dict[str, Any]) -> None:
        """Save config to disk with restrictive permissions."""
        _ensure_config_dir()
        self._config_file.write_text(json.dumps(config, indent=2))
        _restrict_file(self._config_file)

    def _load_keys(self) -> dict[str, str]:
        """Load obfuscated API keys from disk."""
        if not self._keys_file.exists():
            return {}
        try:
            raw = self._keys_file.read_bytes()
            if not raw:
                return {}
            decrypted = _simple_decrypt(raw, _OBFUSCATION_KEY)
            return json.loads(decrypted)
        except (json.JSONDecodeError, OSError, Exception):
            return {}

    def _save_keys(self, keys: dict[str, str]) -> None:
        """Save API keys to disk with obfuscation."""
        _ensure_config_dir()
        encrypted = _simple_encrypt(json.dumps(keys), _OBFUSCATION_KEY)
        self._keys_file.write_bytes(encrypted)
        _restrict_file(self._keys_file)
