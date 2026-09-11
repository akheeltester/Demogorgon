"""Asset Database — stores and manages discovered assets.

Every discovered asset is stored with metadata:
- Hostname, IP, ports, technologies
- HTTP status, title, CDN/WAF detection
- Cloud provider, authentication state
- Source, first_seen, last_seen
- Scope status, risk score
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from enum import Enum


class AssetType(Enum):
    """Types of assets."""
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    IP = "ip"
    PORT = "port"
    SERVICE = "service"
    URL = "url"
    API = "api"
    APPLICATION = "application"
    MOBILE_APP = "mobile_app"
    CLOUD_RESOURCE = "cloud_resource"


class ScopeStatus(Enum):
    """Scope status of an asset."""
    IN_SCOPE = "in_scope"
    OUT_OF_SCOPE = "out_of_scope"
    UNKNOWN = "unknown"


@dataclass
class Asset:
    """A discovered asset with full metadata."""
    id: str = ""
    asset_type: AssetType = AssetType.SUBDOMAIN
    hostname: str = ""
    ip: str = ""
    ports: list[int] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)
    framework: str = ""
    cdn: str = ""
    waf: str = ""
    cloud_provider: str = ""
    http_status: int = 0
    title: str = ""
    tls_info: dict[str, Any] = field(default_factory=dict)
    endpoints: list[dict[str, Any]] = field(default_factory=list)
    parameters: list[str] = field(default_factory=list)
    js_files: list[str] = field(default_factory=list)
    api_endpoints: list[dict[str, Any]] = field(default_factory=list)
    auth_required: bool = False
    source: str = ""
    first_seen: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    last_seen: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    scope_status: ScopeStatus = ScopeStatus.UNKNOWN
    risk_score: float = 0.0

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "asset_type": self.asset_type.value,
            "hostname": self.hostname,
            "ip": self.ip,
            "ports": self.ports,
            "technologies": self.technologies,
            "framework": self.framework,
            "cdn": self.cdn,
            "waf": self.waf,
            "cloud_provider": self.cloud_provider,
            "http_status": self.http_status,
            "title": self.title,
            "tls_info": self.tls_info,
            "endpoints_count": len(self.endpoints),
            "parameters": self.parameters,
            "js_files": self.js_files,
            "api_endpoints_count": len(self.api_endpoints),
            "auth_required": self.auth_required,
            "source": self.source,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "scope_status": self.scope_status.value,
            "risk_score": self.risk_score,
        }

    @classmethod
    def from_dict(cls, data: dict) -> Asset:
        return cls(
            id=data.get("id", ""),
            asset_type=AssetType(data.get("asset_type", "subdomain")),
            hostname=data.get("hostname", ""),
            ip=data.get("ip", ""),
            ports=data.get("ports", []),
            technologies=data.get("technologies", []),
            framework=data.get("framework", ""),
            cdn=data.get("cdn", ""),
            waf=data.get("waf", ""),
            cloud_provider=data.get("cloud_provider", ""),
            http_status=data.get("http_status", 0),
            title=data.get("title", ""),
            tls_info=data.get("tls_info", {}),
            endpoints=[],
            parameters=data.get("parameters", []),
            js_files=data.get("js_files", []),
            api_endpoints=[],
            auth_required=data.get("auth_required", False),
            source=data.get("source", ""),
            first_seen=data.get("first_seen", ""),
            last_seen=data.get("last_seen", ""),
            scope_status=ScopeStatus(data.get("scope_status", "unknown")),
            risk_score=data.get("risk_score", 0.0),
        )


class AssetDatabase:
    """Stores and manages discovered assets.

    Usage:
        db = AssetDatabase(workspace_dir="./engagements/abc123")

        # Add assets
        asset = db.add_asset(hostname="api.example.com", asset_type=AssetType.SUBDOMAIN)
        db.update_asset(asset.id, http_status=200, technologies=["FastAPI"])

        # Query assets
        assets = db.get_assets_by_type(AssetType.SUBDOMAIN)
        asset = db.get_asset_by_hostname("api.example.com")

        # Save/load
        db.save()
        db.load()
    """

    def __init__(self, workspace_dir: str = ""):
        self._workspace_dir = Path(workspace_dir) if workspace_dir else Path(".")
        self._assets: dict[str, Asset] = {}
        self._hostname_index: dict[str, str] = {}  # hostname -> asset_id
        self._ip_index: dict[str, str] = {}  # ip -> asset_id

    def add_asset(
        self,
        hostname: str = "",
        ip: str = "",
        asset_type: AssetType = AssetType.SUBDOMAIN,
        source: str = "",
        **kwargs,
    ) -> Asset:
        """Add a new asset to the database."""
        # Check if already exists
        if hostname and hostname in self._hostname_index:
            asset_id = self._hostname_index[hostname]
            asset = self._assets[asset_id]
            asset.last_seen = datetime.now(timezone.utc).isoformat()
            return asset

        # Create new asset
        asset_id = f"{hostname or ip}_{int(time.time())}"
        asset = Asset(
            id=asset_id,
            asset_type=asset_type,
            hostname=hostname,
            ip=ip,
            source=source,
            **kwargs,
        )

        self._assets[asset_id] = asset
        if hostname:
            self._hostname_index[hostname] = asset_id
        if ip:
            self._ip_index[ip] = asset_id

        return asset

    def update_asset(self, asset_id: str, **kwargs) -> Asset | None:
        """Update an asset's metadata."""
        asset = self._assets.get(asset_id)
        if not asset:
            return None

        for key, value in kwargs.items():
            if hasattr(asset, key):
                setattr(asset, key, value)

        asset.last_seen = datetime.now(timezone.utc).isoformat()
        return asset

    def get_asset(self, asset_id: str) -> Asset | None:
        """Get an asset by ID."""
        return self._assets.get(asset_id)

    def get_asset_by_hostname(self, hostname: str) -> Asset | None:
        """Get an asset by hostname."""
        asset_id = self._hostname_index.get(hostname)
        return self._assets.get(asset_id) if asset_id else None

    def get_asset_by_ip(self, ip: str) -> Asset | None:
        """Get an asset by IP."""
        asset_id = self._ip_index.get(ip)
        return self._assets.get(asset_id) if asset_id else None

    def get_assets_by_type(self, asset_type: AssetType) -> list[Asset]:
        """Get all assets of a specific type."""
        return [a for a in self._assets.values() if a.asset_type == asset_type]

    def get_assets_by_scope(self, scope_status: ScopeStatus) -> list[Asset]:
        """Get all assets with a specific scope status."""
        return [a for a in self._assets.values() if a.scope_status == scope_status]

    def get_all_assets(self) -> list[Asset]:
        """Get all assets."""
        return list(self._assets.values())

    def get_stats(self) -> dict[str, Any]:
        """Get database statistics."""
        assets = list(self._assets.values())
        return {
            "total": len(assets),
            "by_type": {
                t.value: len([a for a in assets if a.asset_type == t])
                for t in AssetType
            },
            "by_scope": {
                s.value: len([a for a in assets if a.scope_status == s])
                for s in ScopeStatus
            },
            "with_technologies": len([a for a in assets if a.technologies]),
            "with_ports": len([a for a in assets if a.ports]),
            "with_endpoints": len([a for a in assets if a.endpoints]),
        }

    def save(self, filename: str = "assets.json") -> None:
        """Save the database to a JSON file."""
        filepath = self._workspace_dir / "recon" / filename
        filepath.parent.mkdir(parents=True, exist_ok=True)

        data = {
            "assets": [a.to_dict() for a in self._assets.values()],
            "saved_at": datetime.now(timezone.utc).isoformat(),
        }

        with open(filepath, "w") as f:
            json.dump(data, f, indent=2)

    def load(self, filename: str = "assets.json") -> bool:
        """Load the database from a JSON file."""
        filepath = self._workspace_dir / "recon" / filename

        if not filepath.exists():
            return False

        try:
            with open(filepath) as f:
                data = json.load(f)

            for asset_data in data.get("assets", []):
                asset = Asset.from_dict(asset_data)
                self._assets[asset.id] = asset
                if asset.hostname:
                    self._hostname_index[asset.hostname] = asset.id
                if asset.ip:
                    self._ip_index[asset.ip] = asset.id

            return True
        except Exception:
            return False

    def to_summary(self) -> str:
        """Generate a human-readable summary."""
        stats = self.get_stats()
        lines = [
            "Asset Database Summary",
            "=" * 40,
            f"Total assets: {stats['total']}",
            "",
            "By type:",
        ]
        for asset_type, count in stats["by_type"].items():
            if count > 0:
                lines.append(f"  {asset_type}: {count}")

        lines.extend([
            "",
            "By scope:",
        ])
        for scope, count in stats["by_scope"].items():
            if count > 0:
                lines.append(f"  {scope}: {count}")

        return "\n".join(lines)
