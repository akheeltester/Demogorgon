"""Tests for Phase 3 components: ReconEngine and Asset Intelligence."""

from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock

from demogorgon.recon.engine import ReconEngine, ReconStage, ReconResult
from demogorgon.core.asset_intel.database import AssetDatabase, Asset, AssetType, ScopeStatus
from demogorgon.core.asset_intel.classifier import AssetClassifier
from demogorgon.core.asset_intel.relationships import RelationshipGraph, Relationship, RelationType


# ── ReconStage tests ────────────────────────────────────────────

class TestReconStage:
    def test_defaults(self):
        stage = ReconStage(name="test", description="Test stage")
        assert stage.name == "test"
        assert stage.description == "Test stage"
        assert stage.depends_on == []
        assert stage.tool_hint == ""
        assert stage.priority == 0
        assert stage.completed is False
        assert stage.result == {}
        assert stage.duration == 0.0
        assert stage.error == ""

    def test_to_dict(self):
        stage = ReconStage(
            name="subdomain_enum",
            description="Discover subdomains",
            depends_on=[],
            tool_hint="subfinder",
            priority=10,
            completed=True,
            result={"subdomains": ["a.example.com"], "total": 1},
            duration=2.5,
        )
        d = stage.to_dict()
        assert d["name"] == "subdomain_enum"
        assert d["completed"] is True
        assert d["duration"] == 2.5
        assert "result_summary" in d
        assert d["result_summary"]["total"] == 1


# ── ReconResult tests ──────────────────────────────────────────

class TestReconResult:
    def test_defaults(self):
        result = ReconResult(domain="example.com")
        assert result.domain == "example.com"
        assert result.stages_completed == 0
        assert result.stages_total == 0
        assert result.subdomains == []
        assert result.live_hosts == []
        assert result.endpoints == []
        assert result.ports == []
        assert result.technologies == []
        assert result.duration == 0.0

    def test_to_dict(self):
        result = ReconResult(
            domain="example.com",
            stages_completed=5,
            stages_total=8,
            subdomains=["api.example.com", "www.example.com"],
            live_hosts=[{"url": "https://api.example.com"}],
            endpoints=[{"url": "https://api.example.com/users"}],
            ports=[{"port": 443, "service": "https"}],
            technologies=["nginx", "python"],
            duration=45.2,
        )
        d = result.to_dict()
        assert d["domain"] == "example.com"
        assert d["stages_completed"] == 5
        assert d["subdomains_count"] == 2
        assert d["live_hosts_count"] == 1
        assert d["endpoints_count"] == 1
        assert d["ports_count"] == 1
        assert d["technologies"] == ["nginx", "python"]
        assert d["duration"] == 45.2


# ── ReconEngine tests ──────────────────────────────────────────

class TestReconEngine:
    def test_build_stages(self):
        mock_registry = MagicMock()
        mock_executor = MagicMock()
        engine = ReconEngine(mock_registry, mock_executor)
        assert len(engine._stages) == 8
        stage_names = [s.name for s in engine._stages]
        assert "subdomain_enum" in stage_names
        assert "http_probe" in stage_names
        assert "port_scan" in stage_names
        assert "web_crawl" in stage_names

    def test_stage_dependencies(self):
        mock_registry = MagicMock()
        mock_executor = MagicMock()
        engine = ReconEngine(mock_registry, mock_executor)
        for stage in engine._stages:
            if stage.name == "dns_resolution":
                assert "subdomain_enum" in stage.depends_on
            elif stage.name == "http_probe":
                assert "subdomain_enum" in stage.depends_on
            elif stage.name == "port_scan":
                assert "dns_resolution" in stage.depends_on

    def test_get_stage_status(self):
        mock_registry = MagicMock()
        mock_executor = MagicMock()
        engine = ReconEngine(mock_registry, mock_executor)
        status = engine.get_stage_status()
        assert len(status) == 8
        assert all("name" in s for s in status)
        assert all("completed" in s for s in status)

    def test_get_results_empty(self):
        mock_registry = MagicMock()
        mock_executor = MagicMock()
        engine = ReconEngine(mock_registry, mock_executor)
        results = engine.get_results()
        assert results["subdomains"] == []
        assert results["live_hosts"] == []
        assert results["endpoints"] == []
        assert results["ports"] == []


# ── AssetDatabase tests ────────────────────────────────────────

class TestAssetDatabase:
    def test_add_asset(self):
        db = AssetDatabase()
        asset = db.add_asset(
            hostname="api.example.com",
            asset_type=AssetType.SUBDOMAIN,
            scope_status=ScopeStatus.IN_SCOPE,
        )
        assert len(db.get_all_assets()) == 1
        assert asset.hostname == "api.example.com"

    def test_get_asset_by_hostname(self):
        db = AssetDatabase()
        asset = db.add_asset(
            hostname="api.example.com",
            asset_type=AssetType.SUBDOMAIN,
            scope_status=ScopeStatus.IN_SCOPE,
        )
        retrieved = db.get_asset_by_hostname("api.example.com")
        assert retrieved is not None
        assert retrieved.hostname == "api.example.com"
        assert retrieved.asset_type == AssetType.SUBDOMAIN

    def test_get_assets_by_type(self):
        db = AssetDatabase()
        db.add_asset(hostname="a.example.com", asset_type=AssetType.SUBDOMAIN, scope_status=ScopeStatus.IN_SCOPE)
        db.add_asset(hostname="b.example.com", asset_type=AssetType.SUBDOMAIN, scope_status=ScopeStatus.IN_SCOPE)
        db.add_asset(ip="1.2.3.4", asset_type=AssetType.IP, scope_status=ScopeStatus.IN_SCOPE)
        subdomains = db.get_assets_by_type(AssetType.SUBDOMAIN)
        assert len(subdomains) == 2

    def test_update_asset(self):
        db = AssetDatabase()
        asset = db.add_asset(
            hostname="api.example.com",
            asset_type=AssetType.SUBDOMAIN,
            scope_status=ScopeStatus.UNKNOWN,
        )
        db.update_asset(asset.id, scope_status=ScopeStatus.IN_SCOPE)
        retrieved = db.get_asset(asset.id)
        assert retrieved.scope_status == ScopeStatus.IN_SCOPE

    def test_get_asset_count(self):
        db = AssetDatabase()
        assert len(db.get_all_assets()) == 0
        db.add_asset(hostname="a.example.com", asset_type=AssetType.SUBDOMAIN)
        assert len(db.get_all_assets()) == 1

    def test_get_all_assets(self):
        db = AssetDatabase()
        db.add_asset(hostname="a.example.com", asset_type=AssetType.SUBDOMAIN)
        db.add_asset(hostname="b.example.com", asset_type=AssetType.SUBDOMAIN)
        all_assets = db.get_all_assets()
        assert len(all_assets) == 2


# ── AssetClassifier tests ──────────────────────────────────────

class TestAssetClassifier:
    def test_classify_asset(self):
        classifier = AssetClassifier()
        asset = Asset(hostname="api.example.com", asset_type=AssetType.SUBDOMAIN)
        classified = classifier.classify_asset(asset)
        assert classified is not None
        assert classified.hostname == "api.example.com"

    def test_calculate_risk(self):
        classifier = AssetClassifier()
        asset = Asset(hostname="admin.example.com", asset_type=AssetType.SUBDOMAIN)
        risk = classifier.calculate_risk(asset)
        assert 0 <= risk <= 1.0

    def test_detect_technologies(self):
        classifier = AssetClassifier()
        asset = Asset(
            hostname="api.example.com",
            asset_type=AssetType.SUBDOMAIN,
            title="FastAPI Application",
        )
        classified = classifier.classify_asset(asset)
        assert "fastapi" in classified.technologies


# ── RelationshipGraph tests ────────────────────────────────────

class TestRelationshipGraph:
    def test_add_relationship(self):
        graph = RelationshipGraph()
        rel = graph.add_relationship(
            source_id="a.example.com",
            target_id="1.2.3.4",
            relation_type=RelationType.RESOLVES_TO,
        )
        assert rel is not None
        assert rel.source_id == "a.example.com"
        assert rel.target_id == "1.2.3.4"

    def test_get_neighbors(self):
        graph = RelationshipGraph()
        graph.add_relationship(
            source_id="a.example.com",
            target_id="1.2.3.4",
            relation_type=RelationType.RESOLVES_TO,
        )
        graph.add_relationship(
            source_id="a.example.com",
            target_id="b.example.com",
            relation_type=RelationType.REFERENCES,
        )
        neighbors = graph.get_neighbors("a.example.com")
        assert len(neighbors) == 2

    def test_get_outgoing(self):
        graph = RelationshipGraph()
        graph.add_relationship(
            source_id="a.example.com",
            target_id="1.2.3.4",
            relation_type=RelationType.RESOLVES_TO,
        )
        graph.add_relationship(
            source_id="b.example.com",
            target_id="a.example.com",
            relation_type=RelationType.REFERENCES,
        )
        outgoing = graph.get_outgoing("a.example.com")
        assert len(outgoing) == 1
        assert outgoing[0].source_id == "a.example.com"

    def test_get_incoming(self):
        graph = RelationshipGraph()
        graph.add_relationship(
            source_id="a.example.com",
            target_id="1.2.3.4",
            relation_type=RelationType.RESOLVES_TO,
        )
        graph.add_relationship(
            source_id="b.example.com",
            target_id="a.example.com",
            relation_type=RelationType.REFERENCES,
        )
        incoming = graph.get_incoming("a.example.com")
        assert len(incoming) == 1
        assert incoming[0].target_id == "a.example.com"

    def test_get_stats(self):
        graph = RelationshipGraph()
        graph.add_relationship(
            source_id="a.example.com",
            target_id="1.2.3.4",
            relation_type=RelationType.RESOLVES_TO,
        )
        graph.add_relationship(
            source_id="a.example.com",
            target_id="b.example.com",
            relation_type=RelationType.REFERENCES,
        )
        stats = graph.get_stats()
        assert stats["nodes"] == 3
        assert stats["edges"] == 2

    def test_empty_graph(self):
        graph = RelationshipGraph()
        stats = graph.get_stats()
        assert stats["nodes"] == 0
        assert stats["edges"] == 0
        neighbors = graph.get_neighbors("nonexistent.com")
        assert len(neighbors) == 0


# ── Enum tests ─────────────────────────────────────────────────

class TestEnums:
    def test_asset_type_values(self):
        assert AssetType.SUBDOMAIN.value == "subdomain"
        assert AssetType.IP.value == "ip"
        assert AssetType.URL.value == "url"
        assert AssetType.DOMAIN.value == "domain"
        assert AssetType.PORT.value == "port"
        assert AssetType.SERVICE.value == "service"
        assert AssetType.API.value == "api"

    def test_scope_status_values(self):
        assert ScopeStatus.IN_SCOPE.value == "in_scope"
        assert ScopeStatus.OUT_OF_SCOPE.value == "out_of_scope"
        assert ScopeStatus.UNKNOWN.value == "unknown"

    def test_relation_type_values(self):
        assert RelationType.RESOLVES_TO.value == "resolves_to"
        assert RelationType.HOSTS.value == "hosts"
        assert RelationType.EXPOSES.value == "exposes"
        assert RelationType.REFERENCES.value == "references"
        assert RelationType.CALLS.value == "calls"


# ── Relationship dataclass tests ───────────────────────────────

class TestRelationship:
    def test_defaults(self):
        rel = Relationship(
            source_id="a.example.com",
            target_id="1.2.3.4",
            relation_type=RelationType.RESOLVES_TO,
        )
        assert rel.source_id == "a.example.com"
        assert rel.target_id == "1.2.3.4"
        assert rel.relation_type == RelationType.RESOLVES_TO
        assert rel.properties == {}
        assert rel.confidence == 0.5

    def test_to_dict(self):
        rel = Relationship(
            source_id="a.example.com",
            target_id="1.2.3.4",
            relation_type=RelationType.RESOLVES_TO,
            confidence=0.8,
        )
        d = rel.to_dict()
        assert d["source_id"] == "a.example.com"
        assert d["target_id"] == "1.2.3.4"
        assert d["relation_type"] == "resolves_to"
        assert d["confidence"] == 0.8

    def test_from_dict(self):
        data = {
            "source_id": "a.example.com",
            "target_id": "1.2.3.4",
            "relation_type": "resolves_to",
            "confidence": 0.7,
        }
        rel = Relationship.from_dict(data)
        assert rel.source_id == "a.example.com"
        assert rel.target_id == "1.2.3.4"
        assert rel.relation_type == RelationType.RESOLVES_TO
        assert rel.confidence == 0.7


# ── Asset dataclass tests ──────────────────────────────────────

class TestAsset:
    def test_defaults(self):
        asset = Asset(hostname="api.example.com", asset_type=AssetType.SUBDOMAIN)
        assert asset.hostname == "api.example.com"
        assert asset.asset_type == AssetType.SUBDOMAIN
        assert asset.scope_status == ScopeStatus.UNKNOWN
        assert asset.risk_score == 0.0
        assert asset.ports == []
        assert asset.technologies == []

    def test_to_dict(self):
        asset = Asset(
            hostname="api.example.com",
            asset_type=AssetType.SUBDOMAIN,
            scope_status=ScopeStatus.IN_SCOPE,
            risk_score=0.5,
        )
        d = asset.to_dict()
        assert d["hostname"] == "api.example.com"
        assert d["asset_type"] == "subdomain"
        assert d["scope_status"] == "in_scope"
        assert d["risk_score"] == 0.5

    def test_from_dict(self):
        data = {
            "hostname": "api.example.com",
            "asset_type": "subdomain",
            "scope_status": "in_scope",
            "risk_score": 0.3,
        }
        asset = Asset.from_dict(data)
        assert asset.hostname == "api.example.com"
        assert asset.asset_type == AssetType.SUBDOMAIN
        assert asset.scope_status == ScopeStatus.IN_SCOPE
        assert asset.risk_score == 0.3