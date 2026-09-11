"""Tests for Phase 4 components: CrawlerPipeline and AttackSurfaceBuilder."""

from __future__ import annotations

import pytest

from demogorgon.core.crawl.endpoint_builder import EndpointBuilder
from demogorgon.core.crawl.surface_builder import AttackSurfaceBuilder
from demogorgon.core.crawl.graph_builder import GraphBuilder
from demogorgon.core.crawl.pipeline import CrawlerPipeline
from demogorgon.core.models import (
    Endpoint,
    AttackSurface,
    BusinessObject,
    WorkflowStep,
    TrustBoundary,
    ObjectRelationship,
    ObjectState,
)
from demogorgon.app_model import ApplicationModel
from demogorgon.are.attack_graph import AttackGraph, NodeType


# ── EndpointBuilder tests ──────────────────────────────────────

class TestEndpointBuilder:
    def test_build_from_katana(self):
        builder = EndpointBuilder()
        data = {
            "endpoints": [
                {"url": "https://api.example.com/users", "method": "GET", "tag": "a", "source": "katana"},
                {"url": "https://api.example.com/users", "method": "POST", "tag": "form", "source": "katana"},
                {"url": "https://example.com/about", "method": "GET", "tag": "a", "source": "katana"},
            ]
        }
        endpoints = builder.build_from_katana(data)
        assert len(endpoints) == 3
        assert endpoints[0].url == "https://api.example.com/users"
        assert endpoints[0].method == "GET"
        assert endpoints[1].method == "POST"

    def test_build_from_katana_dedup(self):
        builder = EndpointBuilder()
        data = {
            "endpoints": [
                {"url": "https://api.example.com/users", "method": "GET"},
                {"url": "https://api.example.com/users", "method": "GET"},
            ]
        }
        endpoints = builder.build_from_katana(data)
        assert len(endpoints) == 1

    def test_build_from_crawler(self):
        builder = EndpointBuilder()
        data = {
            "endpoints": [
                {"url": "https://example.com/page1", "method": "GET"},
            ],
            "forms": [
                {
                    "action": "https://example.com/login",
                    "method": "POST",
                    "inputs": [
                        {"name": "username", "type": "text"},
                        {"name": "password", "type": "password"},
                    ],
                }
            ],
        }
        endpoints = builder.build_from_crawler(data)
        assert len(endpoints) == 2
        # Check form endpoint has params
        login_ep = [ep for ep in endpoints if "login" in ep.url][0]
        assert "username" in login_ep.params
        assert "password" in login_ep.params

    def test_build_from_urls(self):
        builder = EndpointBuilder()
        urls = [
            "https://example.com/api/v1/users",
            "https://example.com/api/v1/users",  # duplicate
            "https://example.com/about",
        ]
        endpoints = builder.build_from_urls(urls)
        assert len(endpoints) == 2

    def test_build_from_httpx(self):
        builder = EndpointBuilder()
        data = {
            "live_hosts": [
                {
                    "url": "https://api.example.com",
                    "status_code": 200,
                    "title": "API",
                    "tech": ["nginx", "python"],
                    "content_type": "application/json",
                }
            ]
        }
        endpoints = builder.build_from_httpx(data)
        assert len(endpoints) == 1
        assert endpoints[0].status_code == 200

    def test_merge(self):
        builder = EndpointBuilder()
        list1 = builder.build_from_urls(["https://example.com/a"])
        list2 = builder.build_from_urls(["https://example.com/b"])
        merged = builder.merge(list1, list2)
        assert len(merged) == 2

    def test_merge_dedup(self):
        builder = EndpointBuilder()
        list1 = builder.build_from_urls(["https://example.com/a"])
        list2 = builder.build_from_urls(["https://example.com/a"])
        merged = builder.merge(list1, list2)
        assert len(merged) == 1

    def test_params_from_query_string(self):
        builder = EndpointBuilder()
        endpoints = builder.build_from_urls(["https://example.com/search?q=test&page=1"])
        assert "q" in endpoints[0].params
        assert "page" in endpoints[0].params


# ── AttackSurfaceBuilder tests ─────────────────────────────────

class TestAttackSurfaceBuilder:
    def test_build(self):
        builder = AttackSurfaceBuilder()
        endpoints = [
            Endpoint(url="https://api.example.com/users", method="GET"),
            Endpoint(url="https://example.com/admin/dashboard", method="GET", auth_required=True),
            Endpoint(url="https://example.com/login", method="POST"),
        ]
        surfaces = builder.build(endpoints)
        assert len(surfaces) == 3

    def test_category_detection(self):
        builder = AttackSurfaceBuilder()
        endpoints = [
            Endpoint(url="https://example.com/api/v1/users", method="GET"),
            Endpoint(url="https://example.com/admin/settings", method="GET"),
            Endpoint(url="https://example.com/login", method="POST"),
            Endpoint(url="https://example.com/search", method="GET"),
            Endpoint(url="https://example.com/debug/trace", method="GET"),
        ]
        surfaces = builder.build(endpoints)
        categories = {s.category for s in surfaces}
        assert "api" in categories
        assert "admin" in categories
        assert "authentication" in categories
        assert "search" in categories
        assert "debug" in categories

    def test_risk_levels(self):
        builder = AttackSurfaceBuilder()
        endpoints = [
            Endpoint(url="https://example.com/admin/delete", method="DELETE", auth_required=True),
            Endpoint(url="https://example.com/about", method="GET"),
        ]
        surfaces = builder.build(endpoints)
        admin_surface = [s for s in surfaces if s.category == "admin"][0]
        about_surface = [s for s in surfaces if s.category == "other"][0]
        assert admin_surface.risk_level in ("high", "critical")
        assert about_surface.risk_level in ("medium", "low", "info")

    def test_state_changing(self):
        builder = AttackSurfaceBuilder()
        endpoints = [
            Endpoint(url="https://example.com/api/users", method="POST"),
            Endpoint(url="https://example.com/api/users", method="GET"),
        ]
        surfaces = builder.build(endpoints)
        post_surface = [s for s in surfaces if s.method == "POST"][0]
        get_surface = [s for s in surfaces if s.method == "GET"][0]
        assert post_surface.state_changing is True
        assert get_surface.state_changing is False


# ── GraphBuilder tests ─────────────────────────────────────────

class TestGraphBuilder:
    def test_build_from_model(self):
        builder = GraphBuilder()
        objects = [
            BusinessObject(object_type="user", object_id="123", owner="alice"),
            BusinessObject(object_type="order", object_id="456", owner="bob"),
        ]
        surfaces = [
            AttackSurface(
                endpoint="https://api.example.com/users",
                method="GET",
                category="api",
                risk_level="medium",
                auth_required=False,
                rate_limited=False,
                parameters=[],
                state_changing=False,
            ),
        ]
        workflows = {}
        trust_boundaries = []
        relationships = [
            ObjectRelationship(
                from_type="user",
                to_type="order",
                relationship="owns",
                from_id="123",
                to_id="456",
            ),
        ]

        graph = builder.build_from_model(objects, surfaces, workflows, trust_boundaries, relationships)
        assert graph is not None
        summary = graph.get_summary()
        assert summary["total_nodes"] >= 3  # 2 objects + 1 endpoint
        assert summary["total_edges"] >= 1  # 1 relationship


# ── CrawlerPipeline tests ──────────────────────────────────────

class TestCrawlerPipeline:
    def test_ingest_katana(self):
        pipeline = CrawlerPipeline()
        data = {
            "endpoints": [
                {"url": "https://example.com/a", "method": "GET"},
                {"url": "https://example.com/b", "method": "POST"},
            ]
        }
        count = pipeline.ingest_katana(data)
        assert count == 2
        assert len(pipeline.get_endpoints()) == 2

    def test_ingest_crawler(self):
        pipeline = CrawlerPipeline()
        data = {
            "endpoints": [{"url": "https://example.com/page1"}],
            "forms": [{"action": "https://example.com/login", "method": "POST", "inputs": [{"name": "user"}]}],
        }
        count = pipeline.ingest_crawler(data)
        assert count == 2

    def test_ingest_urls(self):
        pipeline = CrawlerPipeline()
        count = pipeline.ingest_urls(["https://example.com/a", "https://example.com/b"])
        assert count == 2

    def test_cross_source_dedup(self):
        pipeline = CrawlerPipeline()
        pipeline.ingest_katana({"endpoints": [{"url": "https://example.com/a", "method": "GET"}]})
        pipeline.ingest_urls(["https://example.com/a"])  # same URL
        assert len(pipeline.get_endpoints()) == 1

    def test_build_surfaces(self):
        pipeline = CrawlerPipeline()
        pipeline.ingest_urls([
            "https://example.com/api/users",
            "https://example.com/admin/dashboard",
        ])
        surfaces = pipeline.build_surfaces()
        assert len(surfaces) == 2
        categories = {s.category for s in surfaces}
        assert "api" in categories
        assert "admin" in categories

    def test_get_high_risk_endpoints(self):
        pipeline = CrawlerPipeline()
        pipeline.ingest_urls([
            "https://example.com/admin/delete",
            "https://example.com/about",
        ])
        pipeline.build_surfaces()
        high_risk = pipeline.get_high_risk_endpoints()
        assert len(high_risk) >= 1

    def test_get_state_changing_endpoints(self):
        pipeline = CrawlerPipeline()
        pipeline.ingest_katana({
            "endpoints": [
                {"url": "https://example.com/api/users", "method": "POST"},
                {"url": "https://example.com/api/users", "method": "GET"},
            ]
        })
        state_changing = pipeline.get_state_changing_endpoints()
        assert len(state_changing) == 1
        assert state_changing[0].method == "POST"

    def test_get_summary(self):
        pipeline = CrawlerPipeline()
        pipeline.ingest_urls(["https://example.com/api/users", "https://example.com/about"])
        summary = pipeline.get_summary()
        assert summary["total_endpoints"] == 2
        assert summary["total_surfaces"] == 2
        assert "katana" in summary["sources"] or "manual" in summary["sources"]

    def test_populate_model(self):
        app_model = ApplicationModel("https://example.com")
        pipeline = CrawlerPipeline(app_model=app_model)
        pipeline.ingest_urls(["https://example.com/api/users"])
        pipeline.build_surfaces()
        pipeline.populate_model()
        assert len(app_model.attack_surface) >= 1

    def test_build_graph(self):
        app_model = ApplicationModel("https://example.com")
        attack_graph = AttackGraph()
        pipeline = CrawlerPipeline(app_model=app_model, attack_graph=attack_graph)
        pipeline.ingest_urls(["https://example.com/api/users"])
        pipeline.build_surfaces()
        pipeline.populate_model()
        graph = pipeline.build_graph()
        assert graph is not None

    def test_source_tracking(self):
        pipeline = CrawlerPipeline()
        pipeline.ingest_katana({"endpoints": [{"url": "https://example.com/a"}]})
        pipeline.ingest_httpx({"live_hosts": [{"url": "https://example.com/b"}]})
        summary = pipeline.get_summary()
        assert summary["sources"]["katana"] == 1
        assert summary["sources"]["httpx"] == 1


# ── Integration test ───────────────────────────────────────────

class TestPhase4Integration:
    def test_full_pipeline_flow(self):
        """Test the complete crawl → surface → model → graph flow."""
        # Setup
        app_model = ApplicationModel("https://example.com")
        attack_graph = AttackGraph()
        pipeline = CrawlerPipeline(app_model=app_model, attack_graph=attack_graph)

        # Ingest from multiple sources
        pipeline.ingest_katana({
            "endpoints": [
                {"url": "https://example.com/api/v1/users", "method": "GET"},
                {"url": "https://example.com/api/v1/users", "method": "POST"},
                {"url": "https://example.com/api/v1/orders", "method": "GET"},
            ]
        })
        pipeline.ingest_crawler({
            "endpoints": [
                {"url": "https://example.com/dashboard", "method": "GET"},
            ],
            "forms": [
                {
                    "action": "https://example.com/login",
                    "method": "POST",
                    "inputs": [{"name": "email"}, {"name": "password"}],
                }
            ],
        })
        pipeline.ingest_urls(["https://example.com/admin/settings"])

        # Build surfaces
        surfaces = pipeline.build_surfaces()
        assert len(surfaces) >= 5

        # Populate model
        pipeline.populate_model()
        assert len(app_model.attack_surface) >= 5
        assert len(app_model.observations) >= 1

        # Build graph
        graph = pipeline.build_graph()
        assert graph is not None
        summary = graph.get_summary()
        assert summary["total_nodes"] >= 5

        # Verify pipeline summary
        pipeline_summary = pipeline.get_summary()
        assert pipeline_summary["total_endpoints"] >= 5
        assert pipeline_summary["total_surfaces"] >= 5
        assert len(pipeline_summary["sources"]) >= 3