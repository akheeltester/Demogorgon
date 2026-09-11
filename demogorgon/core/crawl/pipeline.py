"""Crawler Pipeline — orchestrates crawl → parse → dedup → model.

This is the main entry point for Phase 4. It takes raw crawl output
from any source (katana, BFS crawler, browser, httpx) and:
1. Converts to canonical Endpoint objects
2. Deduplicates across sources
3. Classifies into AttackSurface
4. Populates the ApplicationModel
5. Builds/updates the AttackGraph
"""

from __future__ import annotations

import time
from typing import Any

from ...app_model import ApplicationModel
from ...are.attack_graph import AttackGraph
from ..models import Endpoint, AttackSurface
from .endpoint_builder import EndpointBuilder
from .surface_builder import AttackSurfaceBuilder
from .graph_builder import GraphBuilder


class CrawlerPipeline:
    """Orchestrates the crawl-to-model pipeline.

    Usage:
        pipeline = CrawlerPipeline(app_model, attack_graph)

        # Ingest from any source
        pipeline.ingest_katana(katana_output)
        pipeline.ingest_crawler(crawler_output)
        pipeline.ingest_httpx(httpx_output)
        pipeline.ingest_urls(url_list)

        # Get results
        endpoints = pipeline.get_endpoints()
        surfaces = pipeline.get_surfaces()
        summary = pipeline.get_summary()
    """

    def __init__(
        self,
        app_model: ApplicationModel | None = None,
        attack_graph: AttackGraph | None = None,
    ):
        self._app_model = app_model
        self._attack_graph = attack_graph

        self._endpoint_builder = EndpointBuilder()
        self._surface_builder = AttackSurfaceBuilder()
        self._graph_builder = GraphBuilder()

        # Accumulated data
        self._endpoints: list[Endpoint] = []
        self._surfaces: list[AttackSurface] = []
        self._sources: dict[str, int] = {}  # source -> count
        self._last_updated: float = 0.0

    def ingest_katana(self, data: dict[str, Any]) -> int:
        """Ingest katana crawl output. Returns count of new endpoints."""
        endpoints = self._endpoint_builder.build_from_katana(data)
        new_count = self._add_endpoints(endpoints)
        self._sources["katana"] = self._sources.get("katana", 0) + new_count
        return new_count

    def ingest_crawler(self, data: dict[str, Any]) -> int:
        """Ingest BFS crawler output. Returns count of new endpoints."""
        endpoints = self._endpoint_builder.build_from_crawler(data)
        new_count = self._add_endpoints(endpoints)
        self._sources["crawler"] = self._sources.get("crawler", 0) + new_count
        return new_count

    def ingest_httpx(self, data: dict[str, Any]) -> int:
        """Ingest httpx probe output. Returns count of new endpoints."""
        endpoints = self._endpoint_builder.build_from_httpx(data)
        new_count = self._add_endpoints(endpoints)
        self._sources["httpx"] = self._sources.get("httpx", 0) + new_count
        return new_count

    def ingest_urls(self, urls: list[str], source: str = "manual") -> int:
        """Ingest a plain URL list. Returns count of new endpoints."""
        endpoints = self._endpoint_builder.build_from_urls(urls, source=source)
        new_count = self._add_endpoints(endpoints)
        self._sources[source] = self._sources.get(source, 0) + new_count
        return new_count

    def ingest_endpoints(self, endpoints: list[Endpoint]) -> int:
        """Ingest pre-built Endpoint objects directly."""
        new_count = self._add_endpoints(endpoints)
        self._sources["direct"] = self._sources.get("direct", 0) + new_count
        return new_count

    def build_surfaces(self) -> list[AttackSurface]:
        """Classify all endpoints into AttackSurface entries."""
        self._surfaces = self._surface_builder.build(self._endpoints)
        return self._surfaces

    def populate_model(self) -> None:
        """Populate the ApplicationModel with surfaces and observations."""
        if not self._app_model:
            return

        # Build surfaces if not already done
        if not self._surfaces:
            self.build_surfaces()

        # Add surfaces to model
        for surface in self._surfaces:
            self._app_model.add_attack_surface(surface)

        # Add observation about crawl
        self._app_model.add_observation({
            "category": "recon",
            "description": f"Crawl discovered {len(self._endpoints)} endpoints across {len(self._sources)} sources",
            "sources": dict(self._sources),
            "timestamp": time.time(),
        })

    def build_graph(self) -> AttackGraph | None:
        """Build or update the AttackGraph from model data."""
        if not self._app_model or not self._attack_graph:
            return None

        self._attack_graph = self._graph_builder.build_from_model(
            business_objects=self._app_model.business_objects,
            attack_surface=self._app_model.attack_surface,
            workflows=self._app_model.workflows,
            trust_boundaries=self._app_model.trust_boundaries,
            relationships=self._app_model.relationships,
        )
        return self._attack_graph

    def get_endpoints(self) -> list[Endpoint]:
        """Get all accumulated endpoints."""
        return list(self._endpoints)

    def get_surfaces(self) -> list[AttackSurface]:
        """Get all classified surfaces."""
        return list(self._surfaces)

    def get_endpoints_by_category(self, category: str) -> list[Endpoint]:
        """Get endpoints matching a category."""
        if not self._surfaces:
            self.build_surfaces()

        matching_urls = {
            s.endpoint for s in self._surfaces if s.category == category
        }
        return [ep for ep in self._endpoints if ep.url in matching_urls]

    def get_high_risk_endpoints(self) -> list[Endpoint]:
        """Get endpoints with high or critical risk."""
        if not self._surfaces:
            self.build_surfaces()

        high_risk_urls = {
            s.endpoint for s in self._surfaces if s.risk_level in ("high", "critical")
        }
        return [ep for ep in self._endpoints if ep.url in high_risk_urls]

    def get_state_changing_endpoints(self) -> list[Endpoint]:
        """Get endpoints that change state (POST/PUT/PATCH/DELETE)."""
        return [
            ep for ep in self._endpoints
            if ep.method.upper() in {"POST", "PUT", "PATCH", "DELETE"}
        ]

    def get_summary(self) -> dict[str, Any]:
        """Get a summary of pipeline state."""
        if not self._surfaces:
            self.build_surfaces()

        # Category breakdown
        categories: dict[str, int] = {}
        risk_levels: dict[str, int] = {}
        for surface in self._surfaces:
            categories[surface.category] = categories.get(surface.category, 0) + 1
            risk_levels[surface.risk_level] = risk_levels.get(surface.risk_level, 0) + 1

        return {
            "total_endpoints": len(self._endpoints),
            "total_surfaces": len(self._surfaces),
            "sources": dict(self._sources),
            "categories": categories,
            "risk_levels": risk_levels,
            "state_changing": len(self.get_state_changing_endpoints()),
            "high_risk": len(self.get_high_risk_endpoints()),
        }

    def _add_endpoints(self, endpoints: list[Endpoint]) -> int:
        """Add endpoints to the accumulated list. Returns count of new ones."""
        existing_keys = {
            f"{ep.method.upper()}:{ep.url}" for ep in self._endpoints
        }

        new_count = 0
        for ep in endpoints:
            key = f"{ep.method.upper()}:{ep.url}"
            if key not in existing_keys:
                self._endpoints.append(ep)
                existing_keys.add(key)
                new_count += 1

        self._last_updated = time.time()
        return new_count
