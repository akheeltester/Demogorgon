"""Crawl Pipeline — connects raw crawl output to the Application Model.

Takes katana/crawler output → deduplicates → builds Endpoint objects →
classifies into AttackSurface → populates ApplicationModel + AttackGraph.
"""

from .pipeline import CrawlerPipeline
from .endpoint_builder import EndpointBuilder
from .surface_builder import AttackSurfaceBuilder
from .graph_builder import GraphBuilder

__all__ = [
    "CrawlerPipeline",
    "EndpointBuilder",
    "AttackSurfaceBuilder",
    "GraphBuilder",
]