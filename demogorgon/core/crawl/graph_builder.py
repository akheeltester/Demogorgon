"""Graph Builder — populates the AttackGraph from ApplicationModel data.

Creates Nodes and Edges from BusinessObjects, AttackSurface entries,
Workflows, and TrustBoundaries. Keeps the graph in sync with the model.
"""

from __future__ import annotations

import re
from typing import Any

from ..models import (
    BusinessObject,
    AttackSurface,
    WorkflowStep,
    TrustBoundary,
    ObjectRelationship,
)

# Import AttackGraph from ARE module
from ...are.attack_graph import AttackGraph, Node, Edge, NodeType, EdgeType


# Mapping from ObjectRelationship to EdgeType
RELATIONSHIP_TO_EDGE = {
    "creates": EdgeType.CREATES,
    "reads": EdgeType.READS,
    "updates": EdgeType.UPDATES,
    "deletes": EdgeType.DELETES,
    "authorizes": EdgeType.AUTHORIZES,
    "depends_on": EdgeType.DEPENDS_ON,
    "flows_to": EdgeType.FLOWS_TO,
    "controls": EdgeType.CONTROLS,
    "owns": EdgeType.OWNS,
}


class GraphBuilder:
    """Builds an AttackGraph from ApplicationModel data.

    Usage:
        builder = GraphBuilder()
        graph = builder.build_from_model(app_model)
    """

    def build_from_model(
        self,
        business_objects: list[BusinessObject],
        attack_surface: list[AttackSurface],
        workflows: dict[str, list[WorkflowStep]],
        trust_boundaries: list[TrustBoundary],
        relationships: list[ObjectRelationship],
    ) -> AttackGraph:
        """Build a complete AttackGraph from model data."""
        graph = AttackGraph()

        # Add nodes for business objects
        for obj in business_objects:
            node = self._object_to_node(obj)
            graph.add_node(node)

        # Add nodes for attack surface endpoints
        for surface in attack_surface:
            node = self._surface_to_node(surface)
            graph.add_node(node)

        # Add nodes for trust boundaries
        for boundary in trust_boundaries:
            node = self._boundary_to_node(boundary)
            graph.add_node(node)

        # Add edges from workflows
        for workflow_name, steps in workflows.items():
            self._add_workflow_edges(graph, workflow_name, steps)

        # Add edges from object relationships
        for rel in relationships:
            self._add_relationship_edge(graph, rel)

        # Add edges connecting endpoints to business objects
        self._connect_surface_to_objects(graph, attack_surface, business_objects)

        return graph

    def update_graph(
        self,
        graph: AttackGraph,
        business_objects: list[BusinessObject],
        attack_surface: list[AttackSurface],
    ) -> None:
        """Incrementally update an existing graph with new data."""
        # Add new business object nodes
        existing_node_ids = {n.id for n in graph.get_all_nodes() if hasattr(graph, 'get_all_nodes')}
        for obj in business_objects:
            node = self._object_to_node(obj)
            if node.id not in existing_node_ids:
                graph.add_node(node)

        # Add new surface nodes
        for surface in attack_surface:
            node = self._surface_to_node(surface)
            if node.id not in existing_node_ids:
                graph.add_node(node)

    def _object_to_node(self, obj: BusinessObject) -> Node:
        """Convert a BusinessObject to a Node."""
        node_id = f"obj:{obj.object_type}:{obj.identifier}"
        return Node(
            id=node_id,
            name=f"{obj.object_type}#{obj.identifier}",
            node_type=NodeType.ENTITY,
            properties={
                "object_type": obj.object_type,
                "identifier": obj.identifier,
                "owner": obj.owner,
                "organization": obj.organization,
                "state": obj.state.value if hasattr(obj.state, 'value') else str(obj.state),
                "visibility": obj.visibility,
            },
            confidence=0.6,
        )

    def _surface_to_node(self, surface: AttackSurface) -> Node:
        """Convert an AttackSurface entry to a Node."""
        node_id = f"ep:{surface.method}:{surface.endpoint}"
        return Node(
            id=node_id,
            name=f"{surface.method} {surface.endpoint}",
            node_type=NodeType.ENDPOINT,
            properties={
                "category": surface.category,
                "risk_level": surface.risk_level,
                "auth_required": surface.auth_required,
                "state_changing": surface.state_changing,
                "parameters": surface.parameters,
            },
            confidence=0.7,
        )

    def _boundary_to_node(self, boundary: TrustBoundary) -> Node:
        """Convert a TrustBoundary to a Node."""
        node_id = f"tb:{boundary.name}"
        return Node(
            id=node_id,
            name=boundary.name,
            node_type=NodeType.TRUST_BOUNDARY,
            properties={
                "from_level": boundary.from_level,
                "to_level": boundary.to_level,
                "boundary_type": boundary.boundary_type,
                "bypass_techniques": boundary.bypass_techniques,
            },
            confidence=0.5,
        )

    def _add_workflow_edges(
        self,
        graph: AttackGraph,
        workflow_name: str,
        steps: list[WorkflowStep],
    ) -> None:
        """Add edges representing workflow step transitions."""
        for i, step in enumerate(steps):
            source_id = f"ep:{step.method}:{step.endpoint}"

            # Connect to next step
            if i + 1 < len(steps):
                next_step = steps[i + 1]
                target_id = f"ep:{next_step.method}:{next_step.endpoint}"
                graph.add_edge(
                    Edge(
                        source_id=source_id,
                        target_id=target_id,
                        edge_type=EdgeType.FLOWS_TO,
                        properties={
                            "workflow": workflow_name,
                            "step_index": i,
                        },
                    )
                )

            # Connect to produced business objects
            for obj_ref in step.produces_objects:
                obj_node_id = f"obj:{obj_ref}:{step.endpoint}"
                graph.add_edge(
                    Edge(
                        source_id=source_id,
                        target_id=obj_node_id,
                        edge_type=EdgeType.CREATES,
                        properties={"workflow": workflow_name},
                    )
                )

    def _add_relationship_edge(
        self,
        graph: AttackGraph,
        rel: ObjectRelationship,
    ) -> None:
        """Add an edge from an ObjectRelationship."""
        source_id = f"obj:{rel.from_type}:{rel.from_id}"
        target_id = f"obj:{rel.to_type}:{rel.to_id}"

        edge_type = RELATIONSHIP_TO_EDGE.get(rel.relationship, EdgeType.FLOWS_TO)

        graph.add_edge(
            Edge(
                source_id=source_id,
                target_id=target_id,
                edge_type=edge_type,
                properties={
                    "trust_required": rel.trust_required,
                    "bidirectional": rel.bidirectional,
                },
            )
        )

    def _connect_surface_to_objects(
        self,
        graph: AttackGraph,
        surfaces: list[AttackSurface],
        objects: list[BusinessObject],
    ) -> None:
        """Connect endpoints to the business objects they access."""
        for surface in surfaces:
            ep_node_id = f"ep:{surface.method}:{surface.endpoint}"

            for obj in objects:
                # Simple heuristic: if endpoint path contains object type
                obj_type_lower = obj.object_type.lower()
                endpoint_lower = surface.endpoint.lower()

                if obj_type_lower in endpoint_lower:
                    obj_node_id = f"obj:{obj.object_type}:{obj.identifier}"
                    graph.add_edge(
                        Edge(
                            source_id=ep_node_id,
                            target_id=obj_node_id,
                            edge_type=EdgeType.READS,
                            properties={"auto_connected": True},
                        )
                    )
