"""Graph builder — converts a list of AuthEdge into a NetworkX DiGraph.

This is a pure synchronous function with no database dependency.
The caller is responsible for fetching edges from Mongo (async); this
module only handles the in-memory graph construction.
"""

from __future__ import annotations

import networkx as nx

from privesc_detector.models.edge import AuthEdge


def load_graph(edges: list[AuthEdge]) -> nx.DiGraph:
    """Build a directed graph from a list of AuthEdge objects.

    Node attributes:
        privilege_tier  -- taken from the edge's src/dst privilege at event time
        host_id         -- host where the auth event occurred (on src node)

    Edge attributes:
        edge_id         -- AuthEdge.id
        edge_type       -- "ssh" | "kinit" | "su"
        timestamp       -- event datetime (ISO string for JSON-serializability)
        session_id      -- may be None
        src_privilege   -- float
        dst_privilege   -- float
    """
    g: nx.DiGraph = nx.DiGraph()

    for edge in edges:
        # Upsert nodes — later edges may carry higher privilege values; we keep
        # the maximum seen so we don't accidentally downgrade a node's tier.
        _add_or_update_node(g, edge.src_node_id, edge.src_privilege, edge.host_id)
        _add_or_update_node(g, edge.dst_node_id, edge.dst_privilege, edge.host_id)

        # For parallel edges (same src→dst pair) we store a list of edge dicts
        # under a single DiGraph edge keyed by the first edge_id we see.
        # Callers that need multi-edge semantics should use nx.MultiDiGraph instead;
        # for DFS chain detection, DiGraph with an edge_list attribute is sufficient.
        if g.has_edge(edge.src_node_id, edge.dst_node_id):
            g[edge.src_node_id][edge.dst_node_id]["edge_list"].append(
                _edge_attrs(edge)
            )
        else:
            g.add_edge(
                edge.src_node_id,
                edge.dst_node_id,
                edge_id=edge.id,
                edge_list=[_edge_attrs(edge)],
                edge_type=edge.edge_type,
                timestamp=edge.timestamp.isoformat(),
                session_id=edge.session_id,
                src_privilege=edge.src_privilege,
                dst_privilege=edge.dst_privilege,
            )

    return g


def _add_or_update_node(
    g: nx.DiGraph, node_id: str, privilege: float, host_id: str
) -> None:
    if node_id not in g:
        g.add_node(node_id, privilege_tier=privilege, host_id=host_id)
    else:
        existing = g.nodes[node_id].get("privilege_tier", 0.0)
        g.nodes[node_id]["privilege_tier"] = max(existing, privilege)


def _edge_attrs(edge: AuthEdge) -> dict:  # type: ignore[type-arg]
    return {
        "edge_id": edge.id,
        "edge_type": edge.edge_type,
        "timestamp": edge.timestamp.isoformat(),
        "session_id": edge.session_id,
        "src_privilege": edge.src_privilege,
        "dst_privilege": edge.dst_privilege,
    }
