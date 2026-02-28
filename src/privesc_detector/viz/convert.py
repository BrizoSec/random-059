"""Convert an nx.DiGraph to Cytoscape element lists.

Two public functions:
    collapsed_elements(g)  — one Cytoscape edge per src→dst pair
    raw_elements(g)        — one Cytoscape edge per event in edge_list

Both return a list of dicts ready to pass to dash-cytoscape's `elements` prop.
"""

from __future__ import annotations

import networkx as nx


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def collapsed_elements(g: nx.DiGraph) -> list[dict]:
    """One Cytoscape edge per NetworkX edge (parallel events are aggregated)."""
    elements: list[dict] = _node_elements(g)
    for src, dst, attrs in g.edges(data=True):
        edge_list = attrs.get("edge_list", [])
        mechanism = attrs.get("mechanism", "unknown")
        count = len(edge_list)
        label = f"{mechanism} ×{count}" if count > 1 else mechanism
        elements.append({
            "data": {
                "id": f"{src}->{dst}",
                "source": src,
                "target": dst,
                "mechanism": mechanism,
                "event_category": attrs.get("event_category", ""),
                "event_count": count,
                "label": label,
                "src_privilege": attrs.get("src_privilege", 0.0),
                "dst_privilege": attrs.get("dst_privilege", 0.0),
                "timestamp": attrs.get("timestamp", ""),
            },
            "classes": f"mechanism-{mechanism}",
        })
    return elements


def raw_elements(g: nx.DiGraph) -> list[dict]:
    """One Cytoscape edge per event in each NetworkX edge's edge_list."""
    elements: list[dict] = _node_elements(g)
    for src, dst, attrs in g.edges(data=True):
        for entry in attrs.get("edge_list", []):
            mechanism = entry.get("mechanism", "unknown")
            elements.append({
                "data": {
                    "id": entry["event_id"],
                    "source": src,
                    "target": dst,
                    "mechanism": mechanism,
                    "event_category": entry.get("event_category", ""),
                    "event_id": entry["event_id"],
                    "label": mechanism,
                    "src_privilege": entry.get("src_privilege", 0.0),
                    "dst_privilege": entry.get("dst_privilege", 0.0),
                    "timestamp": entry.get("timestamp", ""),
                    "session_id": entry.get("session_id"),
                },
                "classes": f"mechanism-{mechanism}",
            })
    return elements


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _node_elements(g: nx.DiGraph) -> list[dict]:
    elements = []
    for node_id, attrs in g.nodes(data=True):
        tier = attrs.get("privilege_tier", 0.0)
        elements.append({
            "data": {
                "id": node_id,
                "label": _format_label(node_id),
                "privilege_tier": tier,
                "host_id": attrs.get("host_id", ""),
            },
            "classes": _privilege_class(tier),
        })
    return elements


def _format_label(node_id: str) -> str:
    """'account:alice|host:web-01' → 'alice\nweb-01'"""
    account_part, _, host_part = node_id.partition("|")
    account = account_part.removeprefix("account:")
    host = host_part.removeprefix("host:")
    return f"{account}\n{host}"


def _privilege_class(tier: float) -> str:
    if tier < 0.25:
        return "privilege-low"
    if tier < 0.5:
        return "privilege-medium"
    if tier < 0.75:
        return "privilege-high"
    return "privilege-critical"
