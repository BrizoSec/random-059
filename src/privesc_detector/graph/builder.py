"""Graph builder — converts a list of auth events into a NetworkX DiGraph.

This is a pure synchronous function with no database dependency.
The caller is responsible for fetching events from Mongo (async); this
module only handles the in-memory graph construction.
"""

from __future__ import annotations

import networkx as nx

from privesc_detector.model.event import AnyEvent


def load_graph(events: list[AnyEvent]) -> nx.DiGraph:
    """Build a directed graph from a list of auth events.

    Node attributes:
        privilege_tier  -- taken from the event's src/dst privilege at event time
        host_id         -- host where the account was present at this node

    Edge attributes:
        event_id        -- AnyEvent.id
        event_category  -- "authentication" | "session"
        mechanism       -- e.g. "ssh", "kinit", "su"
        timestamp       -- event datetime (ISO string for JSON-serializability)
        session_id      -- may be None
        src_privilege   -- float
        dst_privilege   -- float
    """
    g: nx.DiGraph = nx.DiGraph()

    for event in events:
        # Upsert nodes — later events may carry higher privilege values; we keep
        # the maximum seen so we don't accidentally downgrade a node's tier.
        _add_or_update_node(g, event.src_node_id, event.src_privilege, event.src_host_id)
        _add_or_update_node(g, event.dst_node_id, event.dst_privilege, event.dst_host_id)

        # For parallel edges (same src→dst pair) we store a list of event dicts
        # under a single DiGraph edge keyed by the first event_id we see.
        if g.has_edge(event.src_node_id, event.dst_node_id):
            g[event.src_node_id][event.dst_node_id]["edge_list"].append(
                _event_attrs(event)
            )
        else:
            g.add_edge(
                event.src_node_id,
                event.dst_node_id,
                event_id=event.id,
                edge_list=[_event_attrs(event)],
                event_category=event.event_category,
                mechanism=event.mechanism,
                timestamp=event.timestamp.isoformat(),
                session_id=event.session_id,
                src_privilege=event.src_privilege,
                dst_privilege=event.dst_privilege,
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


def _event_attrs(event: AnyEvent) -> dict:  # type: ignore[type-arg]
    return {
        "event_id": event.id,
        "event_category": event.event_category,
        "mechanism": event.mechanism,
        "timestamp": event.timestamp.isoformat(),
        "session_id": event.session_id,
        "src_privilege": event.src_privilege,
        "dst_privilege": event.dst_privilege,
    }
