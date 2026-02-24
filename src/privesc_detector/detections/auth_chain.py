"""Detection C — Excessive Auth Chain.

Walks the NetworkX DiGraph with an iterative DFS starting from a given node.
Fires when a discovered path (chain of connected sessions / lateral movement
hops) exceeds the configured length threshold.

The DFS tracks visited nodes per path (not globally), so cycles are detected
naturally: a node already on the current path is never extended further.
"""

from __future__ import annotations

import networkx as nx

from privesc_detector.config import ChainConfig
from privesc_detector.detections.base import DetectionResult


def detect(
    graph: nx.DiGraph,
    config: ChainConfig,
    starting_node: str,
) -> list[DetectionResult]:
    """Return DetectionResults for every path longer than max_chain_length.

    Args:
        graph:          Full auth graph built by graph.builder.load_graph().
        config:         Chain detection config (max_chain_length, max_graph_nodes).
        starting_node:  Node ID to start DFS from (typically the src_node_id of
                        the newly ingested edge).

    Returns:
        A list of DetectionResults (empty if no long chains found).
    """
    results: list[DetectionResult] = []

    if graph.number_of_nodes() > config.max_graph_nodes:
        return results  # safety bail-out: graph too large to walk

    if starting_node not in graph:
        return results

    # cutoff = max_chain_length + 1 so we only explore paths that *could* exceed the limit.
    # nx.all_simple_paths requires a target; we use a manual DFS instead so we can
    # enumerate all reachable paths regardless of destination.
    cutoff = config.max_chain_length + 1

    for path in _all_simple_paths_from(graph, starting_node, cutoff):
        hop_count = len(path) - 1  # number of edges traversed
        if hop_count > config.max_chain_length:
            edge_ids = _collect_edge_ids(graph, path)
            host_id = graph.nodes[starting_node].get("host_id", "unknown")
            results.append(
                DetectionResult(
                    detection_type="auth_chain",
                    severity="high",
                    edge_ids=edge_ids,
                    node_ids=list(path),
                    host_id=host_id,
                    description=(
                        f"Excessive auth chain from {starting_node}: "
                        f"{hop_count} hops (threshold: {config.max_chain_length})"
                    ),
                    metadata={
                        "path": list(path),
                        "hop_count": hop_count,
                        "starting_node": starting_node,
                    },
                )
            )

    return results


def _all_simple_paths_from(
    graph: nx.DiGraph,
    source: str,
    cutoff: int,
) -> list[list[str]]:
    """Iterative DFS that yields all simple paths from *source* up to *cutoff* hops.

    A "simple path" never revisits the same node. The stack stores tuples of
    (current_node, path_so_far). We do not yield the single-node path [source].
    """
    paths: list[list[str]] = []
    # Stack entries: (node, path leading to this node)
    stack: list[tuple[str, list[str]]] = [(source, [source])]

    while stack:
        node, path = stack.pop()
        # Record this path if it has at least one edge
        if len(path) > 1:
            paths.append(path)
        # Stop extending if we've reached the cutoff
        if len(path) - 1 >= cutoff:
            continue
        visited = set(path)
        for neighbor in graph.neighbors(node):
            if neighbor not in visited:
                stack.append((neighbor, path + [neighbor]))

    return paths


def _collect_edge_ids(graph: nx.DiGraph, path: list[str]) -> list[str]:
    """Extract edge_ids for each consecutive node pair in the path."""
    ids: list[str] = []
    for src, dst in zip(path, path[1:]):
        edge_data = graph.get_edge_data(src, dst) or {}
        # edge_list holds all parallel edges; use the first edge_id for each hop
        edge_list = edge_data.get("edge_list", [])
        if edge_list:
            ids.append(edge_list[0]["edge_id"])
        elif "edge_id" in edge_data:
            ids.append(edge_data["edge_id"])
    return ids
