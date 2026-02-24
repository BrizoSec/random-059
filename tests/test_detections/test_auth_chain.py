"""Unit tests for Detection C — Excessive Auth Chain."""

from __future__ import annotations

import networkx as nx
import pytest

from privesc_detector.config import ChainConfig
from privesc_detector.detections import auth_chain


def test_no_alert_short_chain(
    linear_graph: nx.DiGraph,
    chain_config: ChainConfig,
) -> None:
    # A→B→C→D is exactly 3 hops; threshold=3 — equal is not "excessive"
    results = auth_chain.detect(linear_graph, chain_config, "A")
    assert results == []


def test_alert_on_long_chain(
    long_chain_graph: nx.DiGraph,
    chain_config: ChainConfig,
) -> None:
    # A→B→C→D→E is 4 hops; threshold=3 — should fire
    results = auth_chain.detect(long_chain_graph, chain_config, "A")
    assert len(results) >= 1
    result = results[0]
    assert result.detection_type == "auth_chain"
    assert result.metadata["hop_count"] == 4
    assert "A" in result.node_ids
    assert "E" in result.node_ids


def test_cycle_not_followed(
    cyclic_graph: nx.DiGraph,
    chain_config: ChainConfig,
) -> None:
    # A→B→C→A: all_simple_paths stops at revisited nodes; should not loop
    # With threshold=3 and only 2 hops in any simple path, no alert expected
    results = auth_chain.detect(cyclic_graph, chain_config, "A")
    assert results == []


def test_graph_size_safety_bailout(chain_config: ChainConfig) -> None:
    # A graph exceeding max_graph_nodes should return empty immediately
    big_config = ChainConfig(max_chain_length=3, max_graph_nodes=5)
    g: nx.DiGraph = nx.DiGraph()
    for i in range(10):
        g.add_node(str(i), privilege_tier=0.1, host_id="host:x")
    results = auth_chain.detect(g, big_config, "0")
    assert results == []


def test_starting_node_not_in_graph(chain_config: ChainConfig) -> None:
    g: nx.DiGraph = nx.DiGraph()
    g.add_node("A", privilege_tier=0.1, host_id="host:x")
    results = auth_chain.detect(g, chain_config, "MISSING")
    assert results == []


def test_edge_ids_collected_from_path(chain_config: ChainConfig) -> None:
    # Build a 4-hop chain manually and verify edge_ids are populated
    g: nx.DiGraph = nx.DiGraph()
    nodes = ["n0", "n1", "n2", "n3", "n4"]
    for i, (src, dst) in enumerate(zip(nodes, nodes[1:])):
        g.add_node(src, privilege_tier=0.2, host_id="host:test")
        g.add_node(dst, privilege_tier=0.2, host_id="host:test")
        g.add_edge(
            src,
            dst,
            edge_id=f"eid-{i}",
            edge_list=[{"edge_id": f"eid-{i}", "edge_type": "ssh"}],
            edge_type="ssh",
        )

    results = auth_chain.detect(g, chain_config, "n0")
    assert results
    assert len(results[0].edge_ids) == 4
    assert results[0].edge_ids[0] == "eid-0"


def test_description_contains_hop_count(
    long_chain_graph: nx.DiGraph,
    chain_config: ChainConfig,
) -> None:
    results = auth_chain.detect(long_chain_graph, chain_config, "A")
    assert results
    assert "4" in results[0].description
