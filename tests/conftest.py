"""Shared pytest fixtures for the privilege escalation detector test suite."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Callable

import networkx as nx
import pytest

from privesc_detector.config import AppConfig, BurstConfig, ChainConfig, KeytabSmugglingConfig, PrivEscConfig
from privesc_detector.detections.auth_burst import BurstWindowState
from privesc_detector.enrichment.cache import AllEnrichments
from privesc_detector.enrichment.critical_accounts import CriticalAccountsCache, CriticalAccountsEnrichment
from privesc_detector.enrichment.vault import VaultCache, VaultEnrichment
from privesc_detector.model.event import AnyEvent, SessionEvent
from privesc_detector.model.node import AccountNode, HostNode


# ---------------------------------------------------------------------------
# Config fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def default_config() -> AppConfig:
    return AppConfig(
        auth_burst=BurstConfig(window_seconds=60, distinct_account_threshold=3, max_events_tracked=100),
        auth_chain=ChainConfig(max_chain_length=3, max_graph_nodes=1000),
        privilege_escalation=PrivEscConfig(enabled=True),
    )


@pytest.fixture
def privesc_config() -> PrivEscConfig:
    return PrivEscConfig(enabled=True)


@pytest.fixture
def burst_config() -> BurstConfig:
    return BurstConfig(window_seconds=60, distinct_account_threshold=3, max_events_tracked=100)


@pytest.fixture
def chain_config() -> ChainConfig:
    return ChainConfig(max_chain_length=3, max_graph_nodes=1000)


# ---------------------------------------------------------------------------
# Enrichment fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def vault_cache() -> VaultCache:
    return VaultEnrichment.to_cache(VaultEnrichment().load())


@pytest.fixture
def critical_accounts_cache() -> CriticalAccountsCache:
    return CriticalAccountsEnrichment.to_cache(CriticalAccountsEnrichment().load())


@pytest.fixture
def all_enrichments(vault_cache: VaultCache, critical_accounts_cache: CriticalAccountsCache) -> AllEnrichments:
    return AllEnrichments(vault=vault_cache, critical_accounts=critical_accounts_cache)


@pytest.fixture
def keytab_config() -> KeytabSmugglingConfig:
    return KeytabSmugglingConfig(enabled=True)


# ---------------------------------------------------------------------------
# Model factories
# ---------------------------------------------------------------------------


@pytest.fixture
def make_edge() -> Callable[..., AnyEvent]:
    """Factory: create a SessionEvent with sensible defaults, override via kwargs."""

    def _factory(**kwargs: Any) -> AnyEvent:
        defaults: dict[str, Any] = {
            "src_account_id": "account:alice",
            "src_host_id": "host:web-01",
            "dst_account_id": "account:bob",
            "dst_host_id": "host:web-01",
            "mechanism": "ssh",
            "src_privilege": 0.2,
            "dst_privilege": 0.2,
            "host_id": "host:web-01",
            "raw_source": "unix_auth",
            "timestamp": datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
        }
        defaults.update(kwargs)
        return SessionEvent(**defaults)

    return _factory


@pytest.fixture
def make_account_node() -> Callable[..., AccountNode]:
    def _factory(**kwargs: Any) -> AccountNode:
        defaults: dict[str, Any] = {
            "id": "account:alice",
            "username": "alice",
            "environment": "dev",
            "privilege_tier": 0.2,
            "sensitivity_score": 0.1,
        }
        defaults.update(kwargs)
        return AccountNode(**defaults)

    return _factory


@pytest.fixture
def make_host_node() -> Callable[..., HostNode]:
    def _factory(**kwargs: Any) -> HostNode:
        defaults: dict[str, Any] = {
            "id": "host:web-01",
            "hostname": "web-01",
            "environment": "prod",
            "privilege_tier": 0.5,
            "sensitivity_score": 0.6,
        }
        defaults.update(kwargs)
        return HostNode(**defaults)

    return _factory


# ---------------------------------------------------------------------------
# Detection state fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def burst_state() -> BurstWindowState:
    return BurstWindowState()


# ---------------------------------------------------------------------------
# Graph fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def linear_graph() -> nx.DiGraph:
    """A→B→C→D: 3-hop linear path (at threshold for max_chain_length=3)."""
    g: nx.DiGraph = nx.DiGraph()
    edges = [("A", "B"), ("B", "C"), ("C", "D")]
    for i, (src, dst) in enumerate(edges):
        g.add_node(src, privilege_tier=0.3, host_id="host:test")
        g.add_node(dst, privilege_tier=0.3, host_id="host:test")
        g.add_edge(
            src,
            dst,
            event_id=f"event-{i}",
            edge_list=[{"event_id": f"event-{i}", "mechanism": "ssh"}],
            mechanism="ssh",
            event_category="session",
        )
    return g


@pytest.fixture
def long_chain_graph() -> nx.DiGraph:
    """A→B→C→D→E: 4-hop chain (exceeds max_chain_length=3)."""
    g: nx.DiGraph = nx.DiGraph()
    nodes = ["A", "B", "C", "D", "E"]
    for i, (src, dst) in enumerate(zip(nodes, nodes[1:])):
        g.add_node(src, privilege_tier=0.3, host_id="host:test")
        g.add_node(dst, privilege_tier=0.3, host_id="host:test")
        g.add_edge(
            src,
            dst,
            event_id=f"event-{i}",
            edge_list=[{"event_id": f"event-{i}", "mechanism": "ssh"}],
            mechanism="ssh",
            event_category="session",
        )
    return g


@pytest.fixture
def cyclic_graph() -> nx.DiGraph:
    """A→B→C→A: a cycle. DFS must not loop."""
    g: nx.DiGraph = nx.DiGraph()
    edges = [("A", "B"), ("B", "C"), ("C", "A")]
    for i, (src, dst) in enumerate(edges):
        g.add_node(src, privilege_tier=0.3, host_id="host:test")
        g.add_node(dst, privilege_tier=0.3, host_id="host:test")
        g.add_edge(
            src,
            dst,
            event_id=f"event-{i}",
            edge_list=[{"event_id": f"event-{i}", "mechanism": "ssh"}],
            mechanism="ssh",
            event_category="session",
        )
    return g
