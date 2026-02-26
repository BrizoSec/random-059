"""FastAPI dependency providers.

All shared resources (DB, stores, dispatcher, config) are attached to
app.state at startup and retrieved here via Request injection.
"""

from __future__ import annotations

from fastapi import Request

from privesc_detector.config import AppConfig
from privesc_detector.dispatcher import EventDispatcher
from privesc_detector.enrichment.cache import EnrichmentCacheManager
from privesc_detector.store.alerts import AlertStore
from privesc_detector.store.edges import EdgeStore
from privesc_detector.store.nodes import NodeStore


def get_config(request: Request) -> AppConfig:
    return request.app.state.config  # type: ignore[no-any-return]


def get_edge_store(request: Request) -> EdgeStore:
    return request.app.state.edge_store  # type: ignore[no-any-return]


def get_node_store(request: Request) -> NodeStore:
    return request.app.state.node_store  # type: ignore[no-any-return]


def get_alert_store(request: Request) -> AlertStore:
    return request.app.state.alert_store  # type: ignore[no-any-return]


def get_dispatcher(request: Request) -> EventDispatcher:
    return request.app.state.dispatcher  # type: ignore[no-any-return]


def get_enrichment_cache(request: Request) -> EnrichmentCacheManager:
    return request.app.state.enrichment_cache  # type: ignore[no-any-return]
