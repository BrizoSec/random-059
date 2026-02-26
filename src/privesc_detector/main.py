"""FastAPI application factory with lifespan startup/shutdown."""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI

from privesc_detector.api.routes import alerts, enrichment, health, ingest
from privesc_detector.config import load_config
from privesc_detector.detections.auth_burst import BurstWindowState
from privesc_detector.dispatcher import EventDispatcher
from privesc_detector.enrichment.cache import EnrichmentCacheManager
from privesc_detector.store.alerts import AlertStore
from privesc_detector.store.client import get_database, get_motor_client
from privesc_detector.store.edges import EdgeStore
from privesc_detector.store.nodes import NodeStore
from privesc_detector.store.sessions import SessionStore


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Create shared resources on startup; close them on shutdown."""
    config = load_config()

    client = get_motor_client(config.mongo_uri)
    db = get_database(client, config.mongo_db)

    edge_store = EdgeStore(db)
    node_store = NodeStore(db)
    session_store = SessionStore(db)
    alert_store = AlertStore(db)

    # Ensure indexes exist (idempotent)
    await edge_store.ensure_indexes()
    await node_store.ensure_indexes()
    await session_store.ensure_indexes()
    await alert_store.ensure_indexes()

    enrichment_cache = EnrichmentCacheManager(config.enrichment)
    enrichment_cache.load_sync()
    await enrichment_cache.start_refresh_loop()

    burst_state = BurstWindowState()
    dispatcher = EventDispatcher(alert_store, burst_state, enrichment_cache, config)

    # Attach to app.state so dependency providers can access them
    app.state.config = config
    app.state.mongo_client = client
    app.state.edge_store = edge_store
    app.state.node_store = node_store
    app.state.session_store = session_store
    app.state.alert_store = alert_store
    app.state.enrichment_cache = enrichment_cache
    app.state.dispatcher = dispatcher

    yield

    await enrichment_cache.stop()
    client.close()


def create_app() -> FastAPI:
    app = FastAPI(
        title="Privilege Escalation Detector",
        version="0.1.0",
        lifespan=lifespan,
    )
    app.include_router(health.router)
    app.include_router(ingest.router)
    app.include_router(alerts.router)
    app.include_router(enrichment.router)
    return app


app = create_app()
