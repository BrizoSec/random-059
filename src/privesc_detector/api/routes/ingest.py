"""POST /ingest/event — receive a normalized AuthEdge, run detections."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from privesc_detector.api.dependencies import get_dispatcher, get_edge_store
from privesc_detector.dispatcher import EventDispatcher
from privesc_detector.graph.builder import load_graph
from privesc_detector.models.alert import Alert
from privesc_detector.models.edge import AuthEdge
from privesc_detector.store.edges import EdgeStore

router = APIRouter()


class IngestResponse(BaseModel):
    edge_id: str
    alerts_fired: list[Alert]


@router.post("/ingest/event", response_model=IngestResponse)
async def ingest_event(
    edge: AuthEdge,
    edge_store: EdgeStore = Depends(get_edge_store),
    dispatcher: EventDispatcher = Depends(get_dispatcher),
) -> IngestResponse:
    """Persist an auth edge and run all detections against the updated graph."""
    # 1. Persist the edge
    await edge_store.insert(edge)

    # 2. Rebuild the full graph (all edges including the new one)
    all_edges = await edge_store.get_all_for_graph()
    graph = load_graph(all_edges)

    # 3. Dispatch detections — returns any alerts that fired
    alerts = await dispatcher.on_edge_inserted(edge, graph)

    return IngestResponse(edge_id=edge.id, alerts_fired=alerts)
