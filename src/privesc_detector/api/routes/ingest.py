"""POST /ingest/event — receive a confirmed auth event, run detections."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from privesc_detector.api.dependencies import get_dispatcher, get_edge_store
from privesc_detector.dispatcher import EventDispatcher
from privesc_detector.graph.builder import load_graph
from privesc_detector.model.alert import Alert
from privesc_detector.model.event import AnyEvent
from privesc_detector.store.edges import EdgeStore

router = APIRouter()


class IngestResponse(BaseModel):
    event_id: str
    alerts_fired: list[Alert]


@router.post("/ingest/event", response_model=IngestResponse)
async def ingest_event(
    event: AnyEvent,
    edge_store: EdgeStore = Depends(get_edge_store),
    dispatcher: EventDispatcher = Depends(get_dispatcher),
) -> IngestResponse:
    """Persist an auth event and run all applicable detections."""
    # 1. Persist the event
    await edge_store.insert(event)

    # 2. Rebuild the full graph (all events including the new one)
    all_events = await edge_store.get_all_for_graph()
    graph = load_graph(all_events)

    # 3. Dispatch detections — returns any alerts that fired
    alerts = await dispatcher.on_event_inserted(event, graph)

    return IngestResponse(event_id=event.id, alerts_fired=alerts)
