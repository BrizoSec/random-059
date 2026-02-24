"""Alert query routes — GET /alerts, GET /alerts/{id}, PATCH /alerts/{id}/acknowledge."""

from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query

from privesc_detector.api.dependencies import get_alert_store
from privesc_detector.models.alert import Alert, DetectionType
from privesc_detector.store.alerts import AlertStore

router = APIRouter()


@router.get("/alerts", response_model=list[Alert])
async def list_alerts(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
    detection_type: DetectionType | None = Query(None),
    since: datetime | None = Query(None),
    alert_store: AlertStore = Depends(get_alert_store),
) -> list[Alert]:
    return await alert_store.list_alerts(
        skip=skip,
        limit=limit,
        detection_type=detection_type,
        since=since,
    )


@router.get("/alerts/{alert_id}", response_model=Alert)
async def get_alert(
    alert_id: str,
    alert_store: AlertStore = Depends(get_alert_store),
) -> Alert:
    alert = await alert_store.get_by_id(alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@router.patch("/alerts/{alert_id}/acknowledge", response_model=dict)
async def acknowledge_alert(
    alert_id: str,
    alert_store: AlertStore = Depends(get_alert_store),
) -> dict:  # type: ignore[type-arg]
    updated = await alert_store.acknowledge(alert_id)
    if not updated:
        raise HTTPException(status_code=404, detail="Alert not found")
    return {"acknowledged": True, "alert_id": alert_id}
