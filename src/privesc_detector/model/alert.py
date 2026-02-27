"""Alert Pydantic model — persisted to MongoDB when a detection fires."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, Field


def _new_id() -> str:
    return str(uuid.uuid4())


def _utcnow() -> datetime:
    return datetime.now(tz=timezone.utc)


DetectionType = Literal["privilege_escalation", "auth_burst", "auth_chain", "keytab_smuggling"]
Severity = Literal["low", "medium", "high", "critical"]


class Alert(BaseModel):
    """A fired detection alert, written to MongoDB for persistence."""

    id: str = Field(default_factory=_new_id)
    detection_type: DetectionType
    severity: Severity
    triggered_at: datetime = Field(default_factory=_utcnow)
    edge_ids: list[str] = Field(default_factory=list)
    node_ids: list[str] = Field(default_factory=list)
    host_id: str
    description: str
    metadata: dict[str, Any] = Field(default_factory=dict)
    acknowledged: bool = False
