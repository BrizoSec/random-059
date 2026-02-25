"""AuthEdge Pydantic model representing a single auth event."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, Field


def _new_id() -> str:
    return str(uuid.uuid4())


def _utcnow() -> datetime:
    return datetime.now(tz=timezone.utc)


EdgeType = Literal["ssh", "kinit", "su"]
RawSource = Literal["crowdstrike", "unix_auth"]


class AuthEdge(BaseModel):
    """A directed auth event from one identity/host to another."""

    id: str = Field(default_factory=_new_id)
    src_node_id: str  # account or host id — the initiating identity
    dst_node_id: str  # account or host id — the target identity
    edge_type: EdgeType
    src_privilege: float = Field(ge=0.0, le=1.0)
    dst_privilege: float = Field(ge=0.0, le=1.0)
    timestamp: datetime = Field(default_factory=_utcnow)
    session_id: str | None = None
    host_id: str  # host where the auth event was recorded
    raw_source: RawSource
    metadata: dict[str, Any] = Field(default_factory=dict)
    auth_success: bool = False  # True only for confirmed auth.log/PAM success events
