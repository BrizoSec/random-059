"""AuthEdge Pydantic model representing a single auth event."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, Field, computed_field


def _new_id() -> str:
    return str(uuid.uuid4())


def _utcnow() -> datetime:
    return datetime.now(tz=timezone.utc)


EdgeType = Literal["ssh", "kinit", "su"]
RawSource = Literal["crowdstrike", "unix_auth"]


class AuthEdge(BaseModel):
    """A directed auth event from one identity/host to another."""

    id: str = Field(default_factory=_new_id)
    src_account_id: str  # account initiating the event
    src_host_id: str     # host the initiating account is on
    dst_account_id: str  # account at the destination
    dst_host_id: str     # host at the destination

    @computed_field
    @property
    def src_node_id(self) -> str:
        return f"{self.src_account_id}|{self.src_host_id}"

    @computed_field
    @property
    def dst_node_id(self) -> str:
        return f"{self.dst_account_id}|{self.dst_host_id}"

    edge_type: EdgeType
    src_privilege: float = Field(ge=0.0, le=1.0)
    dst_privilege: float = Field(ge=0.0, le=1.0)
    timestamp: datetime = Field(default_factory=_utcnow)
    session_id: str | None = None
    host_id: str  # host where the auth event was recorded (typically equals dst_host_id)
    raw_source: RawSource
    metadata: dict[str, Any] = Field(default_factory=dict)
    auth_success: bool = False  # True only for confirmed auth.log/PAM success events
