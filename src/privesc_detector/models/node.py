"""AccountNode and HostNode Pydantic models."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, Field


def _utcnow() -> datetime:
    return datetime.now(tz=timezone.utc)


Environment = Literal["prod", "dev", "staging"]


class AccountNode(BaseModel):
    """Represents a user account in the graph."""

    id: str  # e.g. "account:jsmith"
    username: str
    domain: str | None = None
    environment: Environment = "dev"
    linked_resource_ids: list[str] = Field(default_factory=list)
    privilege_tier: float = Field(ge=0.0, le=1.0)
    sensitivity_score: float = Field(ge=0.0, le=1.0)
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)


class HostNode(BaseModel):
    """Represents a machine/host in the graph."""

    id: str  # e.g. "host:web-prod-01"
    hostname: str
    environment: Environment = "dev"
    privilege_tier: float = Field(ge=0.0, le=1.0)
    sensitivity_score: float = Field(ge=0.0, le=1.0)
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)
