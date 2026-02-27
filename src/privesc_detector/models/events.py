"""Auth event models — confirmed authentication and session events.

Every event in the graph represents a confirmed outcome (successful
authentication or session establishment), never a mere attempt.

Both types share a compound (account, host) node model:
    src_node_id = "{src_account_id}|{src_host_id}"
    dst_node_id = "{dst_account_id}|{dst_host_id}"

Use the AuthEvent union type for code that handles either type.
Use the concrete types (AuthenticationEvent, SessionEvent) for
detection functions that are scoped to one category.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Annotated, Any, Literal, Union

from pydantic import BaseModel, Field, computed_field


def _new_id() -> str:
    return str(uuid.uuid4())


def _utcnow() -> datetime:
    return datetime.now(tz=timezone.utc)


RawSource = Literal["crowdstrike", "unix_auth"]


class BaseAuthEvent(BaseModel):
    """Shared fields for all confirmed auth event types."""

    id: str = Field(default_factory=_new_id)
    src_account_id: str  # account initiating the event
    src_host_id: str     # host the initiating account is on
    dst_account_id: str  # account at the destination
    dst_host_id: str     # host at the destination
    mechanism: str       # narrowed to a Literal by each subclass

    @computed_field
    @property
    def src_node_id(self) -> str:
        return f"{self.src_account_id}|{self.src_host_id}"

    @computed_field
    @property
    def dst_node_id(self) -> str:
        return f"{self.dst_account_id}|{self.dst_host_id}"

    src_privilege: float = Field(ge=0.0, le=1.0)
    dst_privilege: float = Field(ge=0.0, le=1.0)
    timestamp: datetime = Field(default_factory=_utcnow)
    session_id: str | None = None
    host_id: str  # host where the event was recorded (typically equals dst_host_id)
    raw_source: RawSource
    metadata: dict[str, Any] = Field(default_factory=dict)


class AuthenticationEvent(BaseAuthEvent):
    """A confirmed credential acquisition event (kinit, OIDC, certificate, etc.)."""

    event_category: Literal["authentication"] = "authentication"
    mechanism: Literal["kinit", "oidc", "certificate", "fido2"]
    keytab_path: str | None = None  # present when a keytab was used
    realm: str | None = None        # Kerberos realm or identity domain
    principal: str | None = None    # raw asserted identity (e.g. alice@REALM.CORP)


class SessionEvent(BaseAuthEvent):
    """A confirmed session establishment event (SSH, su, sudo, RDP, etc.)."""

    event_category: Literal["session"] = "session"
    mechanism: Literal["ssh", "su", "sudo", "rdp", "winrm"]
    auth_method: str | None = None   # publickey, gssapi, password
    command_line: str | None = None  # populated for sudo


# Discriminated union — use for any code that handles both event types.
AuthEvent = Annotated[
    Union[AuthenticationEvent, SessionEvent],
    Field(discriminator="event_category"),
]
