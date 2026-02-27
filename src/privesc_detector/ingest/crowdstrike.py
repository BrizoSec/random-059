"""CrowdStrike Falcon ingest stub.

Returns a fixed set of mock auth events that simulate what the real
Falcon Event Streams / Detections API would produce after normalization.
CrowdStrike events are confirmed outcomes (session established, su succeeded).

Replace this module's `fetch_events()` with a real Falcon API client when
credentials are available. The return type contract (list[AnyEvent]) must
be preserved.
"""

from __future__ import annotations

from datetime import datetime, timezone

from privesc_detector.model.event import AnyEvent, SessionEvent


def fetch_events() -> list[AnyEvent]:
    """Return mock CrowdStrike auth events as normalized event objects."""
    now = datetime.now(tz=timezone.utc)
    return [
        SessionEvent(
            src_account_id="account:jsmith",
            src_host_id="host:web-prod-01",
            dst_account_id="account:svc-deploy",
            dst_host_id="host:web-prod-01",
            mechanism="su",
            src_privilege=0.2,
            dst_privilege=0.7,
            host_id="host:web-prod-01",
            raw_source="crowdstrike",
            timestamp=now,
            metadata={
                "falcon_event_id": "cs-event-001",
                "process": "sudo",
                "command_line": "sudo -u svc-deploy bash",
            },
        ),
        SessionEvent(
            src_account_id="account:svc-deploy",
            src_host_id="host:web-prod-01",
            dst_account_id="account:root",
            dst_host_id="host:web-prod-01",
            mechanism="su",
            src_privilege=0.7,
            dst_privilege=1.0,
            host_id="host:web-prod-01",
            raw_source="crowdstrike",
            timestamp=now,
            metadata={
                "falcon_event_id": "cs-event-002",
                "process": "su",
                "command_line": "su -",
            },
        ),
        SessionEvent(
            src_account_id="account:jsmith",
            src_host_id="host:web-prod-01",
            dst_account_id="account:jsmith",
            dst_host_id="host:db-prod-01",
            mechanism="ssh",
            src_privilege=0.5,
            dst_privilege=0.5,
            host_id="host:db-prod-01",
            raw_source="crowdstrike",
            timestamp=now,
            metadata={
                "falcon_event_id": "cs-event-003",
                "remote_host": "db-prod-01",
            },
        ),
    ]
