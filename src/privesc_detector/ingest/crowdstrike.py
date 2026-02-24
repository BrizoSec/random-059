"""CrowdStrike Falcon ingest stub.

Returns a fixed set of mock AuthEdge objects that simulate what the real
Falcon Event Streams / Detections API would produce after normalization.

Replace this module's `fetch_events()` with a real Falcon API client when
credentials are available. The return type contract (list[AuthEdge]) must
be preserved.
"""

from __future__ import annotations

from datetime import datetime, timezone

from privesc_detector.models.edge import AuthEdge


def fetch_events() -> list[AuthEdge]:
    """Return mock CrowdStrike auth events as normalized AuthEdge objects."""
    now = datetime.now(tz=timezone.utc)
    return [
        AuthEdge(
            src_node_id="account:jsmith",
            dst_node_id="account:svc-deploy",
            edge_type="su",
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
        AuthEdge(
            src_node_id="account:svc-deploy",
            dst_node_id="account:root",
            edge_type="su",
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
        AuthEdge(
            src_node_id="host:web-prod-01",
            dst_node_id="host:db-prod-01",
            edge_type="ssh",
            src_privilege=0.5,
            dst_privilege=0.5,
            host_id="host:web-prod-01",
            raw_source="crowdstrike",
            timestamp=now,
            metadata={
                "falcon_event_id": "cs-event-003",
                "remote_host": "db-prod-01",
            },
        ),
    ]
