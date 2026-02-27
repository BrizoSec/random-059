"""Detection A — Privilege Escalation.

Fires when an auth event carries a higher destination privilege tier than
its source privilege tier, indicating an account-level escalation event.
"""

from __future__ import annotations

from privesc_detector.config import PrivEscConfig
from privesc_detector.detections.base import DetectionResult
from privesc_detector.models.events import AuthEvent


def detect(event: AuthEvent, config: PrivEscConfig) -> DetectionResult | None:
    """Return a DetectionResult if dst_privilege > src_privilege, else None."""
    if not config.enabled:
        return None

    delta = event.dst_privilege - event.src_privilege
    if delta <= 0:
        return None

    return DetectionResult(
        detection_type="privilege_escalation",
        severity=_severity(delta),
        edge_ids=[event.id],
        node_ids=[event.src_node_id, event.dst_node_id],
        host_id=event.host_id,
        description=(
            f"Privilege escalation on {event.host_id}: "
            f"{event.src_privilege:.2f} → {event.dst_privilege:.2f} "
            f"(+{delta:.2f}) via {event.mechanism}"
        ),
        metadata={
            "delta": round(delta, 4),
            "mechanism": event.mechanism,
            "event_category": event.event_category,
            "src_privilege": event.src_privilege,
            "dst_privilege": event.dst_privilege,
        },
    )


def _severity(delta: float) -> str:
    if delta < 0.2:
        return "low"
    if delta < 0.5:
        return "medium"
    if delta < 0.8:
        return "high"
    return "critical"
