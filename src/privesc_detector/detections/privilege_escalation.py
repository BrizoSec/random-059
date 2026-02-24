"""Detection A — Privilege Escalation.

Fires when an auth edge carries a higher destination privilege tier than
its source privilege tier, indicating an account-level escalation event.
"""

from __future__ import annotations

from privesc_detector.config import PrivEscConfig
from privesc_detector.detections.base import DetectionResult
from privesc_detector.models.edge import AuthEdge


def detect(edge: AuthEdge, config: PrivEscConfig) -> DetectionResult | None:
    """Return a DetectionResult if dst_privilege > src_privilege, else None."""
    if not config.enabled:
        return None

    delta = edge.dst_privilege - edge.src_privilege
    if delta <= 0:
        return None

    return DetectionResult(
        detection_type="privilege_escalation",
        severity=_severity(delta),
        edge_ids=[edge.id],
        node_ids=[edge.src_node_id, edge.dst_node_id],
        host_id=edge.host_id,
        description=(
            f"Privilege escalation on {edge.host_id}: "
            f"{edge.src_privilege:.2f} → {edge.dst_privilege:.2f} "
            f"(+{delta:.2f}) via {edge.edge_type}"
        ),
        metadata={
            "delta": round(delta, 4),
            "edge_type": edge.edge_type,
            "src_privilege": edge.src_privilege,
            "dst_privilege": edge.dst_privilege,
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
