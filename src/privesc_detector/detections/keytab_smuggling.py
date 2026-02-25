"""Detection D — Keytab Smuggling.

Fires when a confirmed kinit auth success uses a keytab that is not in the
expected location for the host, or not registered in the vault at all.
"""

from __future__ import annotations

from privesc_detector.config import KeytabSmugglingConfig
from privesc_detector.detections.base import DetectionResult
from privesc_detector.enrichment.cache import AllEnrichments
from privesc_detector.models.edge import AuthEdge


def detect(
    edge: AuthEdge,
    enrichments: AllEnrichments,
    config: KeytabSmugglingConfig,
) -> DetectionResult | None:
    """Return a DetectionResult if a keytab smuggling pattern is detected, else None."""
    if not config.enabled:
        return None
    if edge.edge_type != "kinit" or not edge.auth_success:
        return None

    keytab_path: str | None = edge.metadata.get("keytab_path")
    if not keytab_path:
        return None  # no keytab path surfaced — cannot evaluate

    vault = enrichments.vault
    in_vault = vault.is_keytab_in_vault(keytab_path)
    in_expected_location = vault.is_keytab_expected(edge.host_id, keytab_path)

    if in_vault and in_expected_location:
        return None  # legitimate keytab use

    reason = (
        "keytab not registered in vault"
        if not in_vault
        else f"keytab '{keytab_path}' not expected on {edge.host_id}"
    )
    is_critical = enrichments.critical_accounts.is_critical(edge.src_node_id)
    severity = "critical" if is_critical else "high"

    return DetectionResult(
        detection_type="keytab_smuggling",
        severity=severity,
        edge_ids=[edge.id],
        node_ids=[edge.src_node_id, edge.dst_node_id],
        host_id=edge.host_id,
        description=(
            f"Keytab smuggling on {edge.host_id}: {reason} "
            f"(account: {edge.src_node_id})"
        ),
        metadata={
            "keytab_path": keytab_path,
            "in_vault": in_vault,
            "in_expected_location": in_expected_location,
            "account_is_critical": is_critical,
        },
    )
