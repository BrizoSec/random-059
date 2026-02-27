"""Detection D — Keytab Smuggling.

Fires when a confirmed kinit authentication uses a keytab that is not in
the expected location for the host, or not registered in the vault at all.

Accepts AuthenticationEvent only — the dispatcher routes here after
confirming event_category == "authentication" and mechanism == "kinit".
"""

from __future__ import annotations

from privesc_detector.config import KeytabSmugglingConfig
from privesc_detector.detections.base import DetectionResult
from privesc_detector.enrichment.cache import AllEnrichments
from privesc_detector.models.events import AuthenticationEvent


def detect(
    event: AuthenticationEvent,
    enrichments: AllEnrichments,
    config: KeytabSmugglingConfig,
) -> DetectionResult | None:
    """Return a DetectionResult if a keytab smuggling pattern is detected, else None."""
    if not config.enabled:
        return None
    if event.mechanism != "kinit":
        return None
    if not event.keytab_path:
        return None  # no keytab used — cannot evaluate

    vault = enrichments.vault
    in_vault = vault.is_keytab_in_vault(event.keytab_path)
    in_expected_location = vault.is_keytab_expected(event.host_id, event.keytab_path)

    if in_vault and in_expected_location:
        return None  # legitimate keytab use

    reason = (
        "keytab not registered in vault"
        if not in_vault
        else f"keytab '{event.keytab_path}' not expected on {event.host_id}"
    )
    is_critical = enrichments.critical_accounts.is_critical(event.src_account_id)
    severity = "critical" if is_critical else "high"

    return DetectionResult(
        detection_type="keytab_smuggling",
        severity=severity,
        edge_ids=[event.id],
        node_ids=[event.src_node_id, event.dst_node_id],
        host_id=event.host_id,
        description=(
            f"Keytab smuggling on {event.host_id}: {reason} "
            f"(account: {event.src_account_id})"
        ),
        metadata={
            "keytab_path": event.keytab_path,
            "in_vault": in_vault,
            "in_expected_location": in_expected_location,
            "account_is_critical": is_critical,
        },
    )
