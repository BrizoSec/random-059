"""EventDispatcher — bridges the store layer to the detection layer.

Called by the ingest route after a new auth event is persisted. Routes to
the appropriate detections by event type and writes any resulting alerts
back to MongoDB.

Detection routing:
    AuthenticationEvent → A (priv esc), B (burst), C (chain), D (keytab — kinit only)
    SessionEvent        → A (priv esc), B (burst), C (chain)

The dispatcher is the only place that combines async (alert store) and sync
(detection functions). Detection functions are pure Python and have no I/O.
"""

from __future__ import annotations

import networkx as nx

from privesc_detector.config import AppConfig
from privesc_detector.detections import auth_burst, auth_chain, keytab_smuggling, privilege_escalation
from privesc_detector.detections.auth_burst import BurstWindowState
from privesc_detector.detections.base import DetectionResult
from privesc_detector.enrichment.cache import EnrichmentCacheManager
from privesc_detector.models.alert import Alert
from privesc_detector.models.events import AuthEvent, AuthenticationEvent
from privesc_detector.store.alerts import AlertStore


class EventDispatcher:
    def __init__(
        self,
        alert_store: AlertStore,
        burst_state: BurstWindowState,
        enrichment_cache: EnrichmentCacheManager,
        config: AppConfig,
    ) -> None:
        self._alert_store = alert_store
        self._burst_state = burst_state
        self._enrichment_cache = enrichment_cache
        self._config = config

    async def on_event_inserted(
        self, event: AuthEvent, graph: nx.DiGraph
    ) -> list[Alert]:
        """Run all applicable detections against the new event and persist any alerts.

        Args:
            event:  The newly inserted auth event.
            graph:  Full auth graph rebuilt from all events (including this one).

        Returns:
            List of Alert objects that were fired and persisted.
        """
        fired: list[Alert] = []

        # Detection A — privilege escalation, all event types
        result_a = privilege_escalation.detect(event, self._config.privilege_escalation)
        if result_a:
            alert = _to_alert(result_a)
            await self._alert_store.insert(alert)
            fired.append(alert)

        # Detection B — auth burst, all event types
        result_b = auth_burst.detect(event, self._burst_state, self._config.auth_burst)
        if result_b:
            alert = _to_alert(result_b)
            await self._alert_store.insert(alert)
            fired.append(alert)

        # Detection C — auth chain, all event types (graph walk from source node)
        for result in auth_chain.detect(graph, self._config.auth_chain, event.src_node_id):
            alert = _to_alert(result)
            await self._alert_store.insert(alert)
            fired.append(alert)

        # Detection D — keytab smuggling, AuthenticationEvent + kinit only
        if isinstance(event, AuthenticationEvent) and event.mechanism == "kinit":
            result_d = keytab_smuggling.detect(
                event, self._enrichment_cache.current, self._config.keytab_smuggling
            )
            if result_d:
                alert = _to_alert(result_d)
                await self._alert_store.insert(alert)
                fired.append(alert)

        return fired


def _to_alert(result: DetectionResult) -> Alert:
    return Alert(
        detection_type=result.detection_type,
        severity=result.severity,
        edge_ids=result.edge_ids,
        node_ids=result.node_ids,
        host_id=result.host_id,
        description=result.description,
        metadata=result.metadata,
    )
