"""EventDispatcher — bridges the store layer to the detection layer.

Called by the ingest route after a new AuthEdge is persisted. Runs all three
detections and writes any resulting alerts back to MongoDB.

The dispatcher is the only place that combines async (alert store) and sync
(detection functions). Detection functions are pure Python and have no I/O.
"""

from __future__ import annotations

import networkx as nx

from privesc_detector.config import AppConfig
from privesc_detector.detections import auth_burst, auth_chain, privilege_escalation
from privesc_detector.detections import keytab_smuggling
from privesc_detector.detections.auth_burst import BurstWindowState
from privesc_detector.detections.base import DetectionResult
from privesc_detector.enrichment.cache import EnrichmentCacheManager
from privesc_detector.models.alert import Alert
from privesc_detector.models.edge import AuthEdge
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

    async def on_edge_inserted(
        self, edge: AuthEdge, graph: nx.DiGraph
    ) -> list[Alert]:
        """Run all detections against the new edge and persist any alerts.

        Args:
            edge:   The newly inserted AuthEdge.
            graph:  Full auth graph rebuilt from all edges (including this one).

        Returns:
            List of Alert objects that were fired and persisted.
        """
        fired: list[Alert] = []

        # Detection A — per-edge, synchronous
        result_a = privilege_escalation.detect(edge, self._config.privilege_escalation)
        if result_a:
            alert = _to_alert(result_a)
            await self._alert_store.insert(alert)
            fired.append(alert)

        # Detection B — per-edge with in-memory sliding window, synchronous
        result_b = auth_burst.detect(edge, self._burst_state, self._config.auth_burst)
        if result_b:
            alert = _to_alert(result_b)
            await self._alert_store.insert(alert)
            fired.append(alert)

        # Detection C — graph walk from the source node, synchronous
        results_c = auth_chain.detect(graph, self._config.auth_chain, edge.src_node_id)
        for result in results_c:
            alert = _to_alert(result)
            await self._alert_store.insert(alert)
            fired.append(alert)

        # Detection D — keytab smuggling, per-edge, synchronous
        result_d = keytab_smuggling.detect(
            edge, self._enrichment_cache.current, self._config.keytab_smuggling
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
