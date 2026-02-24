"""Detection B — Auth Burst.

Tracks per-host auth events in an in-memory sliding window (collections.deque).
Fires when the number of distinct source accounts seen within the window
reaches or exceeds the configured threshold.

BurstWindowState is instantiated once at app startup and injected via the
dispatcher. It survives for the lifetime of the process — no DB persistence.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from privesc_detector.config import BurstConfig
from privesc_detector.detections.base import DetectionResult
from privesc_detector.models.edge import AuthEdge

# (timestamp, account_id) tuples stored per host
_Event = tuple[datetime, str]


@dataclass
class _HostWindow:
    events: deque[_Event] = field(default_factory=deque)


class BurstWindowState:
    """In-memory sliding window state, keyed by host_id."""

    def __init__(self) -> None:
        self._windows: dict[str, _HostWindow] = {}

    def record(
        self,
        host_id: str,
        timestamp: datetime,
        account_id: str,
        max_events: int = 1000,
    ) -> None:
        if host_id not in self._windows:
            self._windows[host_id] = _HostWindow()
        win = self._windows[host_id]
        win.events.append((timestamp, account_id))
        # Trim oldest entries if deque exceeds max length
        while len(win.events) > max_events:
            win.events.popleft()

    def get_distinct_accounts_in_window(
        self,
        host_id: str,
        window_seconds: int,
        as_of: datetime,
    ) -> set[str]:
        """Return the set of distinct account_ids within the sliding window."""
        win = self._windows.get(host_id)
        if win is None:
            return set()
        cutoff = as_of - timedelta(seconds=window_seconds)
        # Evict stale entries from the left
        while win.events and win.events[0][0] < cutoff:
            win.events.popleft()
        return {account_id for _, account_id in win.events}

    def reset(self, host_id: str | None = None) -> None:
        """Clear state — useful in tests."""
        if host_id is None:
            self._windows.clear()
        else:
            self._windows.pop(host_id, None)


def detect(
    edge: AuthEdge,
    state: BurstWindowState,
    config: BurstConfig,
) -> DetectionResult | None:
    """Record the event and return a DetectionResult if burst threshold is met."""
    ts = edge.timestamp
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)

    state.record(
        host_id=edge.host_id,
        timestamp=ts,
        account_id=edge.src_node_id,
        max_events=config.max_events_tracked,
    )

    distinct = state.get_distinct_accounts_in_window(
        host_id=edge.host_id,
        window_seconds=config.window_seconds,
        as_of=ts,
    )

    if len(distinct) < config.distinct_account_threshold:
        return None

    return DetectionResult(
        detection_type="auth_burst",
        severity="high",
        edge_ids=[edge.id],
        node_ids=list(distinct),
        host_id=edge.host_id,
        description=(
            f"Auth burst on {edge.host_id}: {len(distinct)} distinct accounts "
            f"within {config.window_seconds}s window "
            f"(threshold: {config.distinct_account_threshold})"
        ),
        metadata={
            "distinct_account_count": len(distinct),
            "distinct_accounts": sorted(distinct),
            "window_seconds": config.window_seconds,
        },
    )
