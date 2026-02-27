"""Unit tests for Detection B — Auth Burst."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Callable

import pytest

from privesc_detector.config import BurstConfig
from privesc_detector.detections import auth_burst
from privesc_detector.detections.auth_burst import BurstWindowState
from privesc_detector.model.event import AnyEvent


def _ts(offset_seconds: int = 0) -> datetime:
    return datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc) + timedelta(seconds=offset_seconds)


def test_no_alert_below_threshold(
    make_edge: Callable[..., AnyEvent],
    burst_state: BurstWindowState,
    burst_config: BurstConfig,
) -> None:
    # threshold=3 — fire 2 distinct accounts, expect no alert
    for i in range(2):
        edge = make_edge(src_account_id=f"account:user{i}", timestamp=_ts(i))
        result = auth_burst.detect(edge, burst_state, burst_config)
    assert result is None


def test_alert_at_threshold(
    make_edge: Callable[..., AnyEvent],
    burst_state: BurstWindowState,
    burst_config: BurstConfig,
) -> None:
    # threshold=3 — fire 3 distinct accounts in quick succession
    result = None
    for i in range(3):
        edge = make_edge(src_account_id=f"account:user{i}", timestamp=_ts(i))
        result = auth_burst.detect(edge, burst_state, burst_config)
    assert result is not None
    assert result.detection_type == "auth_burst"
    assert result.metadata["distinct_account_count"] == 3


def test_same_account_repeated_does_not_inflate_count(
    make_edge: Callable[..., AnyEvent],
    burst_state: BurstWindowState,
    burst_config: BurstConfig,
) -> None:
    # Same account repeated — should still count as 1 distinct
    result = None
    for i in range(10):
        edge = make_edge(src_account_id="account:alice", timestamp=_ts(i))
        result = auth_burst.detect(edge, burst_state, burst_config)
    assert result is None  # only 1 distinct account


def test_window_eviction(
    make_edge: Callable[..., AnyEvent],
    burst_state: BurstWindowState,
) -> None:
    config = BurstConfig(window_seconds=30, distinct_account_threshold=3)
    # Add 2 accounts at t=0
    for i in range(2):
        edge = make_edge(src_account_id=f"account:old{i}", timestamp=_ts(0))
        auth_burst.detect(edge, burst_state, config)

    # Advance time by 60s (outside the 30s window) and add 1 new account
    # Only 1 account should be in window — below threshold
    edge = make_edge(src_account_id="account:new0", timestamp=_ts(60))
    result = auth_burst.detect(edge, burst_state, config)
    assert result is None
    # Verify old events were evicted
    distinct = burst_state.get_distinct_accounts_in_window(
        "host:web-01", config.window_seconds, _ts(60)
    )
    assert "account:old0" not in distinct
    assert "account:new0" in distinct


def test_per_host_isolation(
    make_edge: Callable[..., AnyEvent],
    burst_state: BurstWindowState,
    burst_config: BurstConfig,
) -> None:
    # Events on host-A should not affect host-B's window
    for i in range(3):
        edge = make_edge(
            src_account_id=f"account:user{i}",
            host_id="host:host-a",
            timestamp=_ts(i),
        )
        auth_burst.detect(edge, burst_state, burst_config)

    # host-B has no events — should not alert
    edge_b = make_edge(src_account_id="account:user0", host_id="host:host-b", timestamp=_ts(0))
    result = auth_burst.detect(edge_b, burst_state, burst_config)
    assert result is None


def test_alert_includes_host_id(
    make_edge: Callable[..., AnyEvent],
    burst_state: BurstWindowState,
    burst_config: BurstConfig,
) -> None:
    result = None
    for i in range(3):
        edge = make_edge(
            src_account_id=f"account:user{i}",
            host_id="host:target",
            timestamp=_ts(i),
        )
        result = auth_burst.detect(edge, burst_state, burst_config)
    assert result is not None
    assert result.host_id == "host:target"


def test_state_reset_clears_window(
    make_edge: Callable[..., AnyEvent],
    burst_config: BurstConfig,
) -> None:
    state = BurstWindowState()
    for i in range(3):
        edge = make_edge(src_account_id=f"account:user{i}", timestamp=_ts(i))
        auth_burst.detect(edge, state, burst_config)

    state.reset()
    # After reset, the 4th unique account should not trigger
    edge = make_edge(src_account_id="account:user99", timestamp=_ts(100))
    result = auth_burst.detect(edge, state, burst_config)
    assert result is None
