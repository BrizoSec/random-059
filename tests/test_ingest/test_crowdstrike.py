"""Unit tests for the CrowdStrike ingest stub."""

from __future__ import annotations

from privesc_detector.ingest import crowdstrike
from privesc_detector.models.edge import AuthEdge


def test_fetch_events_returns_list() -> None:
    events = crowdstrike.fetch_events()
    assert isinstance(events, list)
    assert len(events) > 0


def test_all_events_are_auth_edges() -> None:
    for event in crowdstrike.fetch_events():
        assert isinstance(event, AuthEdge)


def test_raw_source_is_crowdstrike() -> None:
    for event in crowdstrike.fetch_events():
        assert event.raw_source == "crowdstrike"


def test_privilege_values_in_range() -> None:
    for event in crowdstrike.fetch_events():
        assert 0.0 <= event.src_privilege <= 1.0
        assert 0.0 <= event.dst_privilege <= 1.0


def test_events_have_unique_ids() -> None:
    events = crowdstrike.fetch_events()
    ids = [e.id for e in events]
    assert len(ids) == len(set(ids))
