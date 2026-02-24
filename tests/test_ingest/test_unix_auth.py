"""Unit tests for the Unix auth log ingest stub."""

from __future__ import annotations

from privesc_detector.ingest import unix_auth
from privesc_detector.models.edge import AuthEdge


def test_fetch_events_returns_list() -> None:
    events = unix_auth.fetch_events()
    assert isinstance(events, list)
    assert len(events) > 0


def test_all_events_are_auth_edges() -> None:
    for event in unix_auth.fetch_events():
        assert isinstance(event, AuthEdge)


def test_raw_source_is_unix_auth() -> None:
    for event in unix_auth.fetch_events():
        assert event.raw_source == "unix_auth"


def test_privilege_values_in_range() -> None:
    for event in unix_auth.fetch_events():
        assert 0.0 <= event.src_privilege <= 1.0
        assert 0.0 <= event.dst_privilege <= 1.0


def test_events_have_unique_ids() -> None:
    events = unix_auth.fetch_events()
    ids = [e.id for e in events]
    assert len(ids) == len(set(ids))


def test_edge_types_are_valid() -> None:
    valid = {"ssh", "kinit", "su"}
    for event in unix_auth.fetch_events():
        assert event.edge_type in valid
