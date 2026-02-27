"""Unit tests for the Unix auth log ingest stub."""

from __future__ import annotations

from privesc_detector.ingest import unix_auth
from privesc_detector.model.event import AuthenticationEvent, BaseEvent, SessionEvent


def test_fetch_events_returns_list() -> None:
    events = unix_auth.fetch_events()
    assert isinstance(events, list)
    assert len(events) > 0


def test_all_events_are_auth_events() -> None:
    for event in unix_auth.fetch_events():
        assert isinstance(event, BaseEvent)


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


def test_mechanisms_are_valid() -> None:
    session_mechanisms = {"ssh", "su", "sudo", "rdp", "winrm"}
    auth_mechanisms = {"kinit", "oidc", "certificate", "fido2"}
    for event in unix_auth.fetch_events():
        if isinstance(event, SessionEvent):
            assert event.mechanism in session_mechanisms
        elif isinstance(event, AuthenticationEvent):
            assert event.mechanism in auth_mechanisms
