"""Unix auth log ingest stub.

Returns a fixed set of mock auth events that simulate what a real
auth.log / PAM / kinit parser would produce after normalization.
All events are confirmed outcomes — failed attempts are not ingested.

Replace `fetch_events()` with a real file-tail or syslog consumer when
deploying. The return type contract (list[AnyEvent]) must be preserved.
"""

from __future__ import annotations

from datetime import datetime, timezone

from privesc_detector.model.event import AnyEvent, AuthenticationEvent, SessionEvent


def fetch_events() -> list[AnyEvent]:
    """Return mock Unix auth events as normalized event objects."""
    now = datetime.now(tz=timezone.utc)
    return [
        SessionEvent(
            src_account_id="account:alice",
            src_host_id="host:alice-workstation",
            dst_account_id="account:alice",
            dst_host_id="host:app-dev-02",
            mechanism="ssh",
            src_privilege=0.1,
            dst_privilege=0.3,
            host_id="host:app-dev-02",
            raw_source="unix_auth",
            timestamp=now,
            auth_method="publickey",
            metadata={
                "log_line": "sshd[1234]: Accepted publickey for alice from 10.0.0.5",
            },
        ),
        AuthenticationEvent(
            src_account_id="account:alice",
            src_host_id="host:app-dev-02",
            dst_account_id="account:alice-admin",
            dst_host_id="host:app-dev-02",
            mechanism="kinit",
            src_privilege=0.1,
            dst_privilege=0.6,
            host_id="host:app-dev-02",
            raw_source="unix_auth",
            timestamp=now,
            keytab_path="/tmp/smuggled.keytab",
            realm="REALM.CORP",
            principal="alice-admin@REALM.CORP",
            metadata={
                "log_line": "kinit[5678]: TGT obtained for alice-admin@REALM.CORP",
            },
        ),
        SessionEvent(
            src_account_id="account:alice-admin",
            src_host_id="host:app-dev-02",
            dst_account_id="account:alice-admin",
            dst_host_id="host:bastion-01",
            mechanism="ssh",
            src_privilege=0.6,
            dst_privilege=0.8,
            host_id="host:bastion-01",
            raw_source="unix_auth",
            timestamp=now,
            auth_method="gssapi-with-mic",
            metadata={
                "log_line": "sshd[9012]: Accepted gssapi-with-mic for alice-admin",
            },
        ),
    ]
