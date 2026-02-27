"""Unix auth log ingest stub.

Returns a fixed set of mock AuthEdge objects that simulate what a real
auth.log / PAM / kinit parser would produce after normalization.

Replace `fetch_events()` with a real file-tail or syslog consumer when
deploying. The return type contract (list[AuthEdge]) must be preserved.
"""

from __future__ import annotations

from datetime import datetime, timezone

from privesc_detector.models.edge import AuthEdge


def fetch_events() -> list[AuthEdge]:
    """Return mock Unix auth events as normalized AuthEdge objects."""
    now = datetime.now(tz=timezone.utc)
    return [
        AuthEdge(
            src_account_id="account:alice",
            src_host_id="host:alice-workstation",
            dst_account_id="account:alice",
            dst_host_id="host:app-dev-02",
            edge_type="ssh",
            src_privilege=0.1,
            dst_privilege=0.3,
            host_id="host:app-dev-02",
            raw_source="unix_auth",
            timestamp=now,
            metadata={
                "log_line": "sshd[1234]: Accepted publickey for alice from 10.0.0.5",
                "pam_service": "sshd",
            },
        ),
        AuthEdge(
            src_account_id="account:alice",
            src_host_id="host:app-dev-02",
            dst_account_id="account:alice-admin",
            dst_host_id="host:app-dev-02",
            edge_type="kinit",
            src_privilege=0.1,
            dst_privilege=0.6,
            host_id="host:app-dev-02",
            raw_source="unix_auth",
            timestamp=now,
            auth_success=True,
            metadata={
                "log_line": "kinit[5678]: TGT obtained for alice-admin@REALM.CORP",
                "keytab_path": "/tmp/smuggled.keytab",
                "pam_service": "krb5",
                "realm": "REALM.CORP",
            },
        ),
        AuthEdge(
            src_account_id="account:alice-admin",
            src_host_id="host:app-dev-02",
            dst_account_id="account:alice-admin",
            dst_host_id="host:bastion-01",
            edge_type="ssh",
            src_privilege=0.6,
            dst_privilege=0.8,
            host_id="host:bastion-01",
            raw_source="unix_auth",
            timestamp=now,
            metadata={
                "log_line": "sshd[9012]: Accepted gssapi-with-mic for alice-admin",
                "pam_service": "sshd",
            },
        ),
    ]
